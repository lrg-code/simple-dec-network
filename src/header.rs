//! DCP 协议头部 —— 严格对应白皮书表 1
//! 总大小: 24 字节

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt;

/// DCP 头部结构
/// 内存布局: 24 字节，严格对齐
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcpHeader {
    /// Magic 魔数: 启动时用 Salt 异或混淆 (0xDC012026)
    pub magic: u32,
    /// 会话 ID: 发起方随机生成
    pub session_id: u32,
    /// 序列号: 从 0 递增，用于滑动窗口
    pub sequence: u32,
    /// 窗口大小: 默认 256
    pub window: u32,
    /// 负载长度: 固定 1024 (数据包) 或 256 (控制包)
    pub payload_len: u16,
    /// 包类型: 0探测 / 1SYN / 2SYN-ACK / 3ACK / 4心跳 / 5数据 / 6更新宣告 / 7存储请求 / 8离线探测 / 9离线确认 / 10钓鱼指控
    pub typ: u8,
    /// 标志位:
    /// bit 0: PoW
    /// bit 1: ACK
    /// bit 2: 沙盒标志
    /// bit 3: 离线清扫
    /// bits 4-5: Cipher_Suite (00经典 / 01混合 / 10预留 / 11纯后量子)
    /// bits 6-7: 伪装模式 (00 QUIC / 01 TLS / 10 WebRTC / 11 随机)
    pub flags: u8,
    /// BLAKE3-512 校验和 (取前 4 字节)
    pub checksum: [u8; 4],
}

impl DcpHeader {
    /// 创建一个新头部 (校验和后续计算)
    pub fn new(typ: u8, flags: u8, session_id: u32) -> Self {
        Self {
            magic: 0xDC012026,
            typ,
            flags,
            session_id,
            sequence: 0,
            window: 256,
            payload_len: 1024,
            checksum: [0; 4],
        }
    }

    /// 设置魔术 (用 Salt 异或混淆)
    pub fn set_magic_xor(&mut self, salt: u32) {
        self.magic = 0xDC012026 ^ salt;
    }

    /// 获取原始 Magic (恢复)
    pub fn original_magic(&self, salt: u32) -> u32 {
        self.magic ^ salt
    }

    /// 计算校验和 (BLAKE3-512)
    pub fn compute_checksum(&mut self, payload: &[u8]) {
        // 先序列化头部 (不含 checksum 本身)
        let mut header_bytes = self.to_bytes_without_checksum();
        // 将 checksum 位置置 0
        let checksum_pos = 20; // magic(4)+typ(1)+flags(1)+session_id(4)+sequence(4)+window(4)+payload_len(2) = 20
        header_bytes[checksum_pos..checksum_pos + 4].copy_from_slice(&[0; 4]);

        let mut hasher = Hasher::new();
        hasher.update(&header_bytes);
        hasher.update(payload);
        let result = hasher.finalize();
        self.checksum.copy_from_slice(&result.as_bytes()[..4]);
    }

    /// 验证校验和
    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        let mut header_bytes = self.to_bytes_without_checksum();
        let checksum_pos = 20;
        header_bytes[checksum_pos..checksum_pos + 4].copy_from_slice(&[0; 4]);

        let mut hasher = Hasher::new();
        hasher.update(&header_bytes);
        hasher.update(payload);
        let result = hasher.finalize();
        &result.as_bytes()[..4] == &self.checksum[..]
    }

    /// 序列化为字节数组 (不含 checksum, 用于计算校验和)
    fn to_bytes_without_checksum(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.session_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.sequence.to_le_bytes());
        buf[12..16].copy_from_slice(&self.window.to_le_bytes());
        buf[16..18].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[18] = self.typ;
        buf[19] = self.flags;
        // checksum 位置 (20-23) 留空
        buf
    }

    /// 完整的序列化 (头部 + 负载)
    pub fn to_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut header_bytes = self.to_bytes_without_checksum();
        header_bytes[20..24].copy_from_slice(&self.checksum);
        let mut result = Vec::with_capacity(24 + payload.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(payload);
        result
    }

    /// 从字节流反序列化
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        Some(Self {
            magic: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            session_id: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            sequence: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            window: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            payload_len: u16::from_le_bytes([data[16], data[17]]),
            typ: data[18],
            flags: data[19],
            checksum: [data[20], data[21], data[22], data[23]],
        })
    }
}

impl fmt::Display for DcpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DCP[type={}, flags={:#04x}, session={}, seq={}, window={}, len={}, magic={:#010x}]",
            self.typ,
            self.flags,
            self.session_id,
            self.sequence,
            self.window,
            self.payload_len,
            self.magic
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(std::mem::size_of::<DcpHeader>(), 24);
    }

    #[test]
    fn test_checksum() {
        let mut header = DcpHeader::new(1, 0, 12345);
        header.payload_len = 0;
        header.compute_checksum(&[]);
        assert!(header.verify_checksum(&[]));
    }

    #[test]
    fn test_serialization() {
        let mut header = DcpHeader::new(5, 0, 999);
        header.sequence = 42;
        header.payload_len = 1024;
        header.compute_checksum(&[1, 2, 3, 4]);

        let bytes = header.to_bytes(&[1, 2, 3, 4]);
        let parsed = DcpHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.magic, parsed.magic);
        assert_eq!(header.typ, parsed.typ);
        assert_eq!(header.session_id, parsed.session_id);
        assert_eq!(header.sequence, parsed.sequence);
    }
}