//! DCP CIP 轮换与诱饵系统
//! 对应白皮书表3

use rand::{Rng, RngCore};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// CIP 池
pub struct CIPPool {
    /// IPv4 地址池 (虚拟)
    ipv4_pool: Vec<Ipv4Addr>,
    /// IPv6 地址池 (Conjure影子)
    ipv6_pool: Vec<Ipv6Addr>,
    /// 当前使用索引
    current_index: usize,
    /// 冷却列表: 最近使用的IP (不可立即复用)
    cooldown: VecDeque<IpAddr>,
    /// 冷却时间 (秒)
    cooldown_secs: u64,
}

impl CIPPool {
    pub fn new() -> Self {
        let mut ipv4_pool = Vec::new();
        // 生成 127.0.0.2 ~ 127.0.0.20 (CIP虚拟IP)
        for i in 2..=20 {
            ipv4_pool.push(Ipv4Addr::new(127, 0, 0, i));
        }

        let mut ipv6_pool = Vec::new();
        // 生成 Conjure 影子 IPv6 (2001:db8::/64 段)
        for i in 0..100 {
            let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16);
            ipv6_pool.push(addr);
        }

        Self {
            ipv4_pool,
            ipv6_pool,
            current_index: 0,
            cooldown: VecDeque::new(),
            cooldown_secs: 30,
        }
    }

    /// 获取下一个 CIP (轮换)
    pub fn next_ip(&mut self) -> IpAddr {
        // 随机选择 IPv4 或 IPv6
        let use_ipv6 = rand::thread_rng().gen_bool(0.3);

        let ip = if use_ipv6 {
            let idx = rand::thread_rng().gen_range(0..self.ipv6_pool.len());
            IpAddr::V6(self.ipv6_pool[idx])
        } else {
            self.current_index = (self.current_index + 1) % self.ipv4_pool.len();
            IpAddr::V4(self.ipv4_pool[self.current_index])
        };

        // 加入冷却
        self.cooldown.push_back(ip);
        if self.cooldown.len() > 100 {
            self.cooldown.pop_front();
        }

        ip
    }

    /// 检查IP是否在冷却中
    pub fn is_in_cooldown(&self, ip: &IpAddr) -> bool {
        self.cooldown.contains(ip)
    }

    /// 获取随机 Conjure 影子IP (对抗审查)
    pub fn conjure_shadow_ip(&mut self) -> IpAddr {
        let idx = rand::thread_rng().gen_range(0..self.ipv6_pool.len());
        IpAddr::V6(self.ipv6_pool[idx])
    }

    /// 生成诱饵包 (伪装流量)
    pub fn generate_decoy_packet(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(64..1024);
        let mut packet = vec![0u8; size];
        rng.fill_bytes(&mut packet);
        packet
    }

    /// 获取影子IP列表 (用于Conjure战术)
    pub fn get_shadow_ips(&mut self, count: usize) -> Vec<IpAddr> {
        let mut result = Vec::new();
        for _ in 0..count {
            result.push(self.conjure_shadow_ip());
        }
        result
    }
}

impl Default for CIPPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 诱饵调度器 (配合CIP轮换)
pub struct DecoyScheduler {
    /// 诱饵发送间隔 (ms)
    interval_ms: u64,
    /// 是否启用背景噪音
    background_noise: bool,
    /// 诱饵包大小 (固定1024, 与数据包一致)
    packet_size: usize,
}

impl DecoyScheduler {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            background_noise: true,
            packet_size: 1024,
        }
    }

    /// 生成背景噪音包
    pub fn generate_noise(&self) -> Vec<u8> {
        let mut packet = vec![0u8; self.packet_size];
        rand::thread_rng().fill_bytes(&mut packet);
        packet
    }

    /// 是否应该发送诱饵
    pub fn should_send_decoy(&self) -> bool {
        if !self.background_noise {
            return false;
        }
        // 泊松过程模拟: 随机突发
        rand::thread_rng().gen_bool(0.3)
    }

    /// 设置背景噪音
    pub fn set_background_noise(&mut self, enabled: bool) {
        self.background_noise = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cip_rotation() {
        let mut pool = CIPPool::new();
        let ip1 = pool.next_ip();
        let ip2 = pool.next_ip();
        assert_ne!(ip1, ip2);
    }
}