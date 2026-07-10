//! DCP 滑动窗口与重传机制
//! 对应白皮书表1: Sequence + Window + Checksum

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;

/// 滑动窗口条目
#[derive(Debug, Clone)]
pub struct WindowEntry {
    pub sequence: u32,
    pub data: Vec<u8>,
    pub sent_at: Instant,
    pub retries: u8,
}

/// 滑动窗口 (每个会话独立)
pub struct SlidingWindow {
    /// 当前发送序列号
    send_seq: u32,
    /// 当前接收序列号 (期望的下一个)
    recv_seq: u32,
    /// 窗口大小 (默认256)
    window_size: u32,
    /// 发送缓冲区: 序列号 -> 数据
    send_buffer: VecDeque<WindowEntry>,
    /// 接收缓冲区: 序列号 -> 数据 (乱序缓存)
    recv_buffer: DashMap<u32, Vec<u8>>,
    /// 最大重传次数
    max_retries: u8,
    /// 超时时间
    timeout_ms: u64,
}

impl SlidingWindow {
    pub fn new(window_size: u32) -> Self {
        Self {
            send_seq: 0,
            recv_seq: 0,
            window_size,
            send_buffer: VecDeque::with_capacity(window_size as usize),
            recv_buffer: DashMap::new(),
            max_retries: 3,
            timeout_ms: 1000,
        }
    }

    /// 发送数据 (添加到发送缓冲区)
    pub fn send(&mut self, data: Vec<u8>) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.send_buffer.push_back(WindowEntry {
            sequence: seq,
            data,
            sent_at: Instant::now(),
            retries: 0,
        });
        seq
    }

    /// 接收数据 (检查序列号)
    pub fn receive(&mut self, seq: u32, data: Vec<u8>) -> Option<Vec<u8>> {
        // 如果序列号小于期望的, 已经处理过 -> 丢弃
        if seq < self.recv_seq {
            return None;
        }

        // 如果序列号正好是期望的
        if seq == self.recv_seq {
            self.recv_seq = self.recv_seq.wrapping_add(1);
            let mut result = vec![data];

            // 检查缓冲区是否有下一个连续的包
            while let Some((_, buffered)) = self.recv_buffer.remove(&self.recv_seq) {
                result.push(buffered);
                self.recv_seq = self.recv_seq.wrapping_add(1);
            }

            return Some(result.concat());
        }

        // 序列号在窗口内但乱序 -> 缓存
        if seq < self.recv_seq.wrapping_add(self.window_size) {
            self.recv_buffer.insert(seq, data);
            return None;
        }

        // 序列号超出窗口 -> 丢弃 (防重放)
        None
    }

    /// 检查超时并重传 (定时器调用)
    pub fn tick(&mut self) -> Vec<(u32, Vec<u8>)> {
        let now = Instant::now();
        let mut retransmit = Vec::new();

        while let Some(entry) = self.send_buffer.front_mut() {
            if now.duration_since(entry.sent_at) < Duration::from_millis(self.timeout_ms) {
                break;
            }

            if entry.retries >= self.max_retries {
                // 超过最大重传次数, 丢弃
                self.send_buffer.pop_front();
                continue;
            }

            // 重传
            entry.retries += 1;
            entry.sent_at = now;
            retransmit.push((entry.sequence, entry.data.clone()));
            self.send_buffer.pop_front();
        }

        retransmit
    }

    /// 确认收到
    pub fn ack(&mut self, seq: u32) {
        self.send_buffer.retain(|e| e.sequence != seq);
    }

    /// 获取待确认的序列号列表
    pub fn pending_seqs(&self) -> Vec<u32> {
        self.send_buffer.iter().map(|e| e.sequence).collect()
    }

    /// 重置窗口 (新隧道)
    pub fn reset(&mut self) {
        self.send_seq = 0;
        self.recv_seq = 0;
        self.send_buffer.clear();
        self.recv_buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(256);

        let seq1 = window.send(b"Hello".to_vec());
        let seq2 = window.send(b"World".to_vec());

        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);

        // 乱序接收: 先收到 seq1, 再收到 seq0
        let result1 = window.receive(1, b"World".to_vec());
        assert!(result1.is_none()); // 缓存

        let result2 = window.receive(0, b"Hello".to_vec());
        assert_eq!(result2, Some(b"HelloWorld".to_vec()));
    }
}