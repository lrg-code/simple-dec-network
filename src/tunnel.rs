//! DCP 隧道管理 (N条主隧道 + N+2条备用)
//! 对应白皮书表5

use crate::crypto::SessionKey;
use crate::window::SlidingWindow;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// 隧道状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Establishing,  // 正在建立
    Established,   // 已建立
    Degraded,      // 降级 (延迟高)
    Failed,        // 故障
    Ready,         // 备用就绪
}

/// 单条隧道
pub struct Tunnel {
    pub id: u32,
    pub state: TunnelState,
    pub path: Vec<SocketAddr>,        // 路径: [入口, 中继, 出口]
    pub session_key: Option<SessionKey>,
    pub window: SlidingWindow,
    pub created_at: Instant,
    pub last_used: Instant,
    pub rtt_ms: u32,
    pub bandwidth_mbps: f32,
    pub is_inbound: bool,             // 入站还是出站
}

impl Tunnel {
    pub fn new(id: u32, path: Vec<SocketAddr>, is_inbound: bool) -> Self {
        Self {
            id,
            state: TunnelState::Establishing,
            path,
            session_key: None,
            window: SlidingWindow::new(256),
            created_at: Instant::now(),
            last_used: Instant::now(),
            rtt_ms: 100,
            bandwidth_mbps: 10.0,
            is_inbound,
        }
    }

    /// 是否健康 (延迟<300ms, 状态非故障)
    pub fn is_healthy(&self) -> bool {
        self.state == TunnelState::Established && self.rtt_ms < 300
    }

    /// 切换状态
    pub fn set_state(&mut self, state: TunnelState) {
        self.state = state;
    }

    /// 更新RTT
    pub fn update_rtt(&mut self, new_rtt: u32) {
        self.rtt_ms = (self.rtt_ms * 3 + new_rtt) / 4; // 滑动平均
        if self.rtt_ms > 500 {
            self.state = TunnelState::Degraded;
        }
    }
}

/// 隧道管理器
pub struct TunnelManager {
    /// 所有隧道: tunnel_id -> Tunnel
    tunnels: DashMap<u32, Arc<Mutex<Tunnel>>>,
    /// 主隧道数量 (N)
    main_count: usize,
    /// 备用隧道数量 (N+2)
    reserve_count: usize,
    /// 当前隧道ID生成器
    next_id: u32,
}

impl TunnelManager {
    pub fn new(main_count: usize) -> Self {
        let reserve_count = main_count + 2;
        Self {
            tunnels: DashMap::new(),
            main_count,
            reserve_count,
            next_id: 0,
        }
    }

    /// 创建主隧道
    pub async fn create_main_tunnel(&mut self, path: Vec<SocketAddr>) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let tunnel = Arc::new(Mutex::new(Tunnel::new(id, path, false)));
        self.tunnels.insert(id, tunnel);
        id
    }

    /// 创建备用隧道 (提前建立)
    pub async fn create_reserve_tunnel(&mut self, path: Vec<SocketAddr>) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let mut tunnel = Tunnel::new(id, path, false);
        tunnel.state = TunnelState::Ready;
        let tunnel = Arc::new(Mutex::new(tunnel));
        self.tunnels.insert(id, tunnel);
        id
    }

    /// 获取主隧道列表 (健康)
    pub async fn get_main_tunnels(&self) -> Vec<u32> {
        let mut result = Vec::new();
        for entry in self.tunnels.iter() {
            let tunnel = entry.value().lock().await;
            if tunnel.state == TunnelState::Established && tunnel.is_healthy() {
                result.push(*entry.key());
            }
        }
        // 只返回前 N 个
        result.truncate(self.main_count);
        result
    }

    /// 获取备用隧道列表 (就绪)
    pub async fn get_reserve_tunnels(&self) -> Vec<u32> {
        let mut result = Vec::new();
        for entry in self.tunnels.iter() {
            let tunnel = entry.value().lock().await;
            if tunnel.state == TunnelState::Ready {
                result.push(*entry.key());
            }
        }
        result.truncate(self.reserve_count);
        result
    }

    /// 切换隧道: 主 -> 备用
    pub async fn failover(&self, failed_id: u32) -> Option<u32> {
        // 标记故障
        if let Some(entry) = self.tunnels.get(&failed_id) {
            let mut tunnel = entry.lock().await;
            tunnel.state = TunnelState::Failed;
        }

        // 找一个备用隧道
        let reserves = self.get_reserve_tunnels().await;
        if let Some(reserve_id) = reserves.first() {
            // 升级为主隧道
            if let Some(entry) = self.tunnels.get(reserve_id) {
                let mut tunnel = entry.lock().await;
                tunnel.state = TunnelState::Established;
                tunnel.last_used = Instant::now();
                return Some(*reserve_id);
            }
        }
        None
    }

    /// 发送数据 (通过指定隧道)
    pub async fn send_data(&self, tunnel_id: u32, data: Vec<u8>) -> Result<u32, String> {
        if let Some(entry) = self.tunnels.get(&tunnel_id) {
            let mut tunnel = entry.lock().await;
            if tunnel.state != TunnelState::Established {
                return Err("隧道未建立".to_string());
            }
            tunnel.last_used = Instant::now();
            let seq = tunnel.window.send(data);
            Ok(seq)
        } else {
            Err("隧道不存在".to_string())
        }
    }

    /// 接收数据 (从指定隧道)
    pub async fn receive_data(&self, tunnel_id: u32, seq: u32, data: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(entry) = self.tunnels.get(&tunnel_id) {
            let mut tunnel = entry.lock().await;
            tunnel.last_used = Instant::now();
            tunnel.window.receive(seq, data)
        } else {
            None
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new(3) // 默认3条主隧道
    }
}