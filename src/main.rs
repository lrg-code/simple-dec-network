//! DCP 节点 - 完整集成版

mod crypto;
mod handshake;
mod header;
mod packet;
mod window;
mod dht;
mod tunnel;
mod camouflage;
mod storage;
mod app;

use crate::app::{AppManager, CtsMessage, DfsFile, DwsSite, ServiceType};
use crate::camouflage::{CIPPool, DecoyScheduler};
use crate::dht::KademliaTable;
use crate::storage::StorageEngine;
use crate::tunnel::TunnelManager;
use crate::window::SlidingWindow;
use tokio::net::UdpSocket;
use tracing::{info, debug, warn, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("dcp_node=debug")
        .init();

    info!("🚀 DCP v3.4 完整节点启动");
    info!("📋 协议版本: v3.4 (混合抗量子 + 指纹伪装 + 分布式存储)");
    info!("👤 作者: 5t0000");

    // ---- 初始化所有模块 ----
    let bind_addr = "0.0.0.0:9876";
    let socket = UdpSocket::bind(bind_addr).await?;
    info!("📡 监听: {}", bind_addr);

    // DHT 路由表
    let self_id = [0u8; 32]; // TODO: 从密钥生成
    let dht = KademliaTable::new(self_id);

    // 隧道管理器
    let tunnel_mgr = TunnelManager::new(3);

    // CIP 轮换池
    let mut cip_pool = CIPPool::new();

    // 诱饵调度器
    let decoy = DecoyScheduler::new(100);

    // 存储引擎 (最大10GB)
    let storage = std::sync::Arc::new(StorageEngine::new(10));

    // 应用管理器
    let app = AppManager::new(storage.clone());

    // ---- 测试: 发布一个DWS站点 ----
    let site = DwsSite::new("example.dws", "我的第一个DCP站点", "<h1>Hello, DCP!</h1><p>这是去中心化网络!</p>");
    if let Err(e) = app.publish_site(site.clone()).await {
        warn!("发布站点失败: {}", e);
    } else {
        info!("✅ 已发布站点: example.dws");
    }

    // ---- 主循环 ----
    let mut buf = [0u8; 1024];
    info!("⏳ 等待连接...");

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        debug!("收到 {} 字节从 {}", len, addr);
                        
                        if len < 24 {
                            continue;
                        }

                        let header = match header::DcpHeader::from_bytes(&buf[..24]) {
                            Some(h) => h,
                            None => continue,
                        };

                        if !header.verify_checksum(&buf[24..len]) {
                            warn!("校验和失败, 忽略");
                            continue;
                        }

                        // 根据包类型分发
                        let typ = packet::PacketType::from(header.typ);
                        match typ {
                            packet::PacketType::Syn => {
                                info!("SYN握手从 {}", addr);
                                // TODO: 完整握手逻辑
                            }
                            packet::PacketType::Data => {
                                // 解密并交给应用层
                                debug!("数据包从 {} (seq={})", addr, header.sequence);
                            }
                            packet::PacketType::Heartbeat => {
                                debug!("心跳从 {}", addr);
                            }
                            packet::PacketType::Storage => {
                                info!("存储请求从 {}", addr);
                                // TODO: 处理存储请求
                            }
                            _ => {
                                debug!("未处理包类型: {}", header.typ);
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP错误: {}", e);
                    }
                }
            }
            // 定时器: 诱饵发送
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if decoy.should_send_decoy() {
                    let decoy_ip = cip_pool.next_ip();
                    let decoy_data = decoy.generate_noise();
                    // 发送诱饵到随机目标 (隐蔽)
                    // TODO: 实际发送诱饵包
                    debug!("🧨 发送诱饵包 (源IP伪装: {})", decoy_ip);
                }
            }
        }
    }
}