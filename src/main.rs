//! DCP 节点入口
//! 监听 UDP 端口，处理握手和数据包

mod crypto;
mod handshake;
mod header;
mod packet;

use handshake::{Session, SessionManager};
use header::DcpHeader;
use packet::PacketType;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter("dcp_node=debug")
        .init();

    let bind_addr = "0.0.0.0:9876";
    let socket = UdpSocket::bind(bind_addr).await?;
    info!("🚀 DCP 节点启动，监听 {}", bind_addr);
    info!("📋 协议版本: v3.4 (混合抗量子 + 指纹伪装)");
    info!("👤 作者: 5t0000");

    let session_manager = SessionManager::new();
    let mut buf = [0u8; 1024];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                debug!("收到 {} 字节数据包从 {}", len, addr);

                if len < 24 {
                    warn!("包太小, 忽略");
                    continue;
                }

                // 解析头部
                let header = match DcpHeader::from_bytes(&buf[..24]) {
                    Some(h) => h,
                    None => {
                        warn!("无法解析头部, 忽略");
                        continue;
                    }
                };

                debug!("解析到: {}", header);

                // 校验和验证
                let payload = &buf[24..len];
                if !header.verify_checksum(payload) {
                    warn!("校验和失败! 可能数据被篡改, 忽略此包");
                    continue;
                }

                // 根据包类型分发处理
                match PacketType::from(header.typ) {
                    PacketType::Syn => {
                        info!("处理 SYN 握手从 {}", addr);
                        let session = Arc::new(Mutex::new(Session::new(addr)));
                        {
                            let mut session = session.lock().await;
                            if let Some(response) = session.handle_syn(&header, payload) {
                                socket.send_to(&response, addr).await?;
                                info!("✅ 回复 SYN-ACK 给 {}", addr);
                            }
                        }
                        session_manager.store_session(session).await;
                    }
                    PacketType::SynAck => {
                        info!("处理 SYN-ACK 从 {}", addr);
                        // TODO: 查找对应的会话并完成握手
                    }
                    PacketType::Heartbeat => {
                        debug!("心跳包从 {}", addr);
                        // TODO: 回复心跳 ACK
                    }
                    PacketType::Data => {
                        debug!("数据包从 {} (seq={})", addr, header.sequence);
                        // TODO: 解密并交给应用层
                    }
                    _ => {
                        debug!("未处理包类型: {} 从 {}", header.typ, addr);
                    }
                }
            }
            Err(e) => {
                error!("UDP 接收错误: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.0.1-5t");
    }
}