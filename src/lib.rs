//! DCP (Distanced Connect Protocol) 核心库
//! 版本: v3.4
//! 作者: 5t0000

pub mod crypto;
pub mod header;
pub mod packet;
pub mod handshake;

// 重新导出
pub use header::DcpHeader;
pub use packet::PacketType;
pub use handshake::HandshakeState;