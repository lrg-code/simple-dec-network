//! DCP 数据包类型

/// DCP 包类型常量
#[repr(u8)]
pub enum PacketType {
    Probe = 0,       // 探测
    Syn = 1,         // 握手发起
    SynAck = 2,      // 握手响应
    Ack = 3,         // 确认
    Heartbeat = 4,   // 心跳
    Data = 5,        // 数据
    Update = 6,      // 更新宣告
    Storage = 7,     // 存储请求
    OfflineProbe = 8,// 离线探测
    OfflineAck = 9,  // 离线确认
    PhishingVote = 10,// 钓鱼指控
}

impl From<u8> for PacketType {
    fn from(v: u8) -> Self {
        match v {
            0 => PacketType::Probe,
            1 => PacketType::Syn,
            2 => PacketType::SynAck,
            3 => PacketType::Ack,
            4 => PacketType::Heartbeat,
            5 => PacketType::Data,
            6 => PacketType::Update,
            7 => PacketType::Storage,
            8 => PacketType::OfflineProbe,
            9 => PacketType::OfflineAck,
            10 => PacketType::PhishingVote,
            _ => PacketType::Data, // 默认当作数据包
        }
    }
}

impl From<PacketType> for u8 {
    fn from(v: PacketType) -> Self {
        v as u8
    }
}

/// 伪装模式 (Flags bits 6-7)
#[repr(u8)]
pub enum CamouflageMode {
    QUIC = 0,
    TLS = 1,
    WebRTC = 2,
    Random = 3,
}

/// 加密套件 (Flags bits 4-5)
#[repr(u8)]
pub enum CipherSuite {
    Classic = 0,   // X25519 + Ed25519
    Hybrid = 1,    // X25519 + ML-KEM-768 + ML-DSA-65 (默认)
    Reserved = 2,  // 未来扩展
    PurePostQuantum = 3, // 纯后量子
}