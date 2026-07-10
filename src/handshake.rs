//! DCP 0-RTT 握手状态机

use crate::crypto::{SessionKey, X25519KeyPair};
use crate::header::DcpHeader;
use crate::packet::PacketType;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 握手状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    SynSent,
    SynAckSent,
    SynAckReceived,
    Established,
    Failed,
}

/// 会话管理
pub struct Session {
    pub id: u32,
    pub state: HandshakeState,
    pub local_keypair: X25519KeyPair,
    pub peer_public: Option<[u8; 32]>,
    pub session_key: Option<SessionKey>,
    pub sequence: u32,
    pub window: u32,
    pub remote_addr: SocketAddr,
    pub created_at: std::time::Instant,
}

impl Session {
    pub fn new(remote_addr: SocketAddr) -> Self {
        let id: u32 = rand::thread_rng().gen::<u32>();
        Self {
            id,
            state: HandshakeState::Idle,
            local_keypair: X25519KeyPair::generate(),
            peer_public: None,
            session_key: None,
            sequence: 0,
            window: 256,
            remote_addr,
            created_at: std::time::Instant::now(),
        }
    }

    /// 创建 SYN 包 (0-RTT: 携带数据)
    pub fn create_syn_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        self.state = HandshakeState::SynSent;
        let salt: u32 = rand::thread_rng().gen::<u32>();

        let mut header = DcpHeader::new(PacketType::Syn.into(), 1, self.id);
        header.set_magic_xor(salt);
        header.sequence = self.sequence;
        header.window = self.window;
        header.payload_len = 256;

        let mut combined = Vec::with_capacity(4 + 32 + payload.len());
        combined.extend_from_slice(&salt.to_le_bytes());
        combined.extend_from_slice(&self.local_keypair.public_bytes());
        combined.extend_from_slice(payload);

        while combined.len() < 256 {
            combined.push(rand::thread_rng().gen());
        }

        header.compute_checksum(&combined);
        header.to_bytes(&combined)
    }

    /// 处理 SYN 包，生成 SYN-ACK
    pub fn handle_syn(&mut self, header: &DcpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 36 {
            return None;
        }

        let salt = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&payload[4..36]);

        self.peer_public = Some(peer_public);
        self.state = HandshakeState::SynAckSent;

        let shared = self.local_keypair.diffie_hellman(&peer_public);
        let session_key = SessionKey::from_shared_secret(&shared);
        self.session_key = Some(session_key);

        let mut ack_header = DcpHeader::new(PacketType::SynAck.into(), 1, self.id);
        ack_header.set_magic_xor(salt);
        ack_header.sequence = 1;
        ack_header.window = self.window;
        ack_header.payload_len = 256;

        let mut ack_payload = Vec::with_capacity(32 + 8);
        ack_payload.extend_from_slice(&self.local_keypair.public_bytes());
        ack_payload.extend_from_slice(&header.sequence.to_le_bytes());

        while ack_payload.len() < 256 {
            ack_payload.push(rand::thread_rng().gen());
        }

        ack_header.compute_checksum(&ack_payload);
        Some(ack_header.to_bytes(&ack_payload))
    }

    /// 处理 SYN-ACK，完成握手
    pub fn handle_syn_ack(&mut self, header: &DcpHeader, payload: &[u8]) -> bool {
        if payload.len() < 32 {
            return false;
        }

        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&payload[..32]);

        self.peer_public = Some(peer_public);
        let shared = self.local_keypair.diffie_hellman(&peer_public);
        let session_key = SessionKey::from_shared_secret(&shared);
        self.session_key = Some(session_key);
        self.state = HandshakeState::Established;

        true
    }
}

/// 会话管理器 (类似表 5: N+2 隧道池)
pub struct SessionManager {
    pub sessions: Arc<Mutex<HashMap<u32, Arc<Mutex<Session>>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_or_create(&self, addr: SocketAddr) -> Arc<Mutex<Session>> {
        let session = Session::new(addr);
        let id = session.id;
        let session = Arc::new(Mutex::new(session));
        self.sessions.lock().await.insert(id, Arc::clone(&session));
        session
    }

    pub async fn get_session(&self, id: u32) -> Option<Arc<Mutex<Session>>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn store_session(&self, session: Arc<Mutex<Session>>) {
        let id = session.lock().await.id;
        self.sessions.lock().await.insert(id, session);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}