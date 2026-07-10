//! DCP 应用层服务
//! 对应白皮书表15: dws: / dfs: / cts:

use crate::storage::{StorageBlock, StorageEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 服务类型 (对应表15的数值编码)
#[repr(u8)]
pub enum ServiceType {
    Dws = 0x01,  // 去中心化网页
    Dfs = 0x02,  // 文件传输
    Cts = 0x03,  // 实时通讯
    Reserved = 0xFF,
}

impl From<u8> for ServiceType {
    fn from(v: u8) -> Self {
        match v {
            0x01 => ServiceType::Dws,
            0x02 => ServiceType::Dfs,
            0x03 => ServiceType::Cts,
            _ => ServiceType::Reserved,
        }
    }
}

/// DWS: 去中心化网页
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DwsSite {
    pub site_id: [u8; 32],     // 站点公钥哈希
    pub domain: String,
    pub title: String,
    pub content: String,        // HTML内容
    pub version: u64,          // 递增版本号
    pub signature: Vec<u8>,    // 站点签名
    pub published_at: u64,
}

impl DwsSite {
    pub fn new(domain: &str, title: &str, content: &str) -> Self {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(domain.as_bytes());
        let result = hasher.finalize();
        let mut site_id = [0u8; 32];
        site_id.copy_from_slice(result.as_bytes());

        Self {
            site_id,
            domain: domain.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            version: 1,
            signature: Vec::new(),
            published_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// 验证站点签名
    pub fn verify(&self) -> bool {
        // TODO: 实际实现 Ed25519 验签
        true
    }
}

/// DFS: 文件传输
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfsFile {
    pub file_hash: [u8; 32],
    pub name: String,
    pub size: u64,
    pub chunks: Vec<[u8; 32]>,  // 块哈希列表
    pub mime_type: String,
    pub uploaded_at: u64,
}

impl DfsFile {
    pub fn new(name: &str, data: &[u8], chunk_size: usize) -> Self {
        let mut chunks = Vec::new();
        for chunk in data.chunks(chunk_size) {
            chunks.push(StorageBlock::compute_hash(chunk));
        }

        Self {
            file_hash: StorageBlock::compute_hash(data),
            name: name.to_string(),
            size: data.len() as u64,
            chunks,
            mime_type: "application/octet-stream".to_string(),
            uploaded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// CTS: 实时通讯
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtsMessage {
    pub from: [u8; 32],        // 发送者NodeID
    pub to: [u8; 32],          // 接收者NodeID
    pub content: String,
    pub timestamp: u64,
    pub nonce: u64,
}

impl CtsMessage {
    pub fn new(from: [u8; 32], to: [u8; 32], content: &str) -> Self {
        Self {
            from,
            to,
            content: content.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: rand::random(),
        }
    }
}

/// 应用层管理器
pub struct AppManager {
    /// 站点缓存 (dws:)
    pub sites: Arc<Mutex<HashMap<String, DwsSite>>>,
    /// 文件索引 (dfs:)
    pub files: Arc<Mutex<HashMap<[u8; 32], DfsFile>>>,
    /// 消息历史 (cts:)
    pub messages: Arc<Mutex<Vec<CtsMessage>>>,
    /// 存储引擎
    storage: Arc<StorageEngine>,
}

impl AppManager {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        Self {
            sites: Arc::new(Mutex::new(HashMap::new())),
            files: Arc::new(Mutex::new(HashMap::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            storage,
        }
    }

    /// 发布 DWS 网站
    pub async fn publish_site(&self, site: DwsSite) -> Result<(), String> {
        if !site.verify() {
            return Err("站点签名无效".to_string());
        }

        let mut sites = self.sites.lock().await;
        sites.insert(site.domain.clone(), site.clone());

        // 存储到DHT (通过存储引擎)
        let data = serde_json::to_vec(&site).unwrap();
        let block = StorageBlock::new(data);
        self.storage.store_block(block, 100).await?;

        Ok(())
    }

    /// 获取 DWS 站点
    pub async fn get_site(&self, domain: &str) -> Option<DwsSite> {
        let sites = self.sites.lock().await;
        sites.get(domain).cloned()
    }

    /// 上传 DFS 文件
    pub async fn upload_file(&self, file: DfsFile) -> Result<(), String> {
        let mut files = self.files.lock().await;
        files.insert(file.file_hash, file);
        Ok(())
    }

    /// 获取 DFS 文件
    pub async fn get_file(&self, file_hash: &[u8; 32]) -> Option<DfsFile> {
        let files = self.files.lock().await;
        files.get(file_hash).cloned()
    }

    /// 发送 CTS 消息
    pub async fn send_message(&self, msg: CtsMessage) -> Result<(), String> {
        let mut messages = self.messages.lock().await;
        messages.push(msg);
        Ok(())
    }

    /// 获取最近的 CTS 消息
    pub async fn get_recent_messages(&self, limit: usize) -> Vec<CtsMessage> {
        let messages = self.messages.lock().await;
        let start = if messages.len() > limit {
            messages.len() - limit
        } else {
            0
        };
        messages[start..].to_vec()
    }
}