//! DCP 分布式存储引擎
//! 对应白皮书第11章: 内容寻址 + 自动修复

use blake3::Hasher;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 存储块 (1MB固定块)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBlock {
    /// 块哈希 (内容寻址)
    pub hash: [u8; 32],
    /// 块数据 (最大1MB)
    pub data: Vec<u8>,
    /// 存储节点ID列表
    pub stored_by: Vec<[u8; 32]>,
    /// 创建时间
    pub created_at: u64,
    /// 最后访问时间
    pub last_accessed: u64,
    /// 访问次数 (热度)
    pub access_count: u64,
}

impl StorageBlock {
    pub fn new(data: Vec<u8>) -> Self {
        let hash = Self::compute_hash(&data);
        Self {
            hash,
            data,
            stored_by: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_accessed: 0,
            access_count: 0,
        }
    }

    pub fn compute_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(result.as_bytes());
        hash
    }

    /// 检查是否已过期 (冷数据)
    pub fn is_cold(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.last_accessed > 86400 * 7 // 7天未访问
    }

    /// 增加访问计数
    pub fn access(&mut self) {
        self.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.access_count += 1;
    }
}

/// 存储证明 (Proof-of-Storage)
#[derive(Debug, Clone)]
pub struct StorageProof {
    pub block_hash: [u8; 32],
    pub node_id: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// 分布式存储引擎
pub struct StorageEngine {
    /// 本地存储: hash -> Block
    local_storage: Arc<DashMap<[u8; 32], StorageBlock>>,
    /// 存储押金: node_id -> deposit
    deposits: Arc<DashMap<[u8; 32], u64>>,
    /// 最大存储容量 (字节)
    max_storage_bytes: u64,
    /// 当前使用量
    used_bytes: Arc<Mutex<u64>>,
}

impl StorageEngine {
    pub fn new(max_gb: u64) -> Self {
        Self {
            local_storage: Arc::new(DashMap::new()),
            deposits: Arc::new(DashMap::new()),
            max_storage_bytes: max_gb * 1024 * 1024 * 1024,
            used_bytes: Arc::new(Mutex::new(0)),
        }
    }

    /// 存储块 (需要押金)
    pub async fn store_block(&self, block: StorageBlock, deposit: u64) -> Result<(), String> {
        let data_len = block.data.len() as u64;
        let used = *self.used_bytes.lock().await;
        if used + data_len > self.max_storage_bytes {
            return Err("存储空间不足".to_string());
        }

        // 检查押金
        // TODO: 验证押金有效性

        // 存储
        let hash = block.hash;
        self.local_storage.insert(hash, block);
        *self.used_bytes.lock().await += data_len;

        Ok(())
    }

    /// 获取块 (自动增加访问计数)
    pub async fn get_block(&self, hash: &[u8; 32]) -> Option<StorageBlock> {
        if let Some(mut entry) = self.local_storage.get_mut(hash) {
            entry.access();
            return Some(entry.clone());
        }
        None
    }

    /// 删除块 (释放空间)
    pub async fn remove_block(&self, hash: &[u8; 32]) -> bool {
        if let Some((_, block)) = self.local_storage.remove(hash) {
            *self.used_bytes.lock().await -= block.data.len() as u64;
            return true;
        }
        false
    }

    /// 计算某块在节点间的存储证明
    pub fn generate_proof(&self, block_hash: &[u8; 32], node_id: &[u8; 32]) -> Option<StorageProof> {
        if self.local_storage.contains_key(block_hash) {
            Some(StorageProof {
                block_hash: *block_hash,
                node_id: *node_id,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: vec![], // 需要实际签名
            })
        } else {
            None
        }
    }

    /// 自动修复: 检查副本数, 低于阈值则重新复制
    pub async fn auto_repair(&self, min_replicas: usize) -> Vec<[u8; 32]> {
        let mut need_repair = Vec::new();
        for entry in self.local_storage.iter() {
            if entry.stored_by.len() < min_replicas {
                need_repair.push(*entry.key());
            }
        }
        need_repair
    }

    /// 存储统计
    pub async fn stats(&self) -> StorageStats {
        StorageStats {
            total_blocks: self.local_storage.len(),
            used_bytes: *self.used_bytes.lock().await,
            max_bytes: self.max_storage_bytes,
            deposits: self.deposits.len(),
        }
    }
}

/// 存储统计
pub struct StorageStats {
    pub total_blocks: usize,
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub deposits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_block_hash() {
        let data = b"Hello, DCP!".to_vec();
        let block = StorageBlock::new(data.clone());
        let hash2 = StorageBlock::compute_hash(&data);
        assert_eq!(block.hash, hash2);
    }
}