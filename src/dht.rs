//! Kademlia DHT 路由表
//! 对应白皮书: 异或距离 + 2/3共识防日蚀

use dashmap::DashMap;
use std::collections::BinaryHeap;
use std::cmp::Ordering;
use std::net::SocketAddr;

/// 节点信息
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: [u8; 32],
    pub addr: SocketAddr,
    pub country: String,
    pub avg_rtt_ms: u32,
    pub reputation: i32,
    pub last_seen: std::time::Instant,
}

/// 异或距离计算
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// 比较两个异或距离 (用于排序)
#[derive(Eq, PartialEq)]
pub struct XorDistance {
    pub node_id: [u8; 32],
    pub distance: [u8; 32],
}

impl Ord for XorDistance {
    fn cmp(&self, other: &Self) -> Ordering {
        // 按距离从小到大排序
        for i in 0..32 {
            if self.distance[i] != other.distance[i] {
                return other.distance[i].cmp(&self.distance[i]);
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for XorDistance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Kademlia 路由表
pub struct KademliaTable {
    /// 本机 NodeID
    self_id: [u8; 32],
    /// 所有已知节点: NodeID -> NodeInfo
    nodes: DashMap<[u8; 32], NodeInfo>,
    /// 最大节点数
    max_nodes: usize,
}

impl KademliaTable {
    pub fn new(self_id: [u8; 32]) -> Self {
        Self {
            self_id,
            nodes: DashMap::new(),
            max_nodes: 1000,
        }
    }

    /// 添加节点
    pub fn add_node(&self, node: NodeInfo) {
        if self.nodes.len() >= self.max_nodes {
            // LRU淘汰: 删除最久未见的
            let mut oldest = None;
            let mut oldest_time = std::time::Instant::now();
            for entry in self.nodes.iter() {
                if entry.last_seen < oldest_time {
                    oldest_time = entry.last_seen;
                    oldest = Some(*entry.key());
                }
            }
            if let Some(key) = oldest {
                self.nodes.remove(&key);
            }
        }
        self.nodes.insert(node.node_id, node);
    }

    /// 查找距离目标ID最近的 K 个节点
    pub fn find_closest(&self, target: &[u8; 32], k: usize) -> Vec<NodeInfo> {
        let mut heap = BinaryHeap::new();
        for entry in self.nodes.iter() {
            let node_id = *entry.key();
            let distance = xor_distance(&node_id, target);
            heap.push(XorDistance { node_id, distance });
            if heap.len() > k {
                heap.pop();
            }
        }

        let mut result = Vec::new();
        for entry in heap {
            if let Some(node) = self.nodes.get(&entry.node_id) {
                result.push(node.clone());
            }
        }
        result
    }

    /// 获取节点信息
    pub fn get_node(&self, node_id: &[u8; 32]) -> Option<NodeInfo> {
        self.nodes.get(node_id).map(|n| n.clone())
    }

    /// 移除节点 (离线/被踢)
    pub fn remove_node(&self, node_id: &[u8; 32]) {
        self.nodes.remove(node_id);
    }

    /// 检查节点是否存活 (2/3共识防日蚀)
    pub fn verify_consensus(&self, views: Vec<Vec<NodeInfo>>) -> Option<Vec<NodeInfo>> {
        // 至少需要 3 个独立视图
        let view_count = views.len();
        if view_count < 3 {
            return None;
        }

        // 计数每个节点出现的次数
        let mut counts = std::collections::HashMap::new();
        for view in views {
            for node in view {
                *counts.entry(node.node_id).or_insert(0) += 1;
            }
        }

        // 找出出现次数 >= 2/3 的节点
        let threshold = view_count * 2 / 3;
        let consensus_nodes: Vec<NodeInfo> = counts
            .into_iter()
            .filter(|(_, count)| *count >= threshold)
            .filter_map(|(node_id, _)| self.get_node(&node_id))
            .collect();

        if consensus_nodes.len() >= 3 {
            Some(consensus_nodes)
        } else {
            None
        }
    }

    /// 节点数量
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        let dist = xor_distance(&a, &b);
        assert_eq!(dist[0], 1);
    }
}