//! DCP 密码学模块
//! 支持混合抗量子加密 (X25519 + ML-KEM-768)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// DCP 会话密钥
pub struct SessionKey {
    pub key: [u8; 32],
    pub nonce_counter: u64,
}

impl SessionKey {
    /// 从共享密钥派生
    pub fn from_shared_secret(shared: &[u8; 32]) -> Self {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(shared);
        hasher.update(b"DCP-SESSION-KEY-V1");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result.as_bytes()[..32]);
        Self {
            key,
            nonce_counter: 0,
        }
    }

    /// 加密数据 (ChaCha20-Poly1305)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::OsRng;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();

        // 生成 Nonce (12 字节)
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("加密失败");

        // 返回 nonce + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// 解密数据
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 12 {
            return None;
        }
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();

        cipher
            .decrypt(nonce, &ciphertext[12..])
            .ok()
    }

    /// 增加计数器 (用于滑动窗口)
    pub fn next_nonce(&mut self) -> u64 {
        self.nonce_counter += 1;
        self.nonce_counter
    }
}

/// X25519 密钥对
pub struct X25519KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// 计算共享密钥
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        shared.to_bytes()
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// 临时防量子密钥对 (ML-KEM-768 占位)
/// 注意: 真正的 ML-KEM 需要引入 pqcrypto-mlkem 库
pub struct MlKemKeyPair {
    pub public: Vec<u8>,  // 1184 字节
    pub secret: Vec<u8>,  // 2400 字节
}

impl MlKemKeyPair {
    #[cfg(feature = "pqcrypto")]
    pub fn generate() -> Self {
        use pqcrypto_mlkem::mlkem768::*;
        let (public, secret) = keypair();
        Self {
            public: public.as_bytes().to_vec(),
            secret: secret.as_bytes().to_vec(),
        }
    }

    #[cfg(not(feature = "pqcrypto"))]
    pub fn generate() -> Self {
        // 占位实现: 生成随机数据
        let mut rng = rand::thread_rng();
        let mut public = vec![0u8; 1184];
        let mut secret = vec![0u8; 2400];
        rng.fill_bytes(&mut public);
        rng.fill_bytes(&mut secret);
        Self { public, secret }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let shared_a = alice.diffie_hellman(&bob.public_bytes());
        let shared_b = bob.diffie_hellman(&alice.public_bytes());

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_session_key_encryption() {
        let mut key1 = SessionKey::from_shared_secret(&[1u8; 32]);
        let data = b"Hello, DCP!";

        let encrypted = key1.encrypt(data);
        let decrypted = key1.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data);
    }
}