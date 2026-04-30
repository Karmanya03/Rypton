/// Rypton Cryptographic Engine
/// XChaCha20-Poly1305 AEAD + Argon2id KDF + HKDF per-file keys + BLAKE3 integrity
use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.salt.len() + self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < SALT_LEN + NONCE_LEN + 16 {
            return Err(anyhow!("Encrypted blob too short"));
        }
        Ok(Self {
            salt: data[..SALT_LEN].to_vec(),
            nonce: data[SALT_LEN..SALT_LEN + NONCE_LEN].to_vec(),
            ciphertext: data[SALT_LEN + NONCE_LEN..].to_vec(),
        })
    }
}

pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<MasterKey> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| anyhow!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; ARGON2_OUTPUT_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2id failed: {}", e))?;
    Ok(MasterKey { key })
}

pub fn derive_file_key(master_key: &MasterKey, salt: &[u8], label: &str) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), &master_key.key);
    let mut file_key = vec![0u8; 32];
    hk.expand(label.as_bytes(), &mut file_key)
        .map_err(|e| anyhow!("HKDF failed: {}", e))?;
    Ok(file_key)
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<EncryptedBlob> {
    let salt = generate_salt();
    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("Cipher init: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encrypt: {}", e))?;
    Ok(EncryptedBlob {
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt(blob: &EncryptedBlob, key: &[u8]) -> Result<Vec<u8>> {
    let nonce = XNonce::from_slice(&blob.nonce);
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("Cipher init: {}", e))?;
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| anyhow!("Decrypt failed (auth tag mismatch): {}", e))
}

#[allow(dead_code)]
pub fn encrypt_with_password(plaintext: &[u8], password: &str) -> Result<EncryptedBlob> {
    let salt = generate_salt();
    let mut master = derive_master_key(password, &salt)?;
    let blob = encrypt(plaintext, &master.key)?;
    master.key.zeroize();
    Ok(EncryptedBlob {
        salt,
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    })
}

#[allow(dead_code)]
pub fn decrypt_with_password(blob: &EncryptedBlob, password: &str) -> Result<Vec<u8>> {
    let mut master = derive_master_key(password, &blob.salt)?;
    let result = decrypt(blob, &master.key);
    master.key.zeroize();
    result
}

pub fn blake3_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn validate_password_strength(password: &str) -> Result<(), Vec<String>> {
    let mut issues = Vec::new();
    if password.len() < 12 {
        issues.push(format!("Need 12+ chars, got {}", password.len()));
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        issues.push("Missing uppercase".into());
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        issues.push("Missing lowercase".into());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        issues.push("Missing digit".into());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        issues.push("Missing symbol".into());
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = vec![0x42u8; 32];
        let pt = b"The cake is a lie, but this encryption is not.";
        let blob = encrypt(pt, &key).unwrap();
        assert_eq!(pt.to_vec(), decrypt(&blob, &key).unwrap());
    }

    #[test]
    fn password_roundtrip() {
        let pw = "Sup3rS3cur3!Pass";
        let pt = b"ssh-ed25519 AAAA... root@kali";
        let blob = encrypt_with_password(pt, pw).unwrap();
        assert_eq!(pt.to_vec(), decrypt_with_password(&blob, pw).unwrap());
    }

    #[test]
    fn wrong_password() {
        let blob = encrypt_with_password(b"secret", "CorrectHorse!123").unwrap();
        assert!(decrypt_with_password(&blob, "WrongHorse!1234").is_err());
    }

    #[test]
    fn unique_file_keys() {
        let master = MasterKey {
            key: vec![0x42u8; 32],
        };
        let salt = generate_salt();
        let k1 = derive_file_key(&master, &salt, "a").unwrap();
        let k2 = derive_file_key(&master, &salt, "b").unwrap();
        assert_ne!(k1, k2);
    }
}
