/// Vault module: manages encrypted storage, index metadata, and vault operations.
use crate::crypto::{self, EncryptedBlob, MasterKey};
use crate::errors::RyptonError;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

/// Type of item stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultItemType {
    #[serde(rename = "ssh")]
    Ssh,
    #[serde(rename = "shadow")]
    Shadow,
    #[serde(rename = "custom")]
    Custom,
    #[serde(rename = "folder")]
    Folder,
    // System-level (kernel-grade) item types
    #[serde(rename = "system-ssh")]
    SystemSsh,
    #[serde(rename = "system-shadow")]
    SystemShadow,
    #[serde(rename = "system-cert")]
    SystemCert,
    #[serde(rename = "system-config")]
    SystemConfig,
}

impl std::fmt::Display for VaultItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultItemType::Ssh => write!(f, "ssh"),
            VaultItemType::Shadow => write!(f, "shadow"),
            VaultItemType::Custom => write!(f, "custom"),
            VaultItemType::Folder => write!(f, "folder"),
            VaultItemType::SystemSsh => write!(f, "sys-ssh"),
            VaultItemType::SystemShadow => write!(f, "sys-shadow"),
            VaultItemType::SystemCert => write!(f, "sys-cert"),
            VaultItemType::SystemConfig => write!(f, "sys-config"),
        }
    }
}

/// Metadata for a single vault item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub original_path: String,
    pub item_type: VaultItemType,
    pub blake3_hash: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// For folders: list of child blob IDs
    #[serde(default)]
    pub children: Vec<String>,
}

/// Vault configuration (stored in vault root)
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub salt: String,            // hex-encoded Argon2 salt
    pub master_key_hash: String, // BLAKE3 hash of encrypted master key blob
}

/// Get the vault root directory (~/.rypton)
pub fn vault_root() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".rypton")
}

/// Ensure all vault directories exist
pub fn ensure_vault_dirs() -> Result<()> {
    let root = vault_root();
    fs::create_dir_all(root.join("vault"))?;
    fs::create_dir_all(root.join("index"))?;
    fs::create_dir_all(root.join("keys"))?;
    Ok(())
}

/// Check if vault is initialized
pub fn is_initialized() -> bool {
    vault_root().join("keys").join("master.key").exists()
        && vault_root().join("config.json").exists()
}

/// Initialize a new vault with a master password
pub fn init_vault(password: &str) -> Result<()> {
    let root = vault_root();
    if is_initialized() {
        return Err(RyptonError::VaultAlreadyExists(root.display().to_string()).into());
    }

    ensure_vault_dirs()?;

    // Generate vault salt
    let salt = crypto::generate_salt();

    // Derive master key
    let master = crypto::derive_master_key(password, &salt)?;

    // Encrypt the master key with itself (for verification on unlock)
    let verification_data = b"RYPTON_VAULT_V1_VERIFICATION";
    let blob = crypto::encrypt(verification_data, &master.key)?;
    let blob_bytes = blob.to_bytes();

    // Save encrypted master key blob
    fs::write(root.join("keys").join("master.key"), &blob_bytes)?;

    // Save vault config
    let config = VaultConfig {
        version: "1.0.0".to_string(),
        created_at: Utc::now(),
        salt: hex::encode(&salt),
        master_key_hash: crypto::blake3_hash(&blob_bytes),
    };
    let config_json = serde_json::to_string_pretty(&config)?;
    fs::write(root.join("config.json"), config_json)?;

    Ok(())
}

/// Unlock the vault and return the master key
pub fn unlock_vault(password: &str) -> Result<MasterKey> {
    if !is_initialized() {
        return Err(RyptonError::VaultNotInitialized.into());
    }

    let root = vault_root();
    let config: VaultConfig = serde_json::from_str(&fs::read_to_string(root.join("config.json"))?)?;

    let salt = hex::decode(&config.salt).map_err(|e| anyhow!("Invalid salt in config: {}", e))?;
    let master = crypto::derive_master_key(password, &salt)?;

    // Verify by decrypting the master key blob
    let blob_bytes = fs::read(root.join("keys").join("master.key"))?;
    let blob = EncryptedBlob::from_bytes(&blob_bytes)?;
    let decrypted =
        crypto::decrypt(&blob, &master.key).map_err(|_| RyptonError::AuthenticationFailed)?;

    if decrypted != b"RYPTON_VAULT_V1_VERIFICATION" {
        return Err(RyptonError::AuthenticationFailed.into());
    }

    Ok(master)
}

/// Add a single file to the vault
pub fn add_file(master: &MasterKey, path: &Path, item_type: VaultItemType) -> Result<VaultItem> {
    if !path.exists() {
        return Err(RyptonError::FileNotFound(path.display().to_string()).into());
    }
    if !path.is_file() {
        return Err(RyptonError::NotAFile(path.display().to_string()).into());
    }

    let root = vault_root();
    let id = Uuid::new_v4().to_string();
    let plaintext = fs::read(path)?;
    let hash = crypto::blake3_hash(&plaintext);

    // Derive per-file key
    let salt = crypto::generate_salt();
    let file_key = crypto::derive_file_key(master, &salt, &id)?;

    // Encrypt
    let blob = crypto::encrypt(&plaintext, &file_key)?;
    let blob_bytes = blob.to_bytes();

    // Write encrypted blob
    fs::write(root.join("vault").join(format!("{}.blob", id)), &blob_bytes)?;

    // Create metadata
    let item = VaultItem {
        id: id.clone(),
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        original_path: path.canonicalize()?.display().to_string(),
        item_type,
        blake3_hash: hash,
        size_bytes: plaintext.len() as u64,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        children: vec![],
    };

    // Write index metadata
    let meta_json = serde_json::to_string_pretty(&item)?;
    let meta_path = root.join("index").join(format!("{}.json", id));
    let blob_path = root.join("vault").join(format!("{}.blob", id));
    let salt_path = root.join("vault").join(format!("{}.salt", id));

    fs::write(&meta_path, meta_json)?;
    
    // Save the per-file salt alongside the blob
    fs::write(&salt_path, &salt)?;

    // Anti-tamper vault self-protection
    if crate::system_guard::is_root() {
        let _ = crate::system_guard::set_immutable(&blob_path);
        let _ = crate::system_guard::set_immutable(&meta_path);
        let _ = crate::system_guard::set_immutable(&salt_path);
    }

    Ok(item)
}

/// Add an entire folder to the vault (recursive)
pub fn add_folder(
    master: &MasterKey,
    path: &Path,
    exclude_patterns: &[String],
) -> Result<VaultItem> {
    if !path.exists() {
        return Err(RyptonError::FileNotFound(path.display().to_string()).into());
    }
    if !path.is_dir() {
        return Err(RyptonError::NotADirectory(path.display().to_string()).into());
    }

    let folder_id = Uuid::new_v4().to_string();
    let mut children = Vec::new();

    // Count files for progress bar
    let file_count: u64 = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64;

    let pb = ProgressBar::new(file_count);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();
        let file_name = file_path.to_string_lossy();

        // Check exclusion patterns
        let excluded = exclude_patterns.iter().any(|pat| {
            glob::Pattern::new(pat)
                .map(|p| p.matches(&file_name))
                .unwrap_or(false)
        });
        if excluded {
            pb.inc(1);
            continue;
        }

        pb.set_message(format!(
            "{}",
            file_path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let item = add_file(master, file_path, VaultItemType::Custom)?;
        children.push(item.id);
        pb.inc(1);
    }

    pb.finish_with_message("done");

    // Create folder metadata
    let folder_item = VaultItem {
        id: folder_id.clone(),
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        original_path: path.canonicalize()?.display().to_string(),
        item_type: VaultItemType::Folder,
        blake3_hash: String::new(),
        size_bytes: 0,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        children,
    };

    let root = vault_root();
    let meta_json = serde_json::to_string_pretty(&folder_item)?;
    fs::write(
        root.join("index").join(format!("{}.json", folder_id)),
        meta_json,
    )?;

    Ok(folder_item)
}

/// List all vault items
pub fn list_items() -> Result<Vec<VaultItem>> {
    let index_dir = vault_root().join("index");
    if !index_dir.exists() {
        return Ok(vec![]);
    }

    let mut items = Vec::new();
    for entry in fs::read_dir(index_dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|e| e == "json") {
            let content = fs::read_to_string(entry.path())?;
            let item: VaultItem = serde_json::from_str(&content)?;
            items.push(item);
        }
    }

    items.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(items)
}

/// Get a vault item by ID
pub fn get_item(id: &str) -> Result<VaultItem> {
    let meta_path = vault_root().join("index").join(format!("{}.json", id));
    if !meta_path.exists() {
        return Err(RyptonError::ItemNotFound(id.to_string()).into());
    }
    let content = fs::read_to_string(meta_path)?;
    Ok(serde_json::from_str(&content)?)
}

/// Decrypt a vault item and return its plaintext
pub fn decrypt_item(master: &MasterKey, id: &str) -> Result<Vec<u8>> {
    let root = vault_root();
    let blob_path = root.join("vault").join(format!("{}.blob", id));
    let salt_path = root.join("vault").join(format!("{}.salt", id));

    if !blob_path.exists() {
        return Err(RyptonError::ItemNotFound(id.to_string()).into());
    }

    let blob_bytes = fs::read(&blob_path)?;
    let blob = EncryptedBlob::from_bytes(&blob_bytes)?;
    let salt = fs::read(&salt_path)?;
    let file_key = crypto::derive_file_key(master, &salt, id)?;

    crypto::decrypt(&blob, &file_key)
}

/// Remove a vault item
pub fn remove_item(id: &str) -> Result<()> {
    let root = vault_root();
    let blob_path = root.join("vault").join(format!("{}.blob", id));
    let salt_path = root.join("vault").join(format!("{}.salt", id));
    let meta_path = root.join("index").join(format!("{}.json", id));

    if crate::system_guard::is_root() {
        let _ = crate::system_guard::clear_immutable(&blob_path);
        let _ = crate::system_guard::clear_immutable(&meta_path);
        let _ = crate::system_guard::clear_immutable(&salt_path);
    }

    if meta_path.exists() {
        fs::remove_file(&meta_path)?;
    }
    if blob_path.exists() {
        fs::remove_file(&blob_path)?;
    }
    if salt_path.exists() {
        fs::remove_file(&salt_path)?;
    }

    Ok(())
}

/// Re-encrypt the entire vault with a new password
pub fn rekey_vault(old_password: &str, new_password: &str) -> Result<u32> {
    let old_master = unlock_vault(old_password)?;
    let items = list_items()?;

    let pb = ProgressBar::new(items.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} re-encrypting...",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    let mut count = 0u32;
    for item in &items {
        if item.item_type == VaultItemType::Folder {
            pb.inc(1);
            continue;
        }

        // Decrypt with old key
        let plaintext = decrypt_item(&old_master, &item.id)?;

        // Generate new per-file key with new master
        let root = vault_root();
        let config: VaultConfig =
            serde_json::from_str(&fs::read_to_string(root.join("config.json"))?)?;
        let new_salt = crypto::generate_salt();
        let vault_salt = hex::decode(&config.salt).map_err(|e| anyhow!(e))?;
        let new_master = crypto::derive_master_key(new_password, &vault_salt)?;
        let file_key = crypto::derive_file_key(&new_master, &new_salt, &item.id)?;

        let blob_path = root.join("vault").join(format!("{}.blob", item.id));
        let salt_path = root.join("vault").join(format!("{}.salt", item.id));

        if crate::system_guard::is_root() {
            let _ = crate::system_guard::clear_immutable(&blob_path);
            let _ = crate::system_guard::clear_immutable(&salt_path);
        }

        // Re-encrypt
        let blob = crypto::encrypt(&plaintext, &file_key)?;
        fs::write(&blob_path, blob.to_bytes())?;
        fs::write(&salt_path, &new_salt)?;

        if crate::system_guard::is_root() {
            let _ = crate::system_guard::set_immutable(&blob_path);
            let _ = crate::system_guard::set_immutable(&salt_path);
        }

        count += 1;
        pb.inc(1);
    }

    // Re-init master key verification
    let root = vault_root();
    let config: VaultConfig = serde_json::from_str(&fs::read_to_string(root.join("config.json"))?)?;
    let vault_salt = hex::decode(&config.salt).map_err(|e| anyhow!(e))?;
    let new_master = crypto::derive_master_key(new_password, &vault_salt)?;
    let verification = b"RYPTON_VAULT_V1_VERIFICATION";
    let blob = crypto::encrypt(verification, &new_master.key)?;
    fs::write(root.join("keys").join("master.key"), blob.to_bytes())?;

    pb.finish_with_message("done");
    Ok(count)
}

/// Decrypt an entire folder and restore files to a target directory
pub fn decrypt_folder(master: &MasterKey, folder_id: &str, output_dir: &Path) -> Result<u32> {
    let folder = get_item(folder_id)?;
    if folder.item_type != VaultItemType::Folder {
        return Err(anyhow!("Item {} is not a folder", folder_id));
    }

    fs::create_dir_all(output_dir)?;

    let pb = ProgressBar::new(folder.children.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} decrypting...",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    let mut count = 0u32;
    for child_id in &folder.children {
        let child = get_item(child_id)?;
        let plaintext = decrypt_item(master, child_id)?;

        // Reconstruct relative path
        let child_path = PathBuf::from(&child.original_path);
        let folder_base = PathBuf::from(&folder.original_path);
        let relative = child_path.strip_prefix(&folder_base).unwrap_or(&child_path);
        let target = output_dir.join(relative);

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, plaintext)?;

        count += 1;
        pb.inc(1);
    }

    pb.finish_with_message("done");
    Ok(count)
}

/// We need the hex crate for salt encoding
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("Odd hex string length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
