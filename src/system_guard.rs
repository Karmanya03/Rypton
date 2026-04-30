/// System Guard module: kernel-level tamper-proof protection for system credentials.
///
/// Uses Linux kernel features:
///   - chattr +i (immutable flag via FS_IOC_SETFLAGS ioctl)
///   - BLAKE3 integrity baselines for tamper detection
///   - File permission and ownership auditing
///   - Real-time polling-based filesystem monitor
///
/// Protected credential classes:
///   - /etc/shadow, /etc/passwd, /etc/gshadow, /etc/group
///   - /etc/ssh/ssh_host_* (SSH host keys)
///   - /etc/ssh/sshd_config
///   - /etc/sudoers, /etc/sudoers.d/*
///   - /etc/ssl/private/* (TLS private keys)
///   - /etc/pam.d/* (PAM authentication configs)
///   - User SSH keys: ~/.ssh/*
use crate::crypto;
use crate::vault::{self, VaultItemType};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// System credential registry
// ---------------------------------------------------------------------------

/// A system credential file descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCredential {
    pub path: String,
    pub category: String,
    pub description: String,
    pub expected_perms: u32, // octal, e.g. 0o640
    pub critical: bool,      // true = CRIT severity on tamper
}

/// All known system credential paths to monitor
pub fn system_credential_registry() -> Vec<SystemCredential> {
    vec![
        // Authentication databases
        sc(
            "/etc/shadow",
            "auth",
            "System password hashes (shadow database)",
            0o640,
            true,
        ),
        sc("/etc/passwd", "auth", "User account database", 0o644, true),
        sc("/etc/gshadow", "auth", "Group password hashes", 0o640, true),
        sc(
            "/etc/group",
            "auth",
            "Group membership database",
            0o644,
            true,
        ),
        // SSH host keys
        sc(
            "/etc/ssh/ssh_host_rsa_key",
            "ssh",
            "SSH host RSA private key",
            0o600,
            true,
        ),
        sc(
            "/etc/ssh/ssh_host_ed25519_key",
            "ssh",
            "SSH host Ed25519 private key",
            0o600,
            true,
        ),
        sc(
            "/etc/ssh/ssh_host_ecdsa_key",
            "ssh",
            "SSH host ECDSA private key",
            0o600,
            true,
        ),
        sc(
            "/etc/ssh/ssh_host_dsa_key",
            "ssh",
            "SSH host DSA private key",
            0o600,
            true,
        ),
        sc(
            "/etc/ssh/sshd_config",
            "ssh",
            "SSH daemon configuration",
            0o644,
            false,
        ),
        sc(
            "/etc/ssh/ssh_config",
            "ssh",
            "SSH client system-wide config",
            0o644,
            false,
        ),
        // Privilege escalation
        sc(
            "/etc/sudoers",
            "privesc",
            "Sudoers policy file",
            0o440,
            true,
        ),
        // TLS / Certificates
        sc(
            "/etc/ssl/private",
            "tls",
            "TLS/SSL private keys directory",
            0o700,
            true,
        ),
        // PAM
        sc(
            "/etc/pam.d/common-auth",
            "pam",
            "PAM common authentication rules",
            0o644,
            false,
        ),
        sc(
            "/etc/pam.d/common-password",
            "pam",
            "PAM common password rules (Debian/Ubuntu)",
            0o644,
            false,
        ),
        sc(
            "/etc/pam.d/system-auth",
            "pam",
            "PAM system auth rules (RHEL/CentOS/Arch)",
            0o644,
            false,
        ),
        sc(
            "/etc/pam.d/password-auth",
            "pam",
            "PAM password auth rules (RHEL/CentOS)",
            0o644,
            false,
        ),
        sc(
            "/etc/pam.d/sshd",
            "pam",
            "PAM SSH daemon rules",
            0o644,
            false,
        ),
        sc("/etc/pam.d/sudo", "pam", "PAM sudo rules", 0o644, false),
        sc("/etc/pam.d/login", "pam", "PAM login rules", 0o644, false),
        // Login config
        sc(
            "/etc/login.defs",
            "auth",
            "Login policy definitions",
            0o644,
            false,
        ),
        sc(
            "/etc/securetty",
            "auth",
            "Secure TTY list for root login",
            0o600,
            false,
        ),
        // Cron
        sc("/etc/crontab", "cron", "System crontab", 0o644, false),
        // Network
        sc(
            "/etc/hosts",
            "network",
            "Static hostname resolution",
            0o644,
            false,
        ),
        sc(
            "/etc/resolv.conf",
            "network",
            "DNS resolver configuration",
            0o644,
            false,
        ),
    ]
}

fn sc(path: &str, cat: &str, desc: &str, perms: u32, critical: bool) -> SystemCredential {
    SystemCredential {
        path: path.to_string(),
        category: cat.to_string(),
        description: desc.to_string(),
        expected_perms: perms,
        critical,
    }
}

/// Also discover user-level SSH keys dynamically
pub fn discover_user_ssh_keys() -> Vec<SystemCredential> {
    let mut keys = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let ssh_dir = home.join(".ssh");
        if ssh_dir.exists()
            && let Ok(entries) = fs::read_dir(&ssh_dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if path.is_file()
                    && !name.ends_with(".pub")
                    && name != "known_hosts"
                    && name != "authorized_keys"
                    && name != "config"
                {
                    keys.push(SystemCredential {
                        path: path.display().to_string(),
                        category: "user-ssh".to_string(),
                        description: format!("User SSH key: {}", name),
                        expected_perms: 0o600,
                        critical: true,
                    });
                }
            }
        }
    }
    keys
}

// ---------------------------------------------------------------------------
// Integrity baseline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub path: String,
    pub blake3_hash: String,
    pub size_bytes: u64,
    pub permissions: String, // octal string like "0644"
    pub owner: String,       // "uid:gid"
    pub modified: DateTime<Utc>,
    pub immutable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemBaseline {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub hostname: String,
    pub entries: Vec<BaselineEntry>,
}

fn baselines_dir() -> PathBuf {
    vault::vault_root().join("baselines")
}

fn baseline_path() -> PathBuf {
    baselines_dir().join("system_baseline.json")
}

/// Create a BLAKE3 integrity baseline of all system credential files
pub fn create_baseline() -> Result<SystemBaseline> {
    fs::create_dir_all(baselines_dir())?;

    let mut all_creds = system_credential_registry();
    all_creds.extend(discover_user_ssh_keys());

    let mut entries = Vec::new();

    for cred in &all_creds {
        let path = Path::new(&cred.path);
        if !path.exists() {
            continue;
        }

        // For directories, skip individual hashing
        if path.is_dir() {
            continue;
        }

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => continue, // permission denied is expected for some files
        };

        let hash = crypto::blake3_hash(&data);
        let meta = fs::metadata(path)?;
        let perms = format_permissions(&meta);
        let owner = get_owner_string(path);
        let immutable = check_immutable(path);

        entries.push(BaselineEntry {
            path: cred.path.clone(),
            blake3_hash: hash,
            size_bytes: meta.len(),
            permissions: perms,
            owner,
            modified: Utc::now(), // use current as approximation
            immutable,
        });
    }

    let baseline = SystemBaseline {
        version: "1.0.0".to_string(),
        created_at: Utc::now(),
        hostname: get_hostname(),
        entries,
    };

    let json = serde_json::to_string_pretty(&baseline)?;
    fs::write(baseline_path(), &json)?;

    Ok(baseline)
}

/// Verify current system state against stored baseline
pub fn verify_baseline() -> Result<Vec<IntegrityViolation>> {
    let bp = baseline_path();
    if !bp.exists() {
        return Err(anyhow!(
            "No baseline found. Run 'rypton system baseline' first."
        ));
    }

    let baseline: SystemBaseline = serde_json::from_str(&fs::read_to_string(&bp)?)?;
    let mut violations = Vec::new();

    for entry in &baseline.entries {
        let path = Path::new(&entry.path);

        if !path.exists() {
            violations.push(IntegrityViolation {
                path: entry.path.clone(),
                violation_type: ViolationType::Deleted,
                detail: "File has been deleted since baseline was created".to_string(),
            });
            continue;
        }

        // Hash check
        if let Ok(data) = fs::read(path) {
            let current_hash = crypto::blake3_hash(&data);
            if current_hash != entry.blake3_hash {
                violations.push(IntegrityViolation {
                    path: entry.path.clone(),
                    violation_type: ViolationType::ContentModified,
                    detail: format!(
                        "BLAKE3 mismatch: expected {}..., got {}...",
                        &entry.blake3_hash[..16],
                        &current_hash[..std::cmp::min(16, current_hash.len())]
                    ),
                });
            }

            // Size check
            let meta = fs::metadata(path)?;
            if meta.len() != entry.size_bytes {
                violations.push(IntegrityViolation {
                    path: entry.path.clone(),
                    violation_type: ViolationType::SizeChanged,
                    detail: format!("Size changed: {} -> {} bytes", entry.size_bytes, meta.len()),
                });
            }

            // Permission check
            let current_perms = format_permissions(&meta);
            if current_perms != entry.permissions {
                violations.push(IntegrityViolation {
                    path: entry.path.clone(),
                    violation_type: ViolationType::PermissionChanged,
                    detail: format!(
                        "Permissions changed: {} -> {}",
                        entry.permissions, current_perms
                    ),
                });
            }
        }

        // Immutable flag check
        let current_immutable = check_immutable(path);
        if entry.immutable && !current_immutable {
            violations.push(IntegrityViolation {
                path: entry.path.clone(),
                violation_type: ViolationType::ImmutableCleared,
                detail: "Immutable flag was removed (potential tampering)".to_string(),
            });
        }
    }

    Ok(violations)
}

#[derive(Debug)]
pub struct IntegrityViolation {
    pub path: String,
    pub violation_type: ViolationType,
    pub detail: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ViolationType {
    ContentModified,
    Deleted,
    SizeChanged,
    PermissionChanged,
    ImmutableCleared,
    OwnerChanged,
    NewFileDetected,
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationType::ContentModified => write!(f, "MODIFIED"),
            ViolationType::Deleted => write!(f, "DELETED"),
            ViolationType::SizeChanged => write!(f, "SIZE_CHG"),
            ViolationType::PermissionChanged => write!(f, "PERM_CHG"),
            ViolationType::ImmutableCleared => write!(f, "IMMUT_CLR"),
            ViolationType::OwnerChanged => write!(f, "OWNER_CHG"),
            ViolationType::NewFileDetected => write!(f, "NEW_FILE"),
        }
    }
}

// ---------------------------------------------------------------------------
// Immutable flag management (Linux chattr +i / -i)
// ---------------------------------------------------------------------------

/// Set the immutable flag on a file (requires root)
/// Uses chattr on Linux, no-op on other platforms
pub fn set_immutable(path: &Path) -> Result<()> {
    if !is_root() {
        return Err(anyhow!(
            "Setting immutable flag requires root. Run with sudo."
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("chattr")
            .arg("+i")
            .arg(path.to_string_lossy().as_ref())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("chattr +i failed: {}", stderr.trim()));
        }
        return Ok(());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(anyhow!(
            "Immutable flags are only supported on Linux (ext4/btrfs/xfs)."
        ))
    }
}

/// Clear the immutable flag on a file (requires root)
pub fn clear_immutable(path: &Path) -> Result<()> {
    if !is_root() {
        return Err(anyhow!(
            "Clearing immutable flag requires root. Run with sudo."
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("chattr")
            .arg("-i")
            .arg(path.to_string_lossy().as_ref())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("chattr -i failed: {}", stderr.trim()));
        }
        return Ok(());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(anyhow!("Immutable flags are only supported on Linux."))
    }
}

/// Check if a file has the immutable flag set
pub fn check_immutable(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("lsattr")
            .arg("-d")
            .arg(path.to_string_lossy().as_ref())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains('i') && output.status.success();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
    }
    false
}

// ---------------------------------------------------------------------------
// System file protection (backup + encrypt + lock)
// ---------------------------------------------------------------------------

/// Protect a system credential file:
///   1. Read the file
///   2. Encrypt and store in vault
///   3. Optionally set immutable flag
pub fn protect_file(
    master: &crypto::MasterKey,
    path: &Path,
    set_immut: bool,
) -> Result<vault::VaultItem> {
    if !path.exists() {
        return Err(anyhow!("File not found: {}", path.display()));
    }

    // Determine item type from path
    let item_type = classify_system_path(path);

    // Add to vault
    let item = vault::add_file(master, path, item_type)?;

    // Set immutable flag if requested
    if set_immut {
        if is_root() {
            set_immutable(path)?;
        } else {
            eprintln!(
                "  {} Cannot set immutable flag without root. Run with sudo.",
                "[!]".bright_yellow()
            );
        }
    }

    Ok(item)
}

/// Classify a system path into the appropriate vault item type
fn classify_system_path(path: &Path) -> VaultItemType {
    let path_str = path.to_string_lossy();
    if path_str.contains("shadow") || path_str.contains("passwd") || path_str.contains("gshadow") {
        VaultItemType::SystemShadow
    } else if path_str.contains("ssh_host")
        || path_str.contains(".ssh/")
        || path_str.contains("id_rsa")
        || path_str.contains("id_ed25519")
    {
        VaultItemType::SystemSsh
    } else if path_str.contains("ssl") || path_str.contains("cert") || path_str.contains("pki") {
        VaultItemType::SystemCert
    } else {
        VaultItemType::SystemConfig
    }
}

/// Restore a system file from the vault to its original location
pub fn restore_file(master: &crypto::MasterKey, id: &str) -> Result<()> {
    let item = vault::get_item(id)?;
    let plaintext = vault::decrypt_item(master, id)?;

    // Verify integrity
    let hash = crypto::blake3_hash(&plaintext);
    if hash != item.blake3_hash {
        return Err(anyhow!(
            "Integrity check failed for {}. Data may be corrupted.",
            item.name
        ));
    }

    let target = Path::new(&item.original_path);

    // If the file has immutable flag, clear it first
    if check_immutable(target) && is_root() {
        clear_immutable(target)?;
    }

    // Restore the file
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(target, &plaintext)?;

    println!(
        "  {} Restored {} -> {}",
        "[+]".bright_green(),
        item.name.bright_white(),
        item.original_path.bright_cyan()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Real-time filesystem monitoring (polling-based)
// ---------------------------------------------------------------------------

/// Watch all system credential files for changes.
/// Polls every `interval_secs` seconds, comparing BLAKE3 hashes.
/// Blocks until Ctrl+C.
pub fn watch_system_files(interval_secs: u64) -> Result<()> {
    let bp = baseline_path();
    if !bp.exists() {
        return Err(anyhow!(
            "No baseline found. Run 'rypton system baseline' first."
        ));
    }

    let baseline: SystemBaseline = serde_json::from_str(&fs::read_to_string(&bp)?)?;

    // Build hash map from baseline
    let mut baseline_hashes: HashMap<String, String> = HashMap::new();
    for entry in &baseline.entries {
        baseline_hashes.insert(entry.path.clone(), entry.blake3_hash.clone());
    }

    println!("\n  {}", "RYPTON SYSTEM MONITOR".bright_cyan().bold());
    println!("  {}\n", "=====================".bright_cyan());
    println!(
        "  Monitoring {} files every {} seconds...",
        baseline_hashes.len().to_string().bright_green(),
        interval_secs.to_string().bright_yellow()
    );
    println!("  Press {} to stop.\n", "Ctrl+C".bright_red());

    loop {
        for (path_str, expected_hash) in &baseline_hashes {
            let path = Path::new(path_str);
            if !path.exists() {
                println!(
                    "  {} [{}] {} -- FILE DELETED",
                    "[!!]".bright_red().bold(),
                    Utc::now().format("%H:%M:%S"),
                    path_str.bright_white()
                );
                continue;
            }

            if let Ok(data) = fs::read(path) {
                let current_hash = crypto::blake3_hash(&data);
                if &current_hash != expected_hash {
                    println!(
                        "  {} [{}] {} -- TAMPER DETECTED (hash mismatch)",
                        "[!!]".bright_red().bold(),
                        Utc::now().format("%H:%M:%S"),
                        path_str.bright_white()
                    );
                }
            }
        }

        thread::sleep(Duration::from_secs(interval_secs));
    }
}

// ---------------------------------------------------------------------------
// System status / listing
// ---------------------------------------------------------------------------

/// Show the protection status of all system credential files
#[allow(dead_code)]
pub fn show_system_status() {
    println!("\n  {}", "SYSTEM CREDENTIAL STATUS".bright_cyan().bold());
    println!("  {}\n", "========================".bright_cyan());

    let mut all_creds = system_credential_registry();
    all_creds.extend(discover_user_ssh_keys());

    let mut total = 0;
    let mut found = 0;
    let mut immutable_count = 0;
    let mut perm_issues = 0;

    println!(
        "  {:<45} {:<8} {:<8} {:<8} {}",
        "PATH".bright_white().bold(),
        "EXISTS".bright_white().bold(),
        "PERMS".bright_white().bold(),
        "IMMUT".bright_white().bold(),
        "CATEGORY".bright_white().bold(),
    );
    println!("  {}", "-".repeat(90).dimmed());

    for cred in &all_creds {
        total += 1;
        let path = Path::new(&cred.path);
        let exists = path.exists();
        if exists {
            found += 1;
        }

        let (perms_str, perms_ok) = if exists {
            if let Ok(meta) = fs::metadata(path) {
                let p = format_permissions(&meta);
                let ok = check_permission_ok(&meta, cred.expected_perms);
                if !ok {
                    perm_issues += 1;
                }
                (p, ok)
            } else {
                ("????".to_string(), false)
            }
        } else {
            ("----".to_string(), true)
        };

        let immut = if exists { check_immutable(path) } else { false };
        if immut {
            immutable_count += 1;
        }

        let exists_badge = if exists {
            "YES".bright_green()
        } else {
            "NO".dimmed()
        };
        let perms_badge = if perms_ok {
            perms_str.bright_green()
        } else {
            perms_str.bright_red()
        };
        let immut_badge = if immut {
            "YES".bright_cyan()
        } else {
            "no".dimmed()
        };
        let cat_color = match cred.category.as_str() {
            "auth" => cred.category.bright_red(),
            "ssh" => cred.category.bright_magenta(),
            "privesc" => cred.category.bright_yellow(),
            "tls" => cred.category.bright_blue(),
            "pam" => cred.category.bright_cyan(),
            "user-ssh" => cred.category.bright_red(),
            _ => cred.category.normal(),
        };

        // Truncate path for display
        let display_path = if cred.path.len() > 43 {
            format!("...{}", &cred.path[cred.path.len() - 40..])
        } else {
            cred.path.clone()
        };

        println!(
            "  {:<45} {:<8} {:<8} {:<8} {}",
            display_path.bright_white(),
            exists_badge,
            perms_badge,
            immut_badge,
            cat_color,
        );
    }

    println!("\n  {}", "Summary:".bright_white().bold());
    println!("    Files tracked:    {}", total.to_string().bright_green());
    println!("    Files present:    {}", found.to_string().bright_green());
    println!(
        "    Immutable:        {}",
        immutable_count.to_string().bright_cyan()
    );
    println!(
        "    Permission issues:{}",
        if perm_issues > 0 {
            format!(" {}", perm_issues).bright_red().to_string()
        } else {
            " 0".bright_green().to_string()
        }
    );
    println!();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if running as root
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // On Unix, UID 0 = root
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Get hostname
fn get_hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("hostname").output() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Format file permissions as octal string
fn format_permissions(meta: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        format!("{:04o}", meta.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        "----".to_string()
    }
}

/// Check if permissions match expected
#[allow(dead_code)]
fn check_permission_ok(meta: &fs::Metadata, _expected: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = meta.permissions().mode() & 0o7777;
        actual <= _expected
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

/// Get owner UID:GID string
fn get_owner_string(path: &Path) -> String {
    #[cfg(unix)]
    {
        if let Ok(meta) = fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            return format!("{}:{}", meta.uid(), meta.gid());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// CODE RED: Self-integrity protection
// ---------------------------------------------------------------------------

/// Check if the Rypton binary itself has been tampered with.
/// First run: stores a BLAKE3 hash. Subsequent: compares against stored.
/// Mismatch = CODE RED: alert, log, refuse to continue.
pub fn code_red_self_check() -> Result<()> {
    let binary_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    let hash_file = vault::vault_root().join(".binary_blake3");
    let binary_data = match fs::read(&binary_path) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let current_hash = crypto::blake3_hash(&binary_data);

    if hash_file.exists() {
        let stored = fs::read_to_string(&hash_file)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !stored.is_empty() && stored != current_hash {
            code_red_alert(&binary_path, &stored, &current_hash)?;
            return Err(anyhow!(
                "CODE RED: Binary integrity failed. If you updated ryp intentionally, \
                 delete ~/.rypton/.binary_blake3 and re-run."
            ));
        }
    } else {
        let dir = hash_file.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        fs::write(&hash_file, &current_hash)?;
    }
    Ok(())
}

fn code_red_alert(bin: &Path, expected: &str, actual: &str) -> Result<()> {
    let now = chrono::Utc::now();
    eprintln!();
    eprintln!(
        "{}",
        "  ╔══════════════════════════════════════════════════════════╗"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║  ██████╗ ██████╗ ██████╗ ███████╗  ██████╗ ███████╗██████╗  ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║ ██╔════╝██╔═══██╗██╔══██╗██╔════╝  ██╔══██╗██╔════╝██╔══██╗ ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║ ██║     ██║   ██║██║  ██║█████╗    ██████╔╝█████╗  ██║  ██║ ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║ ██║     ██║   ██║██║  ██║██╔══╝    ██╔══██╗██╔══╝  ██║  ██║ ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║ ╚██████╗╚██████╔╝██████╔╝███████╗  ██║  ██║███████╗██████╔╝ ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║  ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝  ╚═╝  ╚═╝╚══════╝╚═════╝  ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║                                                              ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ║  BINARY INTEGRITY COMPROMISED — DO NOT ENTER YOUR PASSWORD   ║"
            .bright_red()
            .bold()
    );
    eprintln!(
        "{}",
        "  ╚══════════════════════════════════════════════════════════════╝"
            .bright_red()
            .bold()
    );
    eprintln!();
    eprintln!(
        "  {} The ryp binary has been modified since last verified.",
        "[!]".bright_red().bold()
    );
    eprintln!(
        "  {} Binary:   {}",
        "[!]".bright_red(),
        bin.display().to_string().bright_white()
    );
    eprintln!(
        "  {} Expected: {}...",
        "[!]".bright_red(),
        &expected[..std::cmp::min(32, expected.len())]
    );
    eprintln!(
        "  {} Actual:   {}...",
        "[!]".bright_red(),
        &actual[..std::cmp::min(32, actual.len())]
    );
    eprintln!();

    // Force notification (bypasses cooldown)
    crate::scanner::notify_desktop_force(
        "⚠️ CODE RED — Rypton Binary Tampered",
        "The ryp binary hash has changed! Do NOT enter your password. Check ~/.rypton/logs/code_red.log",
        "critical",
    );

    // Log incident
    let log_dir = vault::vault_root().join("logs");
    fs::create_dir_all(&log_dir)?;
    let entry = format!(
        "[{}] CODE RED\n  Binary: {}\n  Expected: {}\n  Actual: {}\n  Action: Halted.\n\n",
        now.format("%Y-%m-%d %H:%M:%S UTC"),
        bin.display(),
        expected,
        actual
    );
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("code_red.log"))?;
    f.write_all(entry.as_bytes())?;

    eprintln!(
        "  {} Logged to ~/.rypton/logs/code_red.log",
        "[+]".bright_yellow()
    );
    eprintln!(
        "  {} If you updated ryp intentionally, delete ~/.rypton/.binary_blake3",
        "[i]".bright_cyan()
    );
    eprintln!();
    Ok(())
}

/// Reset stored binary hash (after intentional update)
#[allow(dead_code)]
pub fn reset_binary_hash() -> Result<()> {
    let f = vault::vault_root().join(".binary_blake3");
    if f.exists() {
        fs::remove_file(&f)?;
    }
    code_red_self_check()
}
