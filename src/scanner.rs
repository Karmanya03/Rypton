/// Advanced system-wide security scanner.
/// Detects: SUID/SGID binaries, Linux capabilities, world-writable files,
/// weak permissions, unencrypted secrets, and unowned files.
/// Designed for low resource usage: metadata-only checks, smart directory skipping.
use crate::system_guard;
use anyhow::Result;
#[allow(unused_imports)]
use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::collections::HashSet;
#[allow(unused_imports)]
use std::fs;
use std::path::Path;
#[allow(unused_imports)]
use std::process::Command;
#[allow(unused_imports)]
use walkdir::WalkDir;

/// Directories to skip (virtual/pseudo filesystems)
#[allow(dead_code)]
const SKIP_DIRS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/cache",
    "/var/log/journal",
    "/lost+found",
];

/// Directories to scan for SUID/SGID/caps
#[allow(dead_code)]
const SCAN_ROOTS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/opt", "/etc", "/var", "/tmp", "/home", "/root",
];

/// Known legitimate SUID binaries (reduced false positives)
const KNOWN_SUID: &[&str] = &[
    "sudo",
    "su",
    "passwd",
    "ping",
    "mount",
    "umount",
    "chsh",
    "chfn",
    "newgrp",
    "gpasswd",
    "pkexec",
    "crontab",
    "at",
    "fusermount",
    "fusermount3",
    "ssh-agent",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub path: String,
    pub category: ScanCategory,
    pub risk: RiskLevel,
    pub description: String,
    pub impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ScanCategory {
    Suid,
    Sgid,
    Capability,
    WorldWritable,
    WeakPermissions,
    UnencryptedSecret,
    UnownedFile,
    StickyBitMissing,
}

impl std::fmt::Display for ScanCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanCategory::Suid => write!(f, "SUID"),
            ScanCategory::Sgid => write!(f, "SGID"),
            ScanCategory::Capability => write!(f, "CAPABILITY"),
            ScanCategory::WorldWritable => write!(f, "WORLD-WRITE"),
            ScanCategory::WeakPermissions => write!(f, "WEAK-PERMS"),
            ScanCategory::UnencryptedSecret => write!(f, "UNENCRYPTED"),
            ScanCategory::UnownedFile => write!(f, "UNOWNED"),
            ScanCategory::StickyBitMissing => write!(f, "NO-STICKY"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Info => write!(f, "INFO"),
        }
    }
}

/// Run a full system-wide security scan
pub fn full_scan() -> Result<Vec<ScanFinding>> {
    let mut findings = Vec::new();
    let is_root = system_guard::is_root();

    println!(
        "\n  {}",
        "RYPTON SYSTEM-WIDE SECURITY SCAN".bright_cyan().bold()
    );
    println!("  {}\n", "================================".bright_cyan());

    if !is_root {
        println!(
            "  {} Running without root. Some checks will be limited.\n",
            "[!]".bright_yellow()
        );
    }

    // Phase 1: SUID/SGID binaries
    println!(
        "  {} Scanning for SUID/SGID binaries...",
        "[1/6]".bright_yellow()
    );
    findings.extend(scan_suid_sgid());

    // Phase 2: Linux capabilities
    println!(
        "  {} Scanning for file capabilities...",
        "[2/6]".bright_yellow()
    );
    findings.extend(scan_capabilities());

    // Phase 3: World-writable files
    println!(
        "  {} Scanning for world-writable files...",
        "[3/6]".bright_yellow()
    );
    findings.extend(scan_world_writable());

    // Phase 4: Sensitive file permissions
    println!(
        "  {} Auditing system credential permissions...",
        "[4/6]".bright_yellow()
    );
    findings.extend(scan_sensitive_permissions());

    // Phase 5: Unencrypted secrets
    println!(
        "  {} Scanning for unencrypted secrets...",
        "[5/6]".bright_yellow()
    );
    findings.extend(scan_unencrypted_secrets());

    // Phase 6: Unowned files
    if is_root {
        println!(
            "  {} Scanning for unowned files...",
            "[6/6]".bright_yellow()
        );
        findings.extend(scan_unowned());
    } else {
        println!(
            "  {} Skipping unowned files scan (needs root).",
            "[6/6]".dimmed()
        );
    }

    // Sort by risk level
    findings.sort_by(|a, b| a.risk.cmp(&b.risk));

    // Desktop notifications for critical/high
    let crits = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::Critical)
        .count();
    let highs = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::High)
        .count();
    if crits > 0 || highs > 0 {
        notify_desktop(
            "Rypton Security Alert",
            &format!("{} critical, {} high risk findings detected!", crits, highs),
            if crits > 0 { "critical" } else { "normal" },
        );
    }

    // Print summary
    println!();
    print_scan_summary(&findings);

    Ok(findings)
}

#[allow(dead_code)]
fn should_skip(path: &Path) -> bool {
    let s = path.to_string_lossy();
    SKIP_DIRS.iter().any(|skip| s.starts_with(skip))
}

/// Scan for SUID binaries
#[allow(unused_mut, unused_variables)]
fn scan_suid_sgid() -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let known: HashSet<&str> = KNOWN_SUID.iter().copied().collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for root in SCAN_ROOTS {
            let root_path = Path::new(root);
            if !root_path.exists() {
                continue;
            }

            for entry in WalkDir::new(root)
                .max_depth(6)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if should_skip(entry.path()) {
                    continue;
                }
                if !entry.file_type().is_file() {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    let mode = meta.permissions().mode();
                    let name = entry.file_name().to_string_lossy().to_string();
                    let is_known = known.contains(name.as_str());

                    // SUID check (bit 0o4000)
                    if mode & 0o4000 != 0 {
                        findings.push(ScanFinding {
                            path: entry.path().display().to_string(),
                            category: ScanCategory::Suid,
                            risk: if is_known {
                                RiskLevel::Info
                            } else {
                                RiskLevel::High
                            },
                            description: format!(
                                "SUID binary: {} (mode {:04o})",
                                name,
                                mode & 0o7777
                            ),
                            impact: if is_known {
                                "Known system binary with SUID. Expected.".into()
                            } else {
                                "Unknown SUID binary. Could allow privilege escalation to owner."
                                    .into()
                            },
                            recommendation: if is_known {
                                "Verify this binary is from a trusted package.".into()
                            } else {
                                "Investigate immediately. Remove SUID bit if unnecessary: chmod u-s"
                                    .into()
                            },
                        });
                    }

                    // SGID check (bit 0o2000)
                    if mode & 0o2000 != 0 && !entry.file_type().is_dir() {
                        findings.push(ScanFinding {
                            path: entry.path().display().to_string(),
                            category: ScanCategory::Sgid,
                            risk: if is_known { RiskLevel::Info } else { RiskLevel::Medium },
                            description: format!("SGID binary: {} (mode {:04o})", name, mode & 0o7777),
                            impact: "SGID binary executes with group privileges. Could leak group access.".into(),
                            recommendation: "Verify necessity. Remove SGID bit if unnecessary: chmod g-s".into(),
                        });
                    }
                }
            }
        }
    }
    findings
}

/// Scan for Linux capabilities using getcap
#[allow(unused_mut)]
fn scan_capabilities() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];
        for dir in &dirs {
            if let Ok(output) = Command::new("getcap")
                .arg("-r")
                .arg(dir)
                .stderr(std::process::Stdio::null())
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    let dangerous = line.contains("cap_setuid")
                        || line.contains("cap_setgid")
                        || line.contains("cap_net_raw")
                        || line.contains("cap_sys_admin")
                        || line.contains("cap_dac_override")
                        || line.contains("cap_sys_ptrace");

                    findings.push(ScanFinding {
                        path: line
                            .split_whitespace()
                            .next()
                            .unwrap_or("unknown")
                            .to_string(),
                        category: ScanCategory::Capability,
                        risk: if dangerous {
                            RiskLevel::High
                        } else {
                            RiskLevel::Medium
                        },
                        description: format!("File capability: {}", line.trim()),
                        impact: if dangerous {
                            "Dangerous capability that could enable privilege escalation.".into()
                        } else {
                            "File has extended capabilities beyond normal permissions.".into()
                        },
                        recommendation: "Verify this capability is intentional and required."
                            .into(),
                    });
                }
            }
        }
    }
    findings
}

/// Scan for world-writable files in sensitive locations
#[allow(unused_mut)]
fn scan_world_writable() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sensitive_roots = ["/etc", "/usr", "/bin", "/sbin", "/opt", "/var/www", "/home"];

        for root in &sensitive_roots {
            let root_path = Path::new(root);
            if !root_path.exists() {
                continue;
            }

            for entry in WalkDir::new(root)
                .max_depth(4)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if should_skip(entry.path()) {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    let mode = meta.permissions().mode();

                    // World-writable file (not in /tmp, not symlink)
                    if mode & 0o002 != 0 && entry.file_type().is_file() {
                        findings.push(ScanFinding {
                            path: entry.path().display().to_string(),
                            category: ScanCategory::WorldWritable,
                            risk: RiskLevel::High,
                            description: format!(
                                "World-writable file (mode {:04o})",
                                mode & 0o7777
                            ),
                            impact:
                                "Any user can modify this file. Potential for backdoor injection."
                                    .into(),
                            recommendation: "Remove world-write: chmod o-w".into(),
                        });
                    }

                    // World-writable directory without sticky bit
                    if mode & 0o002 != 0 && entry.file_type().is_dir() && mode & 0o1000 == 0 {
                        let path_str = entry.path().to_string_lossy();
                        if !path_str.starts_with("/tmp") && !path_str.starts_with("/var/tmp") {
                            findings.push(ScanFinding {
                                path: entry.path().display().to_string(),
                                category: ScanCategory::StickyBitMissing,
                                risk: RiskLevel::Medium,
                                description: format!(
                                    "World-writable dir without sticky bit (mode {:04o})",
                                    mode & 0o7777
                                ),
                                impact: "Any user can delete/rename files owned by others.".into(),
                                recommendation: "Set sticky bit: chmod +t".into(),
                            });
                        }
                    }
                }
            }
        }
    }
    findings
}

/// Check permissions on known sensitive system files
#[allow(unused_mut, unused_variables)]
fn scan_sensitive_permissions() -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let creds = system_guard::system_credential_registry();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for cred in &creds {
            let path = Path::new(&cred.path);
            if !path.exists() || path.is_dir() {
                continue;
            }
            if let Ok(meta) = fs::metadata(path) {
                let mode = meta.permissions().mode() & 0o7777;
                if mode > cred.expected_perms {
                    findings.push(ScanFinding {
                        path: cred.path.clone(),
                        category: ScanCategory::WeakPermissions,
                        risk: if cred.critical {
                            RiskLevel::Critical
                        } else {
                            RiskLevel::Medium
                        },
                        description: format!(
                            "{}: permissions {:04o} (expected <= {:04o})",
                            cred.description, mode, cred.expected_perms
                        ),
                        impact: if mode & 0o004 != 0 {
                            "File is world-readable. Any user can read sensitive credentials."
                                .into()
                        } else {
                            "Permissions are more open than necessary.".into()
                        },
                        recommendation: format!(
                            "Fix: chmod {:04o} {}",
                            cred.expected_perms, cred.path
                        ),
                    });
                }
            }
        }
    }
    findings
}

/// Scan for unencrypted secrets in well-known locations
fn scan_unencrypted_secrets() -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return findings,
    };

    let secrets = [
        (".ssh/id_rsa", "Unencrypted RSA private key"),
        (".ssh/id_ed25519", "Unencrypted Ed25519 private key"),
        (".ssh/id_ecdsa", "Unencrypted ECDSA private key"),
        (".aws/credentials", "AWS credentials file"),
        (".kube/config", "Kubernetes config with tokens"),
        (".docker/config.json", "Docker auth config"),
        (".netrc", "FTP/HTTP credentials in plaintext"),
        (".env", "Environment file with secrets"),
        (".pgpass", "PostgreSQL password file"),
        (".vault-token", "HashiCorp Vault token"),
        (".npmrc", "NPM auth token"),
    ];

    for (rel, desc) in &secrets {
        let path = home.join(rel);
        if path.exists() && path.is_file() {
            findings.push(ScanFinding {
                path: path.display().to_string(),
                category: ScanCategory::UnencryptedSecret,
                risk: RiskLevel::High,
                description: desc.to_string(),
                impact: "Plaintext credentials accessible to any process running as your user."
                    .into(),
                recommendation: format!("Move to vault: ryp add {}", path.display()),
            });
        }
    }
    findings
}

/// Scan for files not owned by any valid user/group
#[allow(unused_mut)]
fn scan_unowned() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Use find command for efficiency (kernel-optimized)
        if let Ok(output) = Command::new("find")
            .args(["/etc", "/usr", "/bin", "/sbin", "-nouser", "-o", "-nogroup"])
            .stderr(std::process::Stdio::null())
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().take(50) {
                if line.is_empty() {
                    continue;
                }
                findings.push(ScanFinding {
                    path: line.to_string(),
                    category: ScanCategory::UnownedFile,
                    risk: RiskLevel::Medium,
                    description: "File has no valid owner or group".into(),
                    impact:
                        "Orphaned files may indicate deleted user accounts or compromised packages."
                            .into(),
                    recommendation: "Investigate origin. Assign proper ownership or remove.".into(),
                });
            }
        }
    }
    findings
}

/// Cooldown between desktop notifications (seconds).
/// Prevents spam — only one notification per 5 minutes unless it's CODE RED.
const NOTIFY_COOLDOWN_SECS: i64 = 300;

/// Send desktop notification with rate-limiting.
/// Won't fire more than once per NOTIFY_COOLDOWN_SECS to avoid annoying the user.
pub fn notify_desktop(title: &str, body: &str, urgency: &str) {
    let cooldown_file = crate::vault::vault_root().join(".last_notify");

    // Check cooldown
    if cooldown_file.exists()
        && let Ok(content) = std::fs::read_to_string(&cooldown_file)
        && let Ok(last_ts) = content.trim().parse::<i64>()
    {
        let now = chrono::Utc::now().timestamp();
        if now - last_ts < NOTIFY_COOLDOWN_SECS {
            return; // Still in cooldown, don't spam
        }
    }

    send_notification(title, body, urgency);

    // Update cooldown timestamp
    let _ = std::fs::write(&cooldown_file, chrono::Utc::now().timestamp().to_string());
}

/// Force-send a notification, bypassing cooldown (for CODE RED events)
pub fn notify_desktop_force(title: &str, body: &str, urgency: &str) {
    send_notification(title, body, urgency);
}

fn send_notification(title: &str, body: &str, urgency: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send")
            .arg("-u")
            .arg(urgency)
            .arg("-i")
            .arg("security-high")
            .arg("-a")
            .arg("Rypton")
            .arg(title)
            .arg(body)
            .spawn();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (title, body, urgency);
    }
}

fn print_scan_summary(findings: &[ScanFinding]) {
    let crits = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::Critical)
        .count();
    let highs = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::High)
        .count();
    let meds = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::Medium)
        .count();
    let lows = findings.iter().filter(|f| f.risk == RiskLevel::Low).count();
    let infos = findings
        .iter()
        .filter(|f| f.risk == RiskLevel::Info)
        .count();

    println!(
        "  {} total findings:\n",
        findings.len().to_string().bright_white().bold()
    );

    if crits > 0 {
        println!(
            "    {} {}",
            crits.to_string().bright_red().bold(),
            "CRITICAL".bright_red()
        );
    }
    if highs > 0 {
        println!(
            "    {} {}",
            highs.to_string().bright_yellow().bold(),
            "HIGH".bright_yellow()
        );
    }
    if meds > 0 {
        println!(
            "    {} {}",
            meds.to_string().bright_blue(),
            "MEDIUM".bright_blue()
        );
    }
    if lows > 0 {
        println!("    {} LOW", lows.to_string().dimmed());
    }
    if infos > 0 {
        println!("    {} INFO", infos.to_string().dimmed());
    }

    println!();

    // Print critical and high findings
    for (i, f) in findings
        .iter()
        .filter(|f| f.risk <= RiskLevel::High)
        .enumerate()
    {
        let badge = match f.risk {
            RiskLevel::Critical => "CRIT".bright_red().bold(),
            RiskLevel::High => "HIGH".bright_yellow().bold(),
            _ => "----".dimmed(),
        };
        println!(
            "  {}. [{}] [{}] {}",
            i + 1,
            badge,
            f.category.to_string().dimmed(),
            f.path.bright_white()
        );
        println!("     {}", f.description.dimmed());
        println!("     Impact: {}", f.impact.bright_yellow());
        println!("     Fix: {}", f.recommendation.bright_green());
        println!();
    }
}
