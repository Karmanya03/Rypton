#![allow(dead_code)]
/// Audit module: scans for unencrypted secrets on local AND system filesystems.
use crate::system_guard;
use anyhow::Result;
use colored::*;
use std::fs;
use std::path::Path;

/// Well-known user-level locations to check for unencrypted secrets
const SECRETS_PATTERNS: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".ssh/config",
    ".gnupg/secring.gpg",
    ".gnupg/trustdb.gpg",
    ".aws/credentials",
    ".aws/config",
    ".kube/config",
    ".docker/config.json",
    ".config/gcloud/credentials.db",
    ".config/gcloud/application_default_credentials.json",
    ".netrc",
    ".env",
    ".pgpass",
    ".my.cnf",
    ".bash_history",
    ".zsh_history",
    ".mysql_history",
    ".psql_history",
    ".python_history",
    ".npmrc",
    ".yarnrc",
    ".composer/auth.json",
    ".gem/credentials",
    ".config/gh/hosts.yml",
    ".config/hub",
    ".terraform.d/credentials.tfrc.json",
    ".vault-token",
];

/// System-level files that should never be world-readable
const SYSTEM_SENSITIVE_FILES: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_dsa_key",
    "/etc/sudoers",
    "/etc/ssl/private",
    "/etc/security/opasswd",
    "/etc/krb5.keytab",
];

/// File content patterns that indicate unencrypted private keys
const PRIVATE_KEY_HEADERS: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN CERTIFICATE-----", // not secret but noteworthy
];

/// Patterns that indicate credential content in files
#[allow(dead_code)]
const CREDENTIAL_PATTERNS: &[&str] = &[
    "password",
    "secret_key",
    "access_key",
    "api_key",
    "apikey",
    "token",
    "AWS_SECRET",
    "PRIVATE_KEY",
];

pub fn run_audit() -> Result<()> {
    println!("{}", "\n  RYPTON SECURITY AUDIT".bright_cyan().bold());
    println!("{}", "  ====================\n".bright_cyan());

    let home = dirs::home_dir().expect("Could not determine home directory");
    let mut findings: Vec<Finding> = Vec::new();
    let is_root = system_guard::is_root();

    // Phase 1: User-level secret locations
    println!(
        "{}",
        "  [1/5] Scanning user-level secret locations...".bright_yellow()
    );
    for pattern in SECRETS_PATTERNS {
        let path = home.join(pattern);
        if path.exists() && path.is_file() {
            findings.push(Finding {
                path: path.display().to_string(),
                severity: Severity::Warning,
                reason: format!(
                    "Unencrypted file at well-known credential location: {}",
                    pattern
                ),
                category: "user-secrets".to_string(),
            });
        }
    }

    // Phase 2: SSH key encryption audit
    println!(
        "{}",
        "  [2/5] Auditing SSH key encryption status...".bright_yellow()
    );
    let ssh_dir = home.join(".ssh");
    if ssh_dir.exists() {
        scan_ssh_keys(&ssh_dir, &mut findings)?;
    }

    // Phase 3: System-level credential audit (requires root for full coverage)
    println!(
        "{}",
        "  [3/5] Auditing system-level credentials...".bright_yellow()
    );
    if !is_root {
        println!(
            "  {}",
            "       (running without root -- some checks will be limited)".dimmed()
        );
    }
    scan_system_credentials(&mut findings, is_root);

    // Phase 4: .env file scan across project directories
    println!(
        "{}",
        "  [4/5] Scanning for exposed .env and credential files...".bright_yellow()
    );
    let project_dirs = [
        "projects",
        "lab",
        "dev",
        "code",
        "src",
        "workspace",
        "repos",
        "git",
        "work",
    ];
    for dir_name in &project_dirs {
        let dir = home.join(dir_name);
        if dir.exists() {
            scan_env_files(&dir, &mut findings, 4)?;
        }
    }

    // Phase 5: File permission audit on system credentials
    println!("{}", "  [5/5] Auditing file permissions...".bright_yellow());
    let registry = system_guard::system_credential_registry();
    for cred in &registry {
        let path = Path::new(&cred.path);
        if !path.exists() || path.is_dir() {
            continue;
        }
        if let Ok(meta) = fs::metadata(path) {
            check_permissions(
                path,
                &meta,
                cred.expected_perms,
                cred.critical,
                &mut findings,
            );
        }
    }

    // Report
    println!();
    if findings.is_empty() {
        println!(
            "{}",
            "  [+] No unencrypted secrets or issues found. Your machine is clean.".bright_green()
        );
    } else {
        // Group by severity
        let crits = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        let warns = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Warning))
            .count();
        let infos = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count();

        println!(
            "  {} total findings: {} critical, {} warning, {} info\n",
            findings.len().to_string().bright_white().bold(),
            crits.to_string().bright_red(),
            warns.to_string().bright_yellow(),
            infos.to_string().bright_blue(),
        );

        for (i, finding) in findings.iter().enumerate() {
            let sev_badge = match finding.severity {
                Severity::Critical => "CRIT".bright_red().bold(),
                Severity::Warning => "WARN".bright_yellow().bold(),
                Severity::Info => "INFO".bright_blue().bold(),
            };
            println!(
                "  {}. [{}] [{}] {}",
                i + 1,
                sev_badge,
                finding.category.dimmed(),
                finding.path.bright_white()
            );
            println!("     {}", finding.reason.dimmed());
            println!();
        }

        println!("  {}", "Recommendations:".bright_yellow().bold());
        if crits > 0 {
            println!(
                "    {} Move unencrypted private keys into the vault:",
                "-".bright_red()
            );
            println!(
                "      {}",
                "rypton vault add ~/.ssh/id_rsa --type ssh".dimmed()
            );
            println!(
                "      {}",
                "sudo rypton system protect /etc/shadow --lock".dimmed()
            );
        }
        if warns > 0 {
            println!(
                "    {} Review and vault sensitive config files:",
                "-".bright_yellow()
            );
            println!("      {}", "rypton vault add <path> --type custom".dimmed());
        }
        println!(
            "    {} Create a system integrity baseline:",
            "-".bright_cyan()
        );
        println!("      {}", "sudo rypton system baseline".dimmed());
    }

    println!();
    Ok(())
}

fn scan_ssh_keys(ssh_dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    for entry in fs::read_dir(ssh_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.ends_with(".pub") || name == "known_hosts" || name == "authorized_keys" {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&path) {
            let prefix = if content.len() > 512 {
                &content[..512]
            } else {
                &content
            };
            for header in PRIVATE_KEY_HEADERS {
                if prefix.contains(header) {
                    let is_encrypted = prefix.contains("ENCRYPTED");
                    if !is_encrypted {
                        findings.push(Finding {
                            path: path.display().to_string(),
                            severity: Severity::Critical,
                            reason: "Unencrypted private key detected. No passphrase protection."
                                .to_string(),
                            category: "ssh-keys".to_string(),
                        });
                    }
                    break;
                }
            }
        }
    }
    Ok(())
}

fn scan_system_credentials(findings: &mut Vec<Finding>, _is_root: bool) {
    for sys_file in SYSTEM_SENSITIVE_FILES {
        let path = Path::new(sys_file);
        if !path.exists() {
            continue;
        }

        // Check if world-readable
        #[cfg(unix)]
        {
            if let Ok(meta) = fs::metadata(path) {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o004 != 0 {
                    findings.push(Finding {
                        path: sys_file.to_string(),
                        severity: Severity::Critical,
                        reason: format!("System credential file is WORLD-READABLE (mode {:04o}). This is a serious security issue.", mode & 0o7777),
                        category: "system-perms".to_string(),
                    });
                }
            }
        }

        // Check if immutable flag is set
        if !system_guard::check_immutable(path) {
            findings.push(Finding {
                path: sys_file.to_string(),
                severity: Severity::Info,
                reason: "System file is not immutable. Consider: sudo rypton system lock <path>"
                    .to_string(),
                category: "system-hardening".to_string(),
            });
        }
    }
}

fn check_permissions(
    path: &Path,
    meta: &fs::Metadata,
    expected: u32,
    critical: bool,
    findings: &mut Vec<Finding>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = meta.permissions().mode() & 0o7777;
        if actual > expected {
            findings.push(Finding {
                path: path.display().to_string(),
                severity: if critical {
                    Severity::Warning
                } else {
                    Severity::Info
                },
                reason: format!(
                    "Permissions too open: {:04o} (expected <= {:04o})",
                    actual, expected
                ),
                category: "permissions".to_string(),
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta, expected, critical, findings);
    }
}

fn scan_env_files(dir: &Path, findings: &mut Vec<Finding>, max_depth: usize) -> Result<()> {
    if max_depth == 0 {
        return Ok(());
    }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            if path.is_file() && (name == ".env" || name.starts_with(".env.")) {
                findings.push(Finding {
                    path: path.display().to_string(),
                    severity: Severity::Warning,
                    reason: "Environment file may contain API keys, tokens, or passwords."
                        .to_string(),
                    category: "env-files".to_string(),
                });
            }

            if path.is_dir()
                && !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && name != "vendor"
            {
                scan_env_files(&path, findings, max_depth - 1)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug)]
struct Finding {
    path: String,
    severity: Severity,
    reason: String,
    category: String,
}
