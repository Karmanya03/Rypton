/// Professional security report generator.
/// Generates timestamped Markdown reports from scan findings.
/// Reports auto-accumulate in ~/.rypton/reports/.
use crate::scanner::{RiskLevel, ScanCategory, ScanFinding};
use crate::system_guard;
use crate::vault;
use anyhow::Result;
use chrono::Utc;
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn reports_dir() -> PathBuf {
    vault::vault_root().join("reports")
}

/// Generate a full security report from scan findings
pub fn generate_report(findings: &[ScanFinding]) -> Result<PathBuf> {
    fs::create_dir_all(reports_dir())?;

    let now = Utc::now();
    let filename = format!("rypton_report_{}.md", now.format("%Y-%m-%d_%H-%M-%S"));
    let path = reports_dir().join(&filename);

    let hostname = get_hostname();
    let is_root = system_guard::is_root();

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

    let risk_score = crits * 10 + highs * 5 + meds * 2 + lows;
    let risk_grade = match risk_score {
        0 => "A+ (Excellent)",
        1..=5 => "A (Good)",
        6..=15 => "B (Moderate)",
        16..=30 => "C (Concerning)",
        31..=60 => "D (Poor)",
        _ => "F (Critical)",
    };

    // Group findings by category
    let mut by_category: HashMap<String, Vec<&ScanFinding>> = HashMap::new();
    for f in findings {
        by_category
            .entry(f.category.to_string())
            .or_default()
            .push(f);
    }

    let mut report = String::new();

    // Header
    report.push_str("# Rypton Security Report\n\n");
    report.push_str(&format!(
        "**Generated:** {}  \n",
        now.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str(&format!("**Host:** {}  \n", hostname));
    report.push_str(&format!(
        "**Scan Level:** {}  \n",
        if is_root {
            "Root (full)"
        } else {
            "User (limited)"
        }
    ));
    report.push_str(&format!("**Risk Grade:** **{}**  \n", risk_grade));
    report.push_str(&format!(
        "**Risk Score:** {} / 100\n\n",
        risk_score.min(100)
    ));

    // Executive Summary
    report.push_str("---\n\n## Executive Summary\n\n");
    report.push_str(&format!(
        "Rypton scanned the system and identified **{} findings** across {} categories.\n\n",
        findings.len(),
        by_category.len()
    ));

    report.push_str("| Risk Level | Count | Action Required |\n");
    report.push_str("|---|---|---|\n");
    if crits > 0 {
        report.push_str(&format!(
            "| 🔴 CRITICAL | {} | Immediate remediation required |\n",
            crits
        ));
    }
    if highs > 0 {
        report.push_str(&format!(
            "| 🟠 HIGH | {} | Address within 24 hours |\n",
            highs
        ));
    }
    if meds > 0 {
        report.push_str(&format!(
            "| 🟡 MEDIUM | {} | Schedule for remediation |\n",
            meds
        ));
    }
    if lows > 0 {
        report.push_str(&format!(
            "| 🔵 LOW | {} | Review at next maintenance |\n",
            lows
        ));
    }
    if infos > 0 {
        report.push_str(&format!("| ⚪ INFO | {} | Acknowledged |\n", infos));
    }
    report.push('\n');

    // What Could Be Targeted
    report.push_str("## What Could Be Targeted\n\n");
    report.push_str("Based on the scan results, the following attack vectors are available:\n\n");

    if crits > 0 || highs > 0 {
        let suid_count = findings
            .iter()
            .filter(|f| f.category == ScanCategory::Suid && f.risk <= RiskLevel::High)
            .count();
        let cap_count = findings
            .iter()
            .filter(|f| f.category == ScanCategory::Capability && f.risk <= RiskLevel::High)
            .count();
        let secret_count = findings
            .iter()
            .filter(|f| f.category == ScanCategory::UnencryptedSecret)
            .count();
        let ww_count = findings
            .iter()
            .filter(|f| f.category == ScanCategory::WorldWritable)
            .count();
        let perm_count = findings
            .iter()
            .filter(|f| f.category == ScanCategory::WeakPermissions)
            .count();

        if suid_count > 0 {
            report.push_str(&format!("- **{} unknown SUID binaries** — potential privilege escalation to root via GTFOBins or custom exploits\n", suid_count));
        }
        if cap_count > 0 {
            report.push_str(&format!("- **{} dangerous capabilities** — binaries with elevated kernel permissions that bypass normal access controls\n", cap_count));
        }
        if secret_count > 0 {
            report.push_str(&format!("- **{} unencrypted credential files** — SSH keys, API tokens, database passwords readable by any local process\n", secret_count));
        }
        if ww_count > 0 {
            report.push_str(&format!("- **{} world-writable files** — any user can inject malicious content, backdoors, or config overrides\n", ww_count));
        }
        if perm_count > 0 {
            report.push_str(&format!("- **{} weak permission entries** — system credential files with overly permissive access\n", perm_count));
        }
    } else {
        report.push_str(
            "No critical or high-risk attack vectors identified. System hardening is effective.\n",
        );
    }
    report.push('\n');

    // What Can Be Protected
    report.push_str("## What Can Be Protected\n\n");
    report.push_str("Rypton can directly remediate or mitigate the following:\n\n");
    report.push_str("| Finding Type | Rypton Command | Effect |\n");
    report.push_str("|---|---|---|\n");
    report.push_str("| Unencrypted secrets | `ryp add <path>` | Encrypt and vault the file |\n");
    report.push_str("| Weak file permissions | `ryp lock <path>` | Set kernel immutable flag |\n");
    report.push_str("| System credentials | `ryp protect <path>` | Backup + encrypt + lock |\n");
    report.push_str(
        "| Integrity monitoring | `ryp baseline` + `ryp verify` | Detect unauthorized changes |\n",
    );
    report.push_str(
        "| Real-time alerting | `ryp watch` | Background tamper detection with notifications |\n",
    );
    report.push('\n');

    // What Cannot Be Protected
    report.push_str("## What Cannot Be Protected by Rypton\n\n");
    report.push_str("| Risk | Reason | Mitigation |\n");
    report.push_str("|---|---|---|\n");
    report.push_str("| SUID binaries | Requires package management changes | Use `chmod u-s` or remove unnecessary SUID |\n");
    report.push_str(
        "| File capabilities | Requires `setcap` changes | Remove with `setcap -r <binary>` |\n",
    );
    report.push_str(
        "| Kernel compromise | Beyond userspace protection | Use Secure Boot, module signing |\n",
    );
    report.push_str("| Physical access | Hardware-level threat | Full-disk encryption (LUKS) |\n");
    report
        .push_str("| Unowned files | Requires ownership assignment | `chown root:root <path>` |\n");
    report.push('\n');

    // Potential Impact
    report.push_str("## Potential Impact if Exploited\n\n");
    if crits > 0 {
        report
            .push_str("⚠️ **CRITICAL findings present.** An attacker with local access could:\n\n");
        report.push_str("- Escalate to root via SUID/capability abuse\n");
        report.push_str("- Read system password hashes from world-readable `/etc/shadow`\n");
        report.push_str("- Steal SSH keys, API tokens, and database credentials\n");
        report.push_str("- Persist access by modifying system configs, PAM, or cron\n");
        report.push_str("- Pivot to other systems using stolen credentials\n\n");
    } else if highs > 0 {
        report.push_str("🟠 **HIGH risk findings present.** Exploitation could lead to:\n\n");
        report.push_str("- Credential theft from unencrypted files\n");
        report.push_str("- Unauthorized data modification via world-writable files\n");
        report.push_str("- Potential lateral movement using stolen keys/tokens\n\n");
    } else {
        report.push_str("✅ System risk is low. No immediate exploitation vectors identified.\n\n");
    }

    // Detailed Findings
    report.push_str("---\n\n## Detailed Findings\n\n");
    for (cat, cat_findings) in &by_category {
        report.push_str(&format!("### {}\n\n", cat));
        report.push_str("| # | Risk | Path | Description |\n");
        report.push_str("|---|---|---|---|\n");
        for (i, f) in cat_findings.iter().enumerate() {
            let risk_emoji = match f.risk {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🔵",
                RiskLevel::Info => "⚪",
            };
            let short_path = if f.path.len() > 50 {
                format!("...{}", &f.path[f.path.len() - 47..])
            } else {
                f.path.clone()
            };
            report.push_str(&format!(
                "| {} | {} {} | `{}` | {} |\n",
                i + 1,
                risk_emoji,
                f.risk,
                short_path,
                f.description
            ));
        }
        report.push('\n');
    }

    // Recommendations
    report.push_str("## Recommended Actions\n\n");
    report.push_str("```bash\n");
    report.push_str("# 1. Create integrity baseline\n");
    report.push_str("sudo ryp baseline\n\n");
    report.push_str("# 2. Protect critical system files\n");
    report.push_str("sudo ryp protect /etc/shadow --lock\n");
    report.push_str("sudo ryp protect /etc/ssh/ssh_host_ed25519_key --lock\n\n");
    report.push_str("# 3. Vault your SSH keys\n");
    report.push_str("ryp add ~/.ssh/id_ed25519\n\n");
    report.push_str("# 4. Start background monitoring\n");
    report.push_str("sudo ryp watch &\n");
    report.push_str("```\n\n");

    // Footer
    report.push_str(&format!(
        "---\n\n*Report generated by Rypton v{} at {}*\n",
        env!("CARGO_PKG_VERSION"),
        now.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    fs::write(&path, &report)?;

    println!(
        "  {} Report saved: {}",
        "[+]".bright_green(),
        path.display().to_string().bright_cyan()
    );
    Ok(path)
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("hostname").output() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Update the latest report link
pub fn update_latest_link(report_path: &std::path::Path) -> Result<()> {
    let latest = reports_dir().join("latest.md");
    let content = fs::read_to_string(report_path)?;
    fs::write(latest, content)?;
    Ok(())
}
