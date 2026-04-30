/// CLI module: flat, simple English commands.
/// Binary: ryp
use crate::{crypto, report, scanner, system_guard, tui_app, vault};
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use dialoguer::{Confirm, Password};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ryp",
    version,
    about = "Kernel-level, tamper-proof secrets vault and system credential guardian.",
    long_about = "Rypton (ryp) -- kernel-level tamper-proof vault.\n\
                  XChaCha20-Poly1305 + Argon2id + chattr +i.\n\
                  No cloud. No GUI. No network. No mercy.",
    after_help = "Run 'ryp <command> --help' for details."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault
    Init,
    /// Auto-detect and protect system credentials and user secrets
    Shield,
    /// Add a file to the vault (auto-detects type)
    Add {
        /// File to encrypt and store
        path: PathBuf,
        /// Override auto-detected type
        #[arg(long, short, value_enum)]
        r#type: Option<ItemType>,
    },
    /// List all vault items
    List,
    /// Decrypt and retrieve a vault item
    Get {
        /// Item ID
        id: String,
        /// Write to file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Remove an item from the vault
    Rm {
        /// Item ID to remove
        id: String,
    },
    /// Encrypt an entire folder
    Encrypt {
        /// Folder path
        path: PathBuf,
        /// Exclude glob patterns
        #[arg(long, short)]
        exclude: Vec<String>,
    },
    /// Decrypt a folder from the vault
    Decrypt {
        /// Folder item ID
        id: String,
        /// Output directory
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Protect a system file (encrypt + vault + optional immutable lock)
    Protect {
        /// System file to protect
        path: PathBuf,
        /// Also set kernel immutable flag (requires root)
        #[arg(long)]
        lock: bool,
    },
    /// Restore a system file from vault to original location
    Restore {
        /// Item ID
        id: String,
    },
    /// Set kernel immutable flag on a file (chattr +i, requires root)
    Lock {
        /// File to make immutable
        path: PathBuf,
    },
    /// Remove kernel immutable flag (chattr -i, requires root)
    Unlock {
        /// File to make mutable
        path: PathBuf,
    },
    /// Full system security scan (SUID, SGID, caps, permissions, secrets)
    Scan,
    /// Create integrity baseline of all system credential files
    Baseline,
    /// Verify system files against integrity baseline
    Verify,
    /// Start background tamper monitor (with desktop notifications)
    Watch {
        /// Poll interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
    },
    /// Generate a professional security report
    Report,
    /// Change master password (re-encrypts everything)
    Rekey,
    /// Show vault and system status
    Status,
    /// Launch interactive TUI dashboard
    Tui,
}

#[derive(Clone, ValueEnum)]
pub enum ItemType {
    Ssh,
    Shadow,
    Custom,
}

fn banner() {
    println!(
        "{}",
        r#"
  ██████╗ ██╗   ██╗██████╗
  ██╔══██╗╚██╗ ██╔╝██╔══██╗
  ██████╔╝ ╚████╔╝ ██████╔╝
  ██╔══██╗  ╚██╔╝  ██╔═══╝
  ██║  ██║   ██║   ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝
"#
        .bright_cyan()
    );
}

fn pw(prompt: &str) -> Result<String> {
    Ok(Password::new().with_prompt(prompt).interact()?)
}

fn pw_confirm(prompt: &str) -> Result<String> {
    Ok(Password::new()
        .with_prompt(prompt)
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?)
}

/// Auto-detect vault item type from file path
fn auto_type(path: &std::path::Path) -> vault::VaultItemType {
    let s = path.to_string_lossy();
    if s.contains("shadow") || s.contains("passwd") || s.contains("gshadow") {
        vault::VaultItemType::SystemShadow
    } else if s.contains("ssh_host") {
        vault::VaultItemType::SystemSsh
    } else if s.contains(".ssh/")
        || s.contains("id_rsa")
        || s.contains("id_ed25519")
        || s.contains("id_ecdsa")
    {
        vault::VaultItemType::Ssh
    } else if s.contains("ssl") || s.contains("cert") || s.contains("pki") {
        vault::VaultItemType::SystemCert
    } else if s.contains("/etc/") {
        vault::VaultItemType::SystemConfig
    } else {
        vault::VaultItemType::Custom
    }
}

pub fn dispatch(cli: Cli) -> Result<()> {
    // CODE RED: Verify binary integrity before any vault operation
    if !matches!(cli.command, Commands::Init) && vault::is_initialized() {
        system_guard::code_red_self_check()?;
    }

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Shield => cmd_shield(),
        Commands::Add { path, r#type } => cmd_add(path, r#type),
        Commands::List => cmd_list(),
        Commands::Get { id, output } => cmd_get(id, output),
        Commands::Rm { id } => cmd_rm(id),
        Commands::Encrypt { path, exclude } => cmd_encrypt(path, exclude),
        Commands::Decrypt { id, output } => cmd_decrypt(id, output),
        Commands::Protect { path, lock } => cmd_protect(path, lock),
        Commands::Restore { id } => cmd_restore(id),
        Commands::Lock { path } => cmd_lock(path),
        Commands::Unlock { path } => cmd_unlock(path),
        Commands::Scan => cmd_scan(),
        Commands::Baseline => cmd_baseline(),
        Commands::Verify => cmd_verify(),
        Commands::Watch { interval } => cmd_watch(interval),
        Commands::Report => cmd_report(),
        Commands::Rekey => cmd_rekey(),
        Commands::Status => cmd_status(),
        Commands::Tui => tui_app::run(),
    }
}

// ---------- Core vault commands ----------

fn cmd_init() -> Result<()> {
    banner();
    println!("{}", "[*] Initializing vault...".bright_yellow());
    if vault::is_initialized() {
        println!("{}", "[!] Vault already exists at ~/.rypton".bright_red());
        return Ok(());
    }
    let password = pw_confirm("Set master password")?;
    if let Err(issues) = crypto::validate_password_strength(&password) {
        println!("{}", "[!] Weak password:".bright_red());
        for i in &issues {
            println!("    {} {}", "-".bright_red(), i);
        }
        if !Confirm::new()
            .with_prompt("Continue anyway?")
            .default(false)
            .interact()?
        {
            return Ok(());
        }
    }
    vault::init_vault(&password)?;
    println!("{}", "[+] Vault initialized at ~/.rypton".bright_green());

    // Ask to auto-shield
    if Confirm::new()
        .with_prompt("Do you want to automatically find and protect standard system credentials & secrets? (ryp shield)")
        .default(true)
        .interact()?
    {
        cmd_shield()?;
    }

    Ok(())
}

fn cmd_shield() -> Result<()> {
    banner();
    println!("{}", "[*] Engaging Rypton Auto-Shield...".bright_yellow());

    let master = vault::unlock_vault(&pw("Master password")?)?;
    let mut protected_count = 0;

    // 1. Protect core system files (if root)
    if system_guard::is_root() {
        println!(
            "{}",
            "    Shielding kernel-level system credentials...".bright_cyan()
        );
        let creds = system_guard::system_credential_registry();
        for cred in creds {
            let p = std::path::PathBuf::from(&cred.path);
            if p.exists() {
                match system_guard::protect_file(&master, &p, true) {
                    Ok(_) => {
                        println!(
                            "    {} Locked & Vaulted: {}",
                            "[+]".bright_green(),
                            cred.path
                        );
                        protected_count += 1;
                    }
                    Err(e) => println!(
                        "    {} Failed to protect {}: {}",
                        "[-]".bright_red(),
                        cred.path,
                        e
                    ),
                }
            }
        }
    } else {
        println!(
            "{}",
            "    [i] Not running as root. Skipping /etc/ system credential lockdown..."
                .bright_yellow()
        );
    }

    // 2. Vault user secrets (SSH keys, AWS, etc)
    println!(
        "{}",
        "    Scanning home directory for common unencrypted secrets...".bright_cyan()
    );
    if let Some(home) = dirs::home_dir() {
        let targets = [
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_ecdsa",
            ".aws/credentials",
            ".kube/config",
            ".docker/config.json",
            ".netrc",
            ".pgpass",
            ".vault-token",
            ".env",
        ];

        for t in targets {
            let p = home.join(t);
            if p.exists() {
                let vtype = auto_type(&p);
                match vault::add_file(&master, &p, vtype) {
                    Ok(_) => {
                        println!("    {} Backed up to Vault: {}", "[+]".bright_green(), t);
                        protected_count += 1;
                    }
                    Err(e) => println!("    {} Failed to vault {}: {}", "[-]".bright_red(), t, e),
                }
            }
        }
    }

    if protected_count > 0 {
        println!(
            "\n{}",
            format!(
                "[*] Shield complete! Successfully protected {} items.",
                protected_count
            )
            .bright_green()
            .bold()
        );
        println!(
            "    {} We recommend running `sudo ryp baseline` next.",
            "[i]".bright_cyan()
        );
    } else {
        println!(
            "\n{}",
            "[!] Shield complete. No default standard secrets found or accessible.".bright_yellow()
        );
    }

    Ok(())
}

fn cmd_add(path: PathBuf, override_type: Option<ItemType>) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    let vtype = match override_type {
        Some(ItemType::Ssh) => vault::VaultItemType::Ssh,
        Some(ItemType::Shadow) => vault::VaultItemType::Shadow,
        Some(ItemType::Custom) => vault::VaultItemType::Custom,
        None => auto_type(&path),
    };
    println!(
        "{} {} [{}]",
        "[*] Encrypting".bright_yellow(),
        path.display().to_string().bright_white(),
        vtype.to_string().bright_cyan()
    );
    let item = vault::add_file(&master, &path, vtype)?;
    println!(
        "{} ID: {}",
        "[+] Stored!".bright_green(),
        item.id.bright_cyan()
    );
    println!("    BLAKE3: {}", item.blake3_hash.dimmed());
    Ok(())
}

fn cmd_list() -> Result<()> {
    if !vault::is_initialized() {
        println!("{}", "[!] No vault. Run 'ryp init' first.".bright_red());
        return Ok(());
    }
    let items = vault::list_items()?;
    if items.is_empty() {
        println!(
            "{}",
            "[*] Vault empty. Run 'ryp add <path>' to add files.".yellow()
        );
        return Ok(());
    }
    println!("\n  {}", "RYPTON VAULT".bright_cyan().bold());
    println!("  {}\n", "============".bright_cyan());
    println!(
        "  {:<38} {:<12} {:<28} {:>10}",
        "ID".bright_white().bold(),
        "TYPE".bright_white().bold(),
        "NAME".bright_white().bold(),
        "SIZE".bright_white().bold()
    );
    println!("  {}", "-".repeat(90).dimmed());
    for item in &items {
        let tc = match item.item_type {
            vault::VaultItemType::Ssh => item.item_type.to_string().bright_red(),
            vault::VaultItemType::Shadow => item.item_type.to_string().bright_magenta(),
            vault::VaultItemType::Custom => item.item_type.to_string().bright_blue(),
            vault::VaultItemType::Folder => item.item_type.to_string().bright_yellow(),
            vault::VaultItemType::SystemSsh => item.item_type.to_string().bright_red().bold(),
            vault::VaultItemType::SystemShadow => {
                item.item_type.to_string().bright_magenta().bold()
            }
            vault::VaultItemType::SystemCert => item.item_type.to_string().bright_green().bold(),
            vault::VaultItemType::SystemConfig => item.item_type.to_string().bright_cyan().bold(),
        };
        let sz = if item.size_bytes > 1_048_576 {
            format!("{:.1} MB", item.size_bytes as f64 / 1_048_576.0)
        } else if item.size_bytes > 1024 {
            format!("{:.1} KB", item.size_bytes as f64 / 1024.0)
        } else {
            format!("{} B", item.size_bytes)
        };
        let sid = if item.id.len() > 36 {
            &item.id[..36]
        } else {
            &item.id
        };
        println!(
            "  {:<38} {:<12} {:<28} {:>10}",
            sid.bright_cyan(),
            tc,
            item.name.bright_white(),
            sz.dimmed()
        );
    }
    println!(
        "\n  {} items total\n",
        items.len().to_string().bright_green()
    );
    Ok(())
}

fn cmd_get(id: String, output: Option<PathBuf>) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    let item = vault::get_item(&id)?;
    println!(
        "{} {}",
        "[*] Decrypting".bright_yellow(),
        item.name.bright_white()
    );
    let pt = vault::decrypt_item(&master, &id)?;
    let hash = crypto::blake3_hash(&pt);
    if hash != item.blake3_hash {
        println!("{}", "[!] INTEGRITY FAILED!".bright_red().bold());
    } else {
        println!("{}", "[+] Integrity verified (BLAKE3)".bright_green());
    }
    match output {
        Some(p) => {
            std::fs::write(&p, &pt)?;
            println!("{} {}", "[+] Written to".bright_green(), p.display());
        }
        None => {
            use std::io::Write;
            std::io::stdout().write_all(&pt)?;
            println!();
        }
    }
    Ok(())
}

fn cmd_rm(id: String) -> Result<()> {
    let item = vault::get_item(&id)?;
    if !Confirm::new()
        .with_prompt(format!("Remove '{}' ({})?", item.name, item.item_type))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    if item.item_type == vault::VaultItemType::Folder {
        for cid in &item.children {
            vault::remove_item(cid)?;
        }
    }
    vault::remove_item(&id)?;
    println!("{} {}", "[+] Removed".bright_green(), item.name);
    Ok(())
}

fn cmd_encrypt(path: PathBuf, exclude: Vec<String>) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    println!(
        "{} {}",
        "[*] Encrypting folder".bright_yellow(),
        path.display().to_string().bright_white()
    );
    let item = vault::add_folder(&master, &path, &exclude)?;
    println!(
        "{} ID: {} ({} files)",
        "[+] Done!".bright_green(),
        item.id.bright_cyan(),
        item.children.len()
    );
    Ok(())
}

fn cmd_decrypt(id: String, output: PathBuf) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    println!(
        "{} -> {}",
        "[*] Decrypting folder".bright_yellow(),
        output.display().to_string().bright_white()
    );
    let count = vault::decrypt_folder(&master, &id, &output)?;
    println!("{} {} files restored", "[+] Done!".bright_green(), count);
    Ok(())
}

// ---------- System guard commands ----------

fn cmd_protect(path: PathBuf, lock: bool) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    println!(
        "{} {}",
        "[*] Protecting".bright_yellow(),
        path.display().to_string().bright_white()
    );
    let item = system_guard::protect_file(&master, &path, lock)?;
    println!(
        "{} ID: {} [{}]",
        "[+] Protected!".bright_green(),
        item.id.bright_cyan(),
        item.item_type.to_string().bright_yellow()
    );
    if lock {
        println!("  [+] Immutable flag set (chattr +i)");
    }
    Ok(())
}

fn cmd_restore(id: String) -> Result<()> {
    let master = vault::unlock_vault(&pw("Master password")?)?;
    let item = vault::get_item(&id)?;
    if !Confirm::new()
        .with_prompt(format!(
            "Restore '{}' to {}?",
            item.name, item.original_path
        ))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    system_guard::restore_file(&master, &id)?;
    println!("{}", "[+] Restored.".bright_green());
    Ok(())
}

fn cmd_lock(path: PathBuf) -> Result<()> {
    println!(
        "{} {}",
        "[*] Locking".bright_yellow(),
        path.display().to_string().bright_white()
    );
    system_guard::set_immutable(&path)?;
    println!(
        "{} {} is now immutable (chattr +i)",
        "[+]".bright_green(),
        path.display().to_string().bright_cyan()
    );
    Ok(())
}

fn cmd_unlock(path: PathBuf) -> Result<()> {
    if !Confirm::new()
        .with_prompt(format!("Unlock {}?", path.display()))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    system_guard::clear_immutable(&path)?;
    println!(
        "{} {} is now mutable",
        "[+]".bright_green(),
        path.display().to_string().bright_cyan()
    );
    Ok(())
}

fn cmd_baseline() -> Result<()> {
    println!(
        "{}",
        "\n  [*] Creating integrity baseline...".bright_yellow()
    );
    if !system_guard::is_root() {
        println!(
            "{}",
            "  [!] Running without root. Some files unreadable.".bright_yellow()
        );
    }
    let bl = system_guard::create_baseline()?;
    println!(
        "{} {} files baselined",
        "  [+] Done!".bright_green(),
        bl.entries.len().to_string().bright_cyan()
    );
    Ok(())
}

fn cmd_verify() -> Result<()> {
    println!("{}", "\n  [*] Verifying integrity...".bright_yellow());
    let violations = system_guard::verify_baseline()?;
    if violations.is_empty() {
        println!(
            "{}",
            "  [+] All clean. No tampering detected.".bright_green()
        );
    } else {
        println!(
            "\n  {} violations:\n",
            violations.len().to_string().bright_red().bold()
        );
        for (i, v) in violations.iter().enumerate() {
            println!(
                "  {}. [{}] {}",
                i + 1,
                v.violation_type.to_string().bright_red(),
                v.path.bright_white()
            );
            println!("     {}\n", v.detail.dimmed());
        }
        scanner::notify_desktop(
            "Rypton Alert",
            &format!("{} integrity violations detected!", violations.len()),
            "critical",
        );
    }
    Ok(())
}

fn cmd_watch(interval: u64) -> Result<()> {
    system_guard::watch_system_files(interval)
}

// ---------- Scanner + Report ----------

fn cmd_scan() -> Result<()> {
    let findings = scanner::full_scan()?;
    if !findings.is_empty() {
        println!("\n  {} Generating report...", "[*]".bright_yellow());
        let rp = report::generate_report(&findings)?;
        report::update_latest_link(&rp)?;
    }
    Ok(())
}

fn cmd_report() -> Result<()> {
    println!(
        "{}",
        "\n  [*] Running scan and generating report...".bright_yellow()
    );
    let findings = scanner::full_scan()?;
    let rp = report::generate_report(&findings)?;
    report::update_latest_link(&rp)?;
    println!(
        "\n  {} View: cat {}",
        "[+]".bright_green(),
        rp.display().to_string().bright_cyan()
    );
    Ok(())
}

// ---------- Key management ----------

fn cmd_rekey() -> Result<()> {
    banner();
    println!("{}", "[*] Re-keying vault...".bright_yellow());
    let old = pw("Current master password")?;
    let new = pw_confirm("New master password")?;
    if let Err(issues) = crypto::validate_password_strength(&new) {
        println!("{}", "[!] Weak password:".bright_red());
        for i in &issues {
            println!("    {} {}", "-".bright_red(), i);
        }
        if !Confirm::new()
            .with_prompt("Continue?")
            .default(false)
            .interact()?
        {
            return Ok(());
        }
    }
    let count = vault::rekey_vault(&old, &new)?;
    println!(
        "{} {} items re-encrypted",
        "[+] Done!".bright_green(),
        count
    );
    Ok(())
}

// ---------- Status ----------

fn cmd_status() -> Result<()> {
    banner();
    if !vault::is_initialized() {
        println!("{}", "[!] No vault. Run 'ryp init'.".bright_red());
        return Ok(());
    }
    let items = vault::list_items()?;
    let root = vault::vault_root();

    println!("  {}", "VAULT STATUS".bright_cyan().bold());
    println!("  {}\n", "============".bright_cyan());
    println!(
        "  Location:    {}",
        root.display().to_string().bright_white()
    );
    println!("  Items:       {}", items.len().to_string().bright_green());
    println!(
        "  Privileged:  {}",
        if system_guard::is_root() {
            "yes (root)".bright_green().to_string()
        } else {
            "no (user)".bright_yellow().to_string()
        }
    );

    let mut counts = [0u32; 8];
    for i in &items {
        match i.item_type {
            vault::VaultItemType::Ssh => counts[0] += 1,
            vault::VaultItemType::Shadow => counts[1] += 1,
            vault::VaultItemType::Custom => counts[2] += 1,
            vault::VaultItemType::Folder => counts[3] += 1,
            vault::VaultItemType::SystemSsh => counts[4] += 1,
            vault::VaultItemType::SystemShadow => counts[5] += 1,
            vault::VaultItemType::SystemCert => counts[6] += 1,
            vault::VaultItemType::SystemConfig => counts[7] += 1,
        }
    }

    println!("\n  {}", "User-level:".bright_white().bold());
    println!("    SSH keys:    {}", counts[0].to_string().bright_red());
    println!(
        "    Shadows:     {}",
        counts[1].to_string().bright_magenta()
    );
    println!("    Custom:      {}", counts[2].to_string().bright_blue());
    println!("    Folders:     {}", counts[3].to_string().bright_yellow());
    println!("  {}", "System-level:".bright_white().bold());
    println!("    SSH host:    {}", counts[4].to_string().bright_red());
    println!(
        "    Shadow DB:   {}",
        counts[5].to_string().bright_magenta()
    );
    println!("    TLS certs:   {}", counts[6].to_string().bright_green());
    println!("    Sys configs: {}", counts[7].to_string().bright_cyan());

    println!("\n  {}", "Encryption:".bright_white().bold());
    println!(
        "    Cipher:      {}",
        "XChaCha20-Poly1305 (AEAD)".bright_green()
    );
    println!(
        "    KDF:         {}",
        "Argon2id (64MiB/3iter/4p)".bright_green()
    );
    println!("    Per-file:    {}", "HKDF-SHA256".bright_green());
    println!("    Integrity:   {}", "BLAKE3".bright_green());
    println!("    Memory:      {}", "zeroize on drop".bright_green());
    println!("    Tamper:      {}", "chattr +i (kernel)".bright_green());

    let bl = vault::vault_root()
        .join("baselines")
        .join("system_baseline.json")
        .exists();
    println!("\n  {}", "System Guard:".bright_white().bold());
    println!(
        "    Baseline:    {}",
        if bl {
            "present".bright_green().to_string()
        } else {
            "run 'ryp baseline'".bright_yellow().to_string()
        }
    );

    let reports = vault::vault_root()
        .join("reports")
        .join("latest.md")
        .exists();
    println!(
        "    Report:      {}",
        if reports {
            "present".bright_green().to_string()
        } else {
            "run 'ryp report'".bright_yellow().to_string()
        }
    );
    println!();
    Ok(())
}
