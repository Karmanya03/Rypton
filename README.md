<p align="center">
	<img src="assets/Rypton-Logo.png" alt="Rypton logo" width="240" />
</p>

<h1 align="center">Rypton</h1>

<p align="center">
	<strong>Kernel-level, tamper-proof secrets vault and system credential guardian for Linux.</strong><br />
	Three letters. One command. Your system's credentials locked down with kernel-grade immutable flags, BLAKE3 integrity monitoring, and real-time tamper detection -because <code>/etc/shadow</code> in plaintext is not a configuration choice, it's a liability.
</p>

<p align="center">
	<img src="https://img.shields.io/badge/binary-ryp-0f172a?style=flat-square&labelColor=0f172a&color=dc2626" alt="binary ryp" />
	<img src="https://img.shields.io/badge/release-v0.3.0-0f172a?style=flat-square&labelColor=0f172a&color=dc2626" alt="release v0.3.0" />
	<img src="https://img.shields.io/badge/license-MIT-0f172a?style=flat-square&labelColor=0f172a&color=22c55e" alt="license MIT" />
	<img src="https://img.shields.io/badge/written%20in-Rust-0f172a?style=flat-square&labelColor=0f172a&color=f97316" alt="written in Rust" />
	<img src="https://img.shields.io/badge/platform-Linux-0f172a?style=flat-square&labelColor=0f172a&color=38bdf8" alt="platform Linux" />
</p>

<p align="center">
	<img src="https://img.shields.io/badge/encryption-XChaCha20--Poly1305-0f172a?style=flat-square&labelColor=0f172a&color=a855f7" alt="encryption XChaCha20-Poly1305" />
	<img src="https://img.shields.io/badge/KDF-Argon2id-0f172a?style=flat-square&labelColor=0f172a&color=ec4899" alt="KDF Argon2id" />
	<img src="https://img.shields.io/badge/integrity-BLAKE3-0f172a?style=flat-square&labelColor=0f172a&color=f59e0b" alt="integrity BLAKE3" />
	<img src="https://img.shields.io/badge/tamper--proof-chattr%20%2Bi-0f172a?style=flat-square&labelColor=0f172a&color=ef4444" alt="tamper-proof chattr +i" />
</p>

<p align="center">
	<img src="https://img.shields.io/badge/scanner-SUID%20%7C%20SGID%20%7C%20Caps%20%7C%20World--Write-0f172a?style=flat-square&labelColor=0f172a&color=22c55e" alt="scanner" />
	<img src="https://img.shields.io/badge/alerts-desktop%20notifications-0f172a?style=flat-square&labelColor=0f172a&color=38bdf8" alt="desktop notifications" />
	<img src="https://img.shields.io/badge/reports-auto%20generated-0f172a?style=flat-square&labelColor=0f172a&color=a855f7" alt="auto reports" />
	<img src="https://img.shields.io/badge/cloud-absolutely%20not-0f172a?style=flat-square&labelColor=0f172a&color=ef4444" alt="cloud absolutely not" />
</p>

---

## What Is This

**Rypton** (`ryp`) is a kernel-level, tamper-proof secrets vault, system-wide security scanner, and credential guardian for Linux workstations.

It doesn't just encrypt files -it uses Linux kernel primitives (`chattr +i` immutable flags), BLAKE3 integrity baselines, and real-time polling to make system credentials tamper-proof. It scans your entire system for SUID/SGID binaries, Linux capabilities, world-writable files, and unencrypted secrets, then generates professional reports with risk grades and remediation steps. Critical findings trigger desktop notifications instantly.

Every command is a single English word. The binary is three letters: `ryp`.

### What it protects

| Category           | Files                                        | How                                 |
| ------------------ | -------------------------------------------- | ----------------------------------- |
| **System auth**    | `/etc/shadow`, `/etc/passwd`, `/etc/gshadow` | Encrypt + vault + immutable lock    |
| **SSH host keys**  | `/etc/ssh/ssh_host_*`                        | Integrity baseline + immutable flag |
| **Sudoers**        | `/etc/sudoers`, `/etc/sudoers.d/*`           | Kernel-enforced immutability        |
| **TLS keys**       | `/etc/ssl/private/*`                         | Encrypted backup + lock             |
| **PAM configs**    | `/etc/pam.d/*`                               | Baseline + tamper detection         |
| **User SSH keys**  | `~/.ssh/id_*`                                | Encrypted vault storage             |
| **Config files**   | `~/.config/*`, `~/.env`, `~/.aws/*`          | Encrypted vault storage             |
| **Entire folders** | Any directory tree                           | Recursive encryption                |

### What it scans for

| Scanner                 | Detects                                                       |
| ----------------------- | ------------------------------------------------------------- |
| **SUID/SGID**           | Unknown setuid/setgid binaries (privilege escalation vectors) |
| **Capabilities**        | `cap_setuid`, `cap_sys_admin`, `cap_dac_override`, etc.       |
| **World-writable**      | Files any user can modify in sensitive locations              |
| **Sticky bit**          | World-writable dirs missing sticky bit                        |
| **Weak permissions**    | System credentials with overly permissive modes               |
| **Unencrypted secrets** | SSH keys, AWS creds, kube configs, .env files, API tokens     |
| **Unowned files**       | Orphaned files with no valid UID/GID                          |

## Installation

```bash
# Automated (recommended)
curl -sSL https://raw.githubusercontent.com/Karmanya03/rypton/master/scripts/install.sh | bash

# From source
git clone https://github.com/Karmanya03/rypton.git && cd rypton
cargo install --locked --path .

# Update / Uninstall
curl -sSL https://raw.githubusercontent.com/Karmanya03/rypton/master/scripts/update.sh | bash
curl -sSL https://raw.githubusercontent.com/Karmanya03/rypton/master/scripts/uninstall.sh | bash
```

## Quick Start

```bash
ryp init                              # Create your vault
ryp add ~/.ssh/id_ed25519             # Vault your SSH key (auto-detects type)
ryp add ~/.config/app/api_token       # Vault a config file
ryp encrypt ~/lab/ctf                 # Encrypt entire folder
ryp list                              # See what's in the vault
ryp get <id> -o ~/restored_key        # Decrypt a file

sudo ryp scan                         # Full 6-phase system scan + report
sudo ryp baseline                     # Create integrity baseline
sudo ryp verify                       # Check for tampering
sudo ryp protect /etc/shadow --lock   # Encrypt + immutable flag
sudo ryp lock /etc/ssh/sshd_config    # Kernel-lock a file
sudo ryp watch                        # Real-time tamper monitor
ryp report                            # Generate security report
ryp status                            # Dashboard
ryp tui                               # Interactive TUI
```

## Command Reference

Every command is a single word. No subcommands. No flags to memorize.

| Command                       | What It Does                                             |
| ----------------------------- | -------------------------------------------------------- |
| `ryp init`                    | Initialize vault                                         |
| `ryp add <path>`              | Encrypt and store a file (auto-detects type)             |
| `ryp list`                    | List all vault items                                     |
| `ryp get <id> [-o path]`      | Decrypt and retrieve                                     |
| `ryp rm <id>`                 | Remove from vault                                        |
| `ryp encrypt <folder>`        | Encrypt entire directory                                 |
| `ryp decrypt <id> -o <dir>`   | Restore encrypted folder                                 |
| `ryp lock <path>`             | Set kernel immutable flag (`chattr +i`)                  |
| `ryp unlock <path>`           | Remove kernel immutable flag                             |
| `ryp protect <path> [--lock]` | Encrypt + vault + optional lock                          |
| `ryp restore <id>`            | Restore system file from vault                           |
| `ryp scan`                    | Full system security scan (SUID/SGID/caps/perms/secrets) |
| `ryp baseline`                | Create BLAKE3 integrity baseline                         |
| `ryp verify`                  | Verify against baseline                                  |
| `ryp watch [--interval N]`    | Real-time tamper monitor with desktop notifications      |
| `ryp report`                  | Generate professional security report                    |
| `ryp rekey`                   | Change master password                                   |
| `ryp status`                  | Vault + system health dashboard                          |
| `ryp tui`                     | Interactive TUI                                          |

## System Scanner

The scanner performs a 6-phase system-wide security audit:

1. **SUID/SGID binaries** -Walks `/usr`, `/bin`, `/sbin`, `/opt`, etc. Flags unknown SUID/SGID binaries while whitelisting known system tools.
2. **Linux capabilities** -Runs `getcap` across binary directories. Flags dangerous capabilities like `cap_setuid`, `cap_sys_admin`.
3. **World-writable files** -Detects writable files in sensitive locations and directories missing sticky bits.
4. **System credential permissions** -Audits 20+ system files against expected permission masks.
5. **Unencrypted secrets** -Scans for SSH keys, AWS creds, kube configs, vault tokens, `.env` files.
6. **Unowned files** -Finds orphaned files with no valid UID/GID.

### Desktop Notifications

Critical and high-risk findings trigger `notify-send` desktop alerts automatically. No configuration needed -if your desktop supports FreeDesktop notifications, you'll see them.

### Reports

Every scan generates a timestamped Markdown report in `~/.rypton/reports/` with:

- **Risk grade** (A+ through F) and numeric score
- **Executive summary** with finding counts by severity
- **Attack vector analysis** -what could be targeted
- **Protection matrix** -what Rypton can/cannot fix
- **Impact assessment** -what exploitation could cause
- **Detailed findings** by category with per-item risk levels
- **Remediation commands** -copy-paste `ryp` commands

Reports auto-accumulate. The latest is always at `~/.rypton/reports/latest.md`.

## Architecture

### Key Hierarchy

```
User Password
    ▼ Argon2id (64 MiB, 3 iter, 4 threads)
Master Key (32 bytes)
    ▼ HKDF-SHA256 (per-file salt + UUID label)
Per-File Key (32 bytes)
    ▼ XChaCha20-Poly1305 (24-byte random nonce)
Encrypted Blob
```

### Vault Layout

```
~/.rypton/
├── config.json
├── baselines/system_baseline.json
├── reports/
│   ├── rypton_report_2026-04-30_10-00-00.md
│   └── latest.md
├── vault/*.blob, *.salt
├── index/*.json
└── keys/master.key
```

## Security Model

| Layer          | Primitive                            |
| -------------- | ------------------------------------ |
| Password → Key | Argon2id (64 MiB, 3 iter, 4 threads) |
| Key Derivation | HKDF-SHA256 per-file                 |
| Encryption     | XChaCha20-Poly1305 AEAD              |
| Integrity      | BLAKE3 pre-encryption + baseline     |
| Memory         | zeroize on drop                      |
| Tamper-proof   | `chattr +i` kernel immutable flag    |
| Detection      | Real-time polling + desktop alerts   |
| Scanning       | SUID/SGID/caps/world-write/secrets   |

## FAQ

**Q: What makes this "kernel-level"?**
A: The `chattr +i` immutable flag is enforced by the Linux kernel's VFS layer. Once set, the file cannot be modified, deleted, or renamed by any process -including root. Combined with BLAKE3 baselines and real-time polling, this is defense-in-depth from the kernel up. Basically, we tell the kernel to treat your files like a toddler treats their favorite toy: "MINE. NO TOUCH."

**Q: Will the scanner slow down my system?**
A: No. The scanner uses metadata-only checks (no file content reading for SUID/SGID/permissions), limits walk depth, and skips virtual filesystems (`/proc`, `/sys`, `/dev`). Typical scan completes faster than you can say "Wait, did I leave port 22 open to the entire internet?"

**Q: What about the background monitor?**
A: `ryp watch` polls at configurable intervals (default 5s), only hashing files that are in your baseline. CPU usage is negligible. It's like having a highly caffeinated, very stealthy ninja watching your back 24/7.

**Q: What happens if I forget my password?**
A: Your data becomes very expensive random bytes. There is no backdoor. There is no recovery email. There is only the void. We hope you have a good memory or a sturdy piece of paper hidden under your mattress.

**Q: Wait, CODE RED? What's that?**
A: Rypton is paranoid. On every run, it hashes itself. If it detects that some sneaky malware (or you, messing around) modified the `ryp` binary, it throws a digital tantrum, halts execution, screams "CODE RED" via desktop notification, and refuses to touch your vault. Self-preservation level 9000. 

**Q: Is it "Rypton" or "ryp"?**
A: "Rypton" is the project name. `ryp` is the command because we respect your time and your keyboard's lifespan. Three letters. One syllable. Go wild.

**Q: Can it protect me if someone physically steals my laptop?**
A: If they physically steal your laptop, you have bigger problems. But if you have full-disk encryption (LUKS) AND Rypton, they might as well use your laptop as a very expensive paperweight.

**Q: I ran `sudo ryp lock /etc/shadow` and now I can't change my password! Is it broken?**
A: No, my friend, it is working exactly as intended. You literally locked the file with kernel-level immutability. To change your password, run `sudo ryp unlock /etc/shadow`, change it, and then lock it again. 

---

<p align="center">
  Because sleeping soundly requires assuming the entire internet is actively trying to ruin your life. <br />
  <i>Stay paranoid, my friends.</i>
</p>
