#!/usr/bin/env bash
set -e

echo ""
echo -e "\e[1;32m ██████  ██    ██ ██████ \e[0m"
echo -e "\e[1;32m ██   ██  ██  ██  ██   ██\e[0m"
echo -e "\e[1;32m ██████    ████   ██████ \e[0m"
echo -e "\e[1;32m ██   ██    ██    ██     \e[0m"
echo -e "\e[1;32m ██   ██    ██    ██     \e[0m"
echo -e "\e[1;30;42m [ KERNEL-GRADE IMMUTABLE SECRETS VAULT ] \e[0m"
echo -e "\e[1;36m──────────────────────────────────────────\e[0m"
echo ""
echo "  [*] Installing Rypton (ryp) via Cargo..."
echo ""

if command -v ryp &> /dev/null; then
    echo "  [!] Rypton (ryp) is already installed."
    echo "  [!] Use 'ryp --version' to check the version."
    echo "  [!] If you want to update, run the update script instead."
    exit 0
fi

# Check for Rust/Cargo
if ! command -v cargo &> /dev/null; then
    echo "  [!] Cargo not found. Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install from git
cargo install --locked --git https://github.com/Karmanya03/Rypton.git

# Create system-wide symlinks (both ryp and rypton for backward compat)
if [ -d "/usr/local/bin" ]; then
    echo "  [+] Creating system-wide symlinks (may prompt for sudo)..."
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/ryp
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/rypton
else
    echo "  [!] /usr/local/bin not found. Skipping system-wide symlink."
    echo "      Make sure ~/.cargo/bin is in your PATH."
fi

echo ""
echo "  [+] Rypton installed successfully."
echo "  [+] Run 'ryp --help' to get started."
echo "  [+] Run 'ryp init' to create your vault."
echo ""
