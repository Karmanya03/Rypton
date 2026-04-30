#!/usr/bin/env bash
set -e

echo ""
echo "  ██████╗ ██╗   ██╗██████╗"
echo "  ██╔══██╗╚██╗ ██╔╝██╔══██╗"
echo "  ██████╔╝ ╚████╔╝ ██████╔╝"
echo "  ██╔══██╗  ╚██╔╝  ██╔═══╝"
echo "  ██║  ██║   ██║   ██║"
echo "  ╚═╝  ╚═╝   ╚═╝   ╚═╝"
echo ""
echo "  [*] Installing Rypton (ryp) via Cargo..."
echo ""

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
