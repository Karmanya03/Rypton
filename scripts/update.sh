#!/usr/bin/env bash
set -e

echo ""
echo "  [*] Updating Rypton (ryp)..."

# Re-install latest from git (overwrites old binary)
cargo install --locked --git https://github.com/Karmanya03/Rypton.git --force

# Re-link if /usr/local/bin exists
if [ -d "/usr/local/bin" ]; then
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/ryp
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/rypton
fi

echo ""
echo "  [+] Rypton updated to latest version."
echo "  [+] Your vault data in ~/.rypton is untouched."
echo ""
