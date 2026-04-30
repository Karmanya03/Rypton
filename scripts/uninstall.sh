#!/usr/bin/env bash
set -e

echo ""
echo "  [*] Uninstalling Rypton (ryp)..."

# Remove binary
if command -v cargo &> /dev/null; then
    cargo uninstall rypton 2>/dev/null || true
fi

# Remove system-wide symlinks
if [ -L "/usr/local/bin/ryp" ]; then
    echo "  [+] Removing system-wide symlinks..."
    sudo rm -f /usr/local/bin/ryp
fi
if [ -L "/usr/local/bin/rypton" ]; then
    sudo rm -f /usr/local/bin/rypton
fi

# Remove cargo bin copy
rm -f "$HOME/.cargo/bin/ryp"
rm -f "$HOME/.cargo/bin/rypton"

echo ""
echo "  [+] Rypton binary removed."
echo ""
echo "  [!] Your vault data at ~/.rypton has NOT been removed."
echo "      To permanently delete your encrypted vault, run:"
echo "      rm -rf ~/.rypton"
echo ""
