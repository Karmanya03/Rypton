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
echo "  [*] Uninstalling Rypton (ryp)..."
echo ""

if ! command -v ryp &> /dev/null && [ ! -f "$HOME/.cargo/bin/ryp" ]; then
    echo "  [!] Rypton is not installed. Nothing to uninstall."
    exit 0
fi

if command -v cargo &> /dev/null; then
    cargo uninstall rypton || true
fi

rm -f "$HOME/.cargo/bin/ryp"

if [ -d "/usr/local/bin" ]; then
    sudo rm -f /usr/local/bin/ryp
    sudo rm -f /usr/local/bin/rypton
fi

echo "      To permanently delete your encrypted vault, run:"
echo "      rm -rf ~/.rypton"
echo ""
