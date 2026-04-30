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
echo "  [*] Updating Rypton (ryp)..."
echo ""

if ! command -v ryp &> /dev/null; then
    echo "  [!] Rypton (ryp) is not installed."
    echo "  [!] Please run the installation script first."
    exit 1
fi

cargo install --locked --git https://github.com/Karmanya03/Rypton.git --force

if [ -d "/usr/local/bin" ]; then
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/ryp
    sudo ln -sf "$HOME/.cargo/bin/ryp" /usr/local/bin/rypton
fi

echo ""
echo "  [+] Rypton updated to latest version successfully."
echo "  [+] Your vault data in ~/.rypton is completely untouched."
echo ""
