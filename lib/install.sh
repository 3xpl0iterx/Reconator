#!/usr/bin/env bash
install_dependencies() {
    heading 'Reconator Dependency Installer'
    command -v python3 >/dev/null 2>&1 || { echo '[-] Install Python 3 first.'; return 1; }
    python3 "$RECONATOR_HOME/setup/install.py" --plan || return 1
    echo '[!] Setup builds pinned tools and installs isolated Python dependencies.'
    echo '[!] The detected package manager installs OS dependencies using sudo.'
    echo '[!] Python 3.12 must already be available for the legacy providers.'
    local confirm
    read -r -p '[?] Install dependencies? [y/N]: ' confirm || return 1
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo '[*] Installation cancelled.'; return 0; }
    python3 "$RECONATOR_HOME/setup/install.py" --system
}
