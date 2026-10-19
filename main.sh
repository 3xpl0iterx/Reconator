#!/usr/bin/env bash
# Reconator — created by 3xpl0iter
# shellcheck source-path=SCRIPTDIR
if [ -z "${BASH_VERSION:-}" ]; then
    echo 'Reconator requires Bash. Run: bash main.sh' >&2
    exit 2
fi
if (( BASH_VERSINFO[0] < 5 )); then
    echo 'Reconator requires Bash 5 or newer.' >&2
    exit 2
fi
VERSION='1.0.0-rc.2'
RECONATOR_SOURCE="$(readlink -f -- "${BASH_SOURCE[0]}")" || exit 1
RECONATOR_HOME="$(cd -- "$(dirname -- "$RECONATOR_SOURCE")" && pwd)" || exit 1
RECONATOR_TOOL_BIN="${RECONATOR_TOOL_BIN-$RECONATOR_HOME/tools/bin}"
if [[ -d "$RECONATOR_TOOL_BIN" ]]; then export PATH="$RECONATOR_TOOL_BIN:$PATH"; fi
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; WHITE='\033[0;37m'; BOLD='\033[1m'; RESET='\033[0m'
# Respect non-interactive output and NO_COLOR.
if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; WHITE=''; BOLD=''; RESET=''
fi
wordlist="${wordlist:-${RECONATOR_WORDLIST:-/usr/share/wordlists/dirb/big.txt}}"
# shellcheck source=lib/runtime.sh
source "$RECONATOR_HOME/lib/runtime.sh" || exit 1
# shellcheck source=lib/ui.sh
source "$RECONATOR_HOME/lib/ui.sh" || exit 1
# shellcheck source=lib/validation.sh
source "$RECONATOR_HOME/lib/validation.sh" || exit 1
# shellcheck source=lib/providers.sh
source "$RECONATOR_HOME/lib/providers.sh" || exit 1
# shellcheck source=lib/recon.sh
source "$RECONATOR_HOME/lib/recon.sh" || exit 1
# shellcheck source=lib/cli.sh
source "$RECONATOR_HOME/lib/cli.sh" || exit 1
# shellcheck source=lib/menu.sh
source "$RECONATOR_HOME/lib/menu.sh" || exit 1
# shellcheck source=lib/install.sh
source "$RECONATOR_HOME/lib/install.sh" || exit 1
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi
reconator_install_signal_handler
if (( $# )); then
    if [[ "$1" == --install ]]; then install_dependencies; result=$?;
    else reconator_cli "$@"; result=$?; fi
    if [[ "${RECONATOR_EXIT_ARMED:-false}" == true ]]; then
        read -r -p '[?] Press Enter to finish, or Ctrl+C again to close...'
    fi
    exit "$result"
fi
while true; do
    [[ -t 1 ]] && clear
    banner; menu
    read -r -p '[?] Select an option: ' option || break
    [[ "$option" == 0 || "$option" == 00 ]] && { echo '[+] Exiting Reconator...'; break; }
    exec {menu_input}<&0
    (trap 'reconator_sigint' INT; trap 'cancel_children; exit 143' TERM; menu_dispatch "$option") <&"$menu_input" &
    action_pid=$!
    RECONATOR_CHILDREN="$action_pid"
    wait "$action_pid" || true
    RECONATOR_CHILDREN=''
    exec {menu_input}<&-
    printf '\n'
    read -r -p '[?] Press Enter to return to the menu...' || break
 done
