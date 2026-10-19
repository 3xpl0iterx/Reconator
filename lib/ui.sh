#!/usr/bin/env bash
# Shared globals are supplied by main.sh and the CLI scan context.
# shellcheck disable=SC2154
banner() {
    printf "%b" "${RED}${BOLD}"

    cat << 'EOF'

 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
EOF

    printf "%b\n" "${WHITE}${BOLD}                  R E C O N A T O R${RESET}"
    printf "%b\n" "${WHITE}             Automated Reconnaissance Toolkit${RESET}"
    printf "\n  v%s  |  by 3xpl0iter  |  Ctrl+C twice to close\n" "$VERSION"
}

heading() {
    echo
    echo "========== $1 =========="
    echo
}

ui_section() {
    printf '\n%b%s%b\n' "$CYAN$BOLD" "$1" "$RESET"
}
ui_progress() {
    local number="$1" total="$2" name="$3" status="$4" color="$CYAN"
    case "$status" in success|no_data) color="$GREEN" ;; failed|timeout|interrupted) color="$RED" ;; skipped) color="$YELLOW" ;; esac
    printf '%b[%02d/%02d] %s %s%b\n' "$color" "$number" "$total" "$name" "$status" "$RESET"
}
