#!/usr/bin/env bash
# Shared globals are supplied by main.sh and the CLI scan context.
# shellcheck disable=SC2154
# A single ordered registry owns both labels and dispatch.
MENU_IDS=(01 02 03 04 05 06 07 08 09 10 11 12 99 00)
declare -A MENU_LABEL=(
    [01]='Passive Recon' [02]='Active Recon' [03]='Full Recon - all tools'
    [04]='Public Subdomains' [05]='DNS Enumeration' [06]='HTTP Inspection'
    [07]='Analyze Results' [08]='Previous Scans' [09]='Directory Discovery'
    [10]='Install Dependencies' [11]='Provider Enumeration (choose tools)'
    [12]='Check Tool Setup' [99]='About' [00]='Exit')
declare -A MENU_ACTION=(
    [01]=menu_passive [02]=menu_active [03]=menu_full [04]=menu_subdomains
    [05]=menu_dns [06]=menu_http [07]=run_analyze_results [08]=show_previous_scans
    [09]=menu_directory [10]=install_dependencies [11]=menu_providers
    [12]=cli_doctor [99]=menu_about [00]=menu_exit)
menu() {
    local id group=''
    printf '\n%bSELECT RECON MODE%b\n' "$CYAN$BOLD" "$RESET"
    for id in "${MENU_IDS[@]}"; do
        case "$id" in
            01) group='SCAN MODES' ;; 07) group='RESULTS' ;; 09) group='DISCOVERY & SETUP' ;; 99) group='SESSION' ;; *) group='' ;;
        esac
        [[ -n "$group" ]] && printf '\n  %b%s%b\n' "$BOLD" "$group" "$RESET"
        printf '  %b[%s]%b %-35s' "$GREEN" "$id" "$RESET" "${MENU_LABEL[$id]}"
        [[ "$id" == 03 ]] && printf '\n       All 6 providers, host/web checks and per-tool reports.'
        declare -F "${MENU_ACTION[$id]}" >/dev/null || printf ' (Coming soon)'
        printf '\n'
    done
    printf '\n'
}

menu_dispatch() {
    local id="$1"
    [[ "$id" =~ ^[0-9]$ ]] && id="0$id"
    if [[ -z "${MENU_ACTION[$id]:-}" ]] || ! declare -F "${MENU_ACTION[$id]}" >/dev/null; then echo '[-] Invalid/unavailable option'; return 2; fi
    "${MENU_ACTION[$id]}"
}
menu_scan() {
    local mode="$1" domain selected_target answer
    local -a args=()
    if [[ "$mode" == full || "$mode" == passive || "$mode" == subdomains || "$mode" == dns ]]; then
        read -r -p '[?] Enter root domain: ' domain || return 1
    else read -r -p '[?] Enter target (host/IP/URL): ' domain || return 1; fi
    args=(scan -d "$domain" --mode "$mode")
    if [[ "$mode" == full ]]; then
        read -r -p '[?] Enter active target: ' selected_target || return 1
        args+=(--target "$selected_target")
    fi
    if [[ "$mode" == full || "$mode" == directory ]]; then
        read -r -p '[?] Confirm authorization for automated directory testing [y/N]: ' answer || return 1
        [[ "$answer" == y || "$answer" == Y ]] && args+=(--directory)
    fi
    reconator_cli "${args[@]}"
}
menu_passive() { menu_scan passive; }
menu_active() { menu_scan active; }
menu_full() { menu_scan full; }
menu_subdomains() { menu_scan subdomains; }
menu_dns() { menu_scan dns; }
menu_http() { menu_scan http; }
menu_directory() { menu_scan directory; }
menu_providers() {
    local providers domain
    read -r -p '[?] Providers (all or comma-separated): ' providers || return 1
    read -r -p '[?] Enter root domain: ' domain || return 1
    reconator_cli scan -d "$domain" --mode subdomains --providers "$providers"
}
menu_about() { printf '\nReconator v%s\nAutomated Reconnaissance Toolkit\nCreated by 3xpl0iter\n' "$VERSION"; }
menu_exit() { return 0; }
show_previous_scans() {
    local root="${RECONATOR_RESULTS:-$RECONATOR_HOME/results}"
    echo 'Previous scans:'
    [[ -d "$root" ]] || { echo 'No scans yet.'; return 0; }
    find "$root" -mindepth 2 -maxdepth 2 -type d | sort
}
run_analyze_results() {
    local selected
    show_previous_scans
    read -r -p '[?] Enter scan directory path: ' selected || return 1
    [[ -d "$selected" ]] || { echo '[-] Scan directory does not exist'; return 2; }
    cli_report "$selected"
}
