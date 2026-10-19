#!/usr/bin/env bash
# RECONATOR_CHILDREN is consumed by runtime.sh.
# shellcheck disable=SC2034
cli_help() {
    cat <<HELP
Reconator v$VERSION — by 3xpl0iter
Usage: reconator [scan|passive|active|full|enum|dns|http|directory|web] [options]
No arguments: interactive menu.
  -m, --mode MODE          passive, active, full, subdomains, dns, http, directory, web
  -d, --domain HOST        Domain/IP/HTTP URL; provider modes require a domain
  -t, --targets FILE       One target per line, duplicates removed
  --target HOST           Active host for a single root domain (Full Recon)
  --providers LIST        Comma-separated providers, or all
                          subfinder,theharvester,oneforall,sudomy,amass,crobat
  --scope FILE            Allowed domains/CIDRs (input targets only)
  --exclude FILE          Excluded domains/CIDRs
  --profile PROFILE       quick, balanced (default), thorough
  --output DIR            Results root; default project/results
  --resume                Resume successful phases in a stable scan directory
  --resume-dir DIR        Resume a specified scan with matching targets/settings
  --wordlist FILE         Directory wordlist; RECONATOR_WORDLIST also supported
  --directory             Confirm directory testing for this invocation
  --severity LIST         all (default), or critical,high,medium,low,info,unknown
  --timeout SECONDS       Per-module deadline (default 300)
  --http-timeout SECONDS   Per-request timeout (default 10)
  --rate N / --threads N   Request rate/concurrency (defaults 2/1)
  --jobs N                Concurrent input targets (default 1, maximum 8)
  --ports SPEC            Nmap ports (default 1-300)
  --fast / --aggressive   Nmap modes; default ports 1–300 with service detection
  --nmap-only / --nuclei-only / --nikto-only
  --amass-active / --amass-ip
Commands: doctor, history, report SCAN_DIR, compare SCAN_A SCAN_B, --install
  -h, --help / -v, --version
Full Recon runs all selected providers, host checks and reports. Providers default
to all in full/subdomains mode; passive defaults to subfinder,theharvester,crobat,sudomy.
OneForAll/Amass may perform DNS checks. Newly discovered assets are not scanned.
Provider keys remain in provider configuration files. No wordlists are downloaded.
HELP
}
cli_doctor() {
    local tool missing=0 destination="${RECONATOR_RESULTS:-$RECONATOR_HOME/results}"
    echo "Reconator v$VERSION — offline environment check"
    for tool in bash python3 curl whois ping nmap subfinder theHarvester ffuf dig httpx nuclei nikto amass; do
        if command -v "$tool" >/dev/null 2>&1; then printf '[+] %-14s %s\n' "$tool" "$(command -v "$tool")";
        else echo "[-] $tool missing"; missing=1; fi
    done
    if command -v httpx >/dev/null 2>&1 && ! httpx -h 2>&1 | grep -qi probe; then echo '[-] ProjectDiscovery httpx required'; missing=1; fi
    local script python
    script="${ONEFORALL_SCRIPT:-$RECONATOR_HOME/tools/OneForAll/oneforall.py}"
    python=python3
    [[ -x "$RECONATOR_HOME/tools/OneForAll/.venv/bin/python" ]] && python="$RECONATOR_HOME/tools/OneForAll/.venv/bin/python"
    python="${ONEFORALL_PYTHON:-$python}"
    if [[ -f "$script" ]] && "$python" -c 'import fire, sqlalchemy' >/dev/null 2>&1; then echo '[+] OneForAll script and Python dependencies';
    else echo '[-] OneForAll script/environment unavailable'; missing=1; fi
    script="${SUDOMY_SCRIPT:-$RECONATOR_HOME/tools/Sudomy/sudomy}"
    if [[ -f "$script" && -r "$(dirname -- "$script")/sudomy.api" ]]; then echo '[+] Sudomy script and API configuration file';
    else echo '[-] Sudomy script/API configuration file missing'; missing=1; fi
    if [[ -r "$wordlist" && -f "$wordlist" ]]; then echo "[+] Readable wordlist: $wordlist";
    else echo "[!] Directory mode unavailable: wordlist not readable: $wordlist"; fi
    while [[ ! -e "$destination" && "$destination" != / ]]; do destination="$(dirname -- "$destination")"; done
    if [[ -d "$destination" && -w "$destination" && -x "$destination" ]]; then echo '[+] Results location writable';
    else echo '[-] Results location is not writable'; missing=1; fi
    echo '[*] API credentials/service availability require separate checks. The historical Crobat/Sonar endpoint has returned 404.'
    return "$missing"
}
cli_report() { python3 "$RECONATOR_HOME/lib/report.py" "$1"; }
phase_evidence() {
    local name="$1" path
    local files="logs/$name.log"
    local -a candidates=()
    case "$name" in
        subfinder|theharvester|oneforall|sudomy|amass|crobat)
            if [[ -d "$scan_dir/providers/$name" ]]; then
                while IFS= read -r path; do files+=",${path#"$scan_dir/"}"; done < <(find "$scan_dir/providers/$name" -type f | sort)
            fi ;;
        nmap) candidates=(nmap.txt nmap.xml) ;; http) candidates=(http.txt http-errors.log base-url.txt) ;;
        whois) candidates=(whois.txt whois-raw.txt) ;; dns) candidates=(dns.txt) ;; httpx) candidates=(live.txt) ;;
        nuclei) candidates=(nuclei.jsonl) ;; nikto) candidates=(nikto.json) ;; directory) candidates=(directories.json) ;;
    esac
    for path in "${candidates[@]}"; do [[ -f "$scan_dir/$path" ]] && files+=",$path"; done
    printf '%s' "$files"
}
record_phase() { python3 "$RECONATOR_HOME/lib/state.py" "$scan_dir" "$@"; }
scan_cleanup() {
    local rc=$?
    trap - EXIT
    trap '' INT TERM HUP
    if [[ -n "${active_pid:-}" ]]; then kill -TERM "$active_pid" 2>/dev/null; wait "$active_pid" 2>/dev/null; fi
    if [[ -n "${active_phase:-}" ]]; then record_phase "$active_phase" interrupted "$rc" "$(phase_evidence "$active_phase")"; fi
    if (( rc == 130 || rc == 143 )); then
        printf 'interrupted\n' > "$scan_dir/scan-status.txt"
        python3 "$RECONATOR_HOME/lib/run.py" 3 python3 "$RECONATOR_HOME/lib/report.py" "$scan_dir" >/dev/null 2>&1 || true
    fi
    rm -f -- "$scan_dir/state/"*.exit.[0-9]*.tmp "$scan_dir/state/"*.status.[0-9]*.tmp "$scan_dir/state/"*.files.[0-9]*.tmp "$scan_dir/reports/"*.json.[0-9]*.tmp "$scan_dir/reports/"*.md.[0-9]*.tmp "$scan_dir/"manifest.tsv.[0-9]*.tmp "$scan_dir/"subdomains_uniq.txt.[0-9]*.tmp "$scan_dir/"subdomains.txt.[0-9]*.tmp
    rmdir -- "$scan_dir/.lock" 2>/dev/null || true
    return "$rc"
}
cli_phase() {
    local name="$1" rc=0 status
    shift
    phase_number=$((phase_number + 1))
    if [[ "$cli_resume" == true && -f "$scan_dir/state/$name.ok" ]]; then echo "[$phase_number/$phase_total] Resume: $name already completed."; return 0; fi
    ui_progress "$phase_number" "$phase_total" "$name" started
    active_phase="$name"
    record_phase "$name" running 0 "logs/$name.log"
    export RECONATOR_HOME scan_dir root_domain target wordlist cli_nmap_mode cli_severity cli_rate cli_threads cli_timeout cli_http_timeout cli_directory_allowed cli_ports AMASS_ACTIVE AMASS_IP
    python3 "$RECONATOR_HOME/lib/run.py" "$cli_timeout" bash "$RECONATOR_HOME/lib/phase.sh" "$@" > "$scan_dir/logs/$name.log" 2>&1 &
    active_pid=$!
    wait "$active_pid" || rc=$?
    active_pid=''
    if (( rc == 0 )); then
        python3 "$RECONATOR_HOME/lib/report.py" validate "$scan_dir" "$name" >> "$scan_dir/logs/$name.log" 2>&1 || rc=$?
    fi
    case "$rc" in
        0) status=success ;; 3) status=no_data ;; 4|127) status=skipped ;; 28|124) status=timeout ;; 130|143) status=interrupted ;; *) status=failed ;;
    esac
    record_phase "$name" "$status" "$rc" "$(phase_evidence "$name")"
    active_phase=''
    ui_progress "$phase_number" "$phase_total" "$name" "$status"
    if [[ "$name" == http ]]; then
        LC_ALL=C grep -E 'HTTPS unavailable;|HTTP inspection (succeeded|unavailable)' "$scan_dir/logs/http.log" || true
    fi
    (( rc == 130 || rc == 143 )) && exit "$rc"
    (( rc == 0 || rc == 3 || rc == 4 ))
}
cli_scan_domain() {
    root_domain="$1"; target="${cli_target:-$1}"
    local key="$cli_mode-${cli_providers//,/_}-$cli_nmap_mode" phase failed=0
    scan_dir="$cli_output/$root_domain"
    mkdir -p "$scan_dir" || return 1
    if [[ -n "$cli_resume_dir" ]]; then scan_dir="$cli_resume_dir";
    elif [[ "$cli_resume" == true ]]; then scan_dir="$scan_dir/$key"; mkdir -p "$scan_dir" || return 1;
    else scan_dir="$(mktemp -d "$scan_dir/$key-$(date +%Y-%m-%d_%H-%M-%S)-XXXXXX")" || return 1; fi
    mkdir "$scan_dir/.lock" 2>/dev/null || { echo "[-] Scan locked: $scan_dir"; return 1; }
    local active_phase='' active_pid='' phase_number=0 phase_total=0 config_digest
    trap scan_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -p "$scan_dir/state" "$scan_dir/logs" || return 1
    config_digest="$(printf '%s\n' "$root_domain" "$target" "$cli_mode" "$cli_providers" "$cli_nmap_mode" "$cli_severity" "$cli_ports" "$cli_rate" "$cli_threads" "$cli_timeout" "$cli_http_timeout" "$wordlist" "$cli_directory_allowed" "${HARVESTER_SOURCES:-crtsh}" "${HARVESTER_LIMIT:-500}" "${ONEFORALL_SCRIPT:-}" "${ONEFORALL_PYTHON:-}" "${SUDOMY_SCRIPT:-}" "${AMASS_BIN:-amass}" "$AMASS_ACTIVE" "$AMASS_IP" "${CROBAT_API_BASE:-https://sonar.omnisint.io}"; sha256sum "$RECONATOR_HOME/main.sh" "$RECONATOR_HOME/lib/"*.sh "$RECONATOR_HOME/lib/"*.py)"
    config_digest="$(printf '%s' "$config_digest" | sha256sum)"
    if [[ -n "$cli_resume_dir" ]]; then
        [[ -f "$scan_dir/domain.txt" && -f "$scan_dir/target.txt" && -f "$scan_dir/mode.txt" ]] || { echo '[-] Not a current Reconator scan'; return 2; }
        [[ "$(cat "$scan_dir/domain.txt")" == "$root_domain" && "$(cat "$scan_dir/target.txt")" == "$target" && "$(cat "$scan_dir/mode.txt")" == "$cli_mode" ]] || { echo '[-] Resume root/target/mode mismatch'; return 2; }
    fi
    if [[ -f "$scan_dir/state/config" && "$(cat "$scan_dir/state/config")" != "$config_digest" ]]; then
        echo '[*] Settings/code changed; repeating phases.'
        local archive entry
        archive="$scan_dir/archive/previous-$(date +%Y%m%d-%H%M%S-%N)"
        mkdir -p "$archive" || return 1
        for entry in "$scan_dir/"*; do
            [[ "$(basename -- "$entry")" == archive ]] && continue
            mv -- "$entry" "$archive/" || return 1
        done
        mkdir -p "$scan_dir/state" "$scan_dir/logs" || return 1
    fi
    printf '%s\n' "$config_digest" > "$scan_dir/state/config"
    printf '%s\n' "$root_domain" > "$scan_dir/domain.txt"
    printf '%s\n' "$target" > "$scan_dir/target.txt"
    printf '%s\n' "$cli_mode" > "$scan_dir/mode.txt"
    printf '%s\n' "$VERSION" > "$scan_dir/version.txt"
    printf 'running\n' > "$scan_dir/scan-status.txt"
    local -a phases=() selected=()
    IFS=',' read -r -a selected <<< "$cli_providers"
    case "$cli_mode" in
        passive) phases=(whois "${selected[@]}") ;;
        subdomains) phases=("${selected[@]}") ;;
        active) phases=(ping nmap http) ;;
        full) phases=(ping nmap http whois dns "${selected[@]}" httpx nuclei nikto directory) ;;
        web) phases=(http httpx nmap nuclei nikto) ;;
        *) phases=("$cli_mode") ;;
    esac
    phase_total=${#phases[@]}
    for phase in "${phases[@]}"; do
        [[ -f "$scan_dir/state/$phase.status" ]] || record_phase "$phase" pending 0 '-'
    done
    ui_section "${cli_mode^^} RECON"
    echo "  Root: $root_domain   Active target: $target"
    echo "  Modules: $phase_total   Severity: $cli_severity"
    echo "[*] Scan directory: $scan_dir"
    for phase in "${phases[@]}"; do
        case "$phase" in
            subfinder) cli_phase "$phase" cli_subfinder || failed=1 ;;
            theharvester|oneforall|sudomy|amass|crobat) cli_phase "$phase" provider_run "$phase" || failed=1 ;;
            *) cli_phase "$phase" "cli_$phase" || failed=1 ;;
        esac
    done
    if (( failed )); then printf 'incomplete\n' > "$scan_dir/scan-status.txt"; else printf 'complete\n' > "$scan_dir/scan-status.txt"; fi
    cli_report "$scan_dir" || failed=1
    return "$failed"
}
reconator_cli() {
    local mode_alias=''
    case "${1:-}" in
        -h|--help) cli_help; return ;; -v|--version) echo "Reconator v$VERSION"; return ;;
        doctor) cli_doctor; return ;;
        history) show_previous_scans; return ;;
        report) [[ $# == 2 && -d "$2" ]] || { echo 'Usage: reconator report SCAN_DIR'; return 2; }; cli_report "$2"; return ;;
        compare) [[ $# == 3 ]] || { echo 'Usage: reconator compare SCAN_A SCAN_B'; return 2; }; python3 "$RECONATOR_HOME/lib/report.py" compare "$2" "$3"; return ;;
        scan) shift ;;
        passive|active|full|enum|dns|http|directory|web) mode_alias="$1"; [[ "$mode_alias" == enum ]] && mode_alias=subdomains; shift ;;
        -*) ;; *) echo "[-] Unknown command: $1"; return 2 ;;
    esac
    if [[ -n "$mode_alias" && $# == 0 ]]; then menu_scan "$mode_alias"; return; fi
    local cli_mode="${mode_alias:-passive}" cli_providers='' cli_resume=false cli_resume_dir=''
    local cli_output="${RECONATOR_RESULTS:-$RECONATOR_HOME/results}" cli_domain='' cli_file='' cli_target='' cli_nmap_mode=default
    local cli_ports=1-300 cli_severity=all cli_timeout=300 cli_http_timeout=10 cli_rate=2 cli_threads=1 cli_jobs=1 cli_directory_allowed=false
    local AMASS_ACTIVE=false AMASS_IP=false profile=balanced scope='' exclude='' only_mode='' rc=0
    local wordlist="${RECONATOR_WORDLIST:-/usr/share/wordlists/dirb/big.txt}"
    while (( $# )); do
        case "$1" in
            -h|--help) cli_help; return ;;
            -m|--mode|-d|--domain|-t|--targets|--target|--providers|--output|--wordlist|--severity|--timeout|--http-timeout|--rate|--threads|--ports|--jobs|--scope|--exclude|--profile|--resume-dir)
                [[ $# -ge 2 && -n "$2" ]] || { echo "[-] Missing value for $1"; return 2; }
                case "$1" in
                    -m|--mode) cli_mode="$2" ;; -d|--domain) cli_domain="$2" ;; -t|--targets) cli_file="$2" ;;
                    --target) cli_target="$2" ;; --providers) cli_providers="$2" ;; --output) cli_output="$2" ;;
                    --wordlist) wordlist="$2" ;; --severity) cli_severity="$2" ;; --timeout) cli_timeout="$2" ;;
                    --http-timeout) cli_http_timeout="$2" ;; --rate) cli_rate="$2" ;; --threads) cli_threads="$2" ;; --ports) cli_ports="$2" ;;
                    --jobs) cli_jobs="$2" ;; --scope) scope="$2" ;; --exclude) exclude="$2" ;;
                    --profile) profile="$2" ;; --resume-dir) cli_resume_dir="$2"; cli_resume=true ;;
                esac
                shift 2 ;;
            --resume) cli_resume=true; shift ;; --directory) cli_directory_allowed=true; shift ;;
            --amass-active) AMASS_ACTIVE=true; shift ;; --amass-ip) AMASS_IP=true; shift ;;
            --fast|--aggressive) cli_nmap_mode="${1#--}"; shift ;;
            --nmap-only|--nuclei-only|--nikto-only)
                [[ -z "$only_mode" ]] || { echo '[-] Choose one phase-only option'; return 2; }
                only_mode="${1#--}"; only_mode="${only_mode%-only}"; shift ;;
            *) echo "[-] Unknown option: $1"; return 2 ;;
        esac
    done
    if [[ -n "$only_mode" ]]; then
        [[ "$cli_mode" == passive && -z "$mode_alias" ]] || { echo '[-] Conflicting mode options'; return 2; }; cli_mode="$only_mode"
    fi
    case "$profile" in quick) [[ "$cli_nmap_mode" == default ]] && cli_nmap_mode=fast ;; balanced) ;; thorough) [[ "$cli_nmap_mode" == default ]] && cli_nmap_mode=aggressive ;; *) echo '[-] Invalid profile'; return 2 ;; esac
    case "$cli_mode" in passive|active|full|subdomains|dns|http|directory|web|nmap|nuclei|nikto) ;; *) echo '[-] Invalid mode'; return 2 ;; esac
    if [[ -z "$cli_providers" ]]; then
        if [[ "$cli_mode" == passive ]]; then cli_providers=subfinder,theharvester,crobat,sudomy;
        else cli_providers=all; fi
    fi
    [[ "$cli_providers" == all ]] && cli_providers=subfinder,theharvester,oneforall,sudomy,amass,crobat
    [[ "$cli_providers" =~ ^(subfinder|theharvester|oneforall|sudomy|amass|crobat)(,(subfinder|theharvester|oneforall|sudomy|amass|crobat))*$ ]] || { echo '[-] Invalid provider list'; return 2; }
    [[ "$cli_severity" =~ ^(all|(critical|high|medium|low|info|unknown)(,(critical|high|medium|low|info|unknown))*)$ ]] || { echo '[-] Invalid severity'; return 2; }
    [[ "$cli_ports" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || { echo '[-] Invalid port specification'; return 2; }
    python3 - "$cli_ports" <<'PYPORTS' || return 2
import sys
for part in sys.argv[1].split(','):
    numbers = [int(n) for n in part.split('-')]
    if any(n < 1 or n > 65535 for n in numbers) or numbers != sorted(numbers):
        print('[-] Ports must be ordered within 1–65535', file=sys.stderr)
        sys.exit(2)
PYPORTS
    local number
    for number in "$cli_timeout" "$cli_http_timeout" "$cli_rate" "$cli_threads" "$cli_jobs"; do
        [[ "$number" =~ ^[1-9][0-9]{0,4}$ ]] || { echo '[-] Numeric limits must be positive integers'; return 2; }
    done
    (( cli_jobs <= 8 && cli_threads <= 100 && cli_rate <= 1000 && cli_timeout <= 86400 && cli_http_timeout <= 300 )) || { echo '[-] Requested limits are out of range'; return 2; }
    [[ -n "$cli_domain" && -z "$cli_file" || -z "$cli_domain" && -n "$cli_file" ]] || { echo '[-] Choose -d HOST or -t FILE'; return 2; }
    if [[ -n "$cli_target" ]]; then
        [[ -n "$cli_domain" && "$cli_mode" == full ]] || { echo '[-] --target requires a single Full Recon root domain'; return 2; }
        cli_target="$(normalize_target "$cli_target")" || return 2
    fi
    mkdir -p "$cli_output" || return 1
    cli_output="$(cd -- "$cli_output" && pwd)" || return 1
    if [[ -n "$cli_resume_dir" ]]; then
        [[ -d "$cli_resume_dir" && -n "$cli_domain" ]] || { echo '[-] --resume-dir needs an existing scan and a single target'; return 2; }
        cli_resume_dir="$(cd -- "$cli_resume_dir" && pwd)" || return 1
    fi
    local target_list filtered
    target_list="$(mktemp "$cli_output/.targets-XXXXXX.tmp")" || return 1
    if [[ -n "$cli_domain" ]]; then printf '%s\n' "$cli_domain" > "$target_list";
    else [[ -r "$cli_file" ]] || { rm -f -- "$target_list"; echo '[-] Cannot read target file'; return 2; }; cp -- "$cli_file" "$target_list"; fi
    filtered="$(python3 "$RECONATOR_HOME/lib/targets.py" filter "$target_list" "$scope" "$exclude")"; rc=$?
    rm -f -- "$target_list"
    (( rc == 0 )) || return "$rc"
    [[ -n "$filtered" ]] || { echo '[-] No targets remain'; return 2; }
    local -a domains=() pids=()
    mapfile -t domains <<< "$filtered"
    local domain pid
    for domain in "${domains[@]}"; do
        case "$cli_mode" in passive|full|subdomains|dns) root_domain="$domain"; validate_root_domain || return 2 ;; esac
    done
    if [[ -n "$cli_target" ]]; then
        printf '%s\n' "$cli_target" > "$cli_output/.target-scope-$$.tmp"
        python3 "$RECONATOR_HOME/lib/targets.py" filter "$cli_output/.target-scope-$$.tmp" "$scope" "$exclude" > "$cli_output/.target-scope-$$.filtered.tmp"
        rc=$?; filtered="$(cat "$cli_output/.target-scope-$$.filtered.tmp")"
        rm -f -- "$cli_output/.target-scope-$$.tmp" "$cli_output/.target-scope-$$.filtered.tmp"
        (( rc == 0 )) && [[ -n "$filtered" ]] || return 2
    fi
    rc=0
    RECONATOR_CHILDREN=''
    for domain in "${domains[@]}"; do
        cli_scan_domain "$domain" &
        pids+=("$!"); RECONATOR_CHILDREN="${pids[*]}"
        if (( ${#pids[@]} >= cli_jobs )); then
            for pid in "${pids[@]}"; do wait "$pid"; number=$?; (( number == 130 || number == 143 )) && { cancel_children; return "$number"; }; (( number == 0 )) || rc=1; done
            pids=(); RECONATOR_CHILDREN=''
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid"; number=$?; (( number == 130 || number == 143 )) && { cancel_children; return "$number"; }; (( number == 0 )) || rc=1; done
    RECONATOR_CHILDREN=''
    return "$rc"
}
