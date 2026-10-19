#!/usr/bin/env bash
# Shared globals are supplied by main.sh and the CLI scan context.
# shellcheck disable=SC2154
cli_subfinder() {
    command -v subfinder >/dev/null 2>&1 || return 127
    mkdir -p "$scan_dir/providers/subfinder" || return 1
    subfinder -d "$root_domain" -all -silent -o "$scan_dir/providers/subfinder/subdomains.txt"
}
cli_ping() {
    command -v ping >/dev/null 2>&1 || return 127
    local attempt
    for attempt in {1..6}; do
        echo "Ping attempt $attempt/6"
        if LC_ALL=C ping -c 1 -W 2 "$target"; then return 0; fi
    done
    echo 'No ICMP reply; the host may still be online.'
    return 3
}
parse_whois() {
    LC_ALL=C grep -Ei '^(Domain Name|Registrar:|Creation Date:|Updated Date:|Registry Expiry Date:|Name Server:|DNSSEC:)' "$1"
}
cli_whois() {
    command -v whois >/dev/null 2>&1 || return 127
    LC_ALL=C whois "$root_domain" > "$scan_dir/whois-raw.txt" || return $?
    parse_whois "$scan_dir/whois-raw.txt" > "$scan_dir/whois.txt"
    local rc=$?
    (( rc == 1 )) && return 3
    return "$rc"
}
cli_nmap() {
    command -v nmap >/dev/null 2>&1 || return 127
    local -a flags=(-p "${cli_ports:-1-300}" -sV)
    [[ "$cli_nmap_mode" == fast ]] && flags=(-F -T4)
    [[ "$cli_nmap_mode" == aggressive ]] && flags=(-sVC)
    is_ip "$target" && [[ "$target" == *:* ]] && flags+=(-6)
    LC_ALL=C nmap "${flags[@]}" -oN "$scan_dir/nmap.txt" -oX "$scan_dir/nmap.xml" "$target"
}
cli_http() {
    command -v curl >/dev/null 2>&1 || return 127
    local host="$target" scheme rc=0
    [[ "$host" == *:* ]] && host="[$host]"
    rm -f -- "$scan_dir/base-url.txt"
    : > "$scan_dir/http-errors.log"
    for scheme in https http; do
        curl --silent --show-error -I --connect-timeout 5 --max-time "${cli_http_timeout:-10}" \
            "$scheme://$host" > "$scan_dir/http.txt" 2>> "$scan_dir/http-errors.log"
        rc=$?
        if (( rc == 0 )); then
            printf '%s\n' "$scheme://$host" > "$scan_dir/base-url.txt"
            echo "HTTP inspection succeeded using $scheme."
            return 0
        fi
        if [[ "$scheme" == https ]]; then echo 'HTTPS unavailable; trying HTTP.'; fi
    done
    echo 'HTTP inspection unavailable; details saved to http-errors.log.'
    return "$rc"
}
cli_dns() {
    command -v dig >/dev/null 2>&1 || return 127
    local type rc=0
    : > "$scan_dir/dns.txt"
    for type in A AAAA MX NS TXT SOA; do
        echo "=== $type ===" >> "$scan_dir/dns.txt"
        LC_ALL=C dig +time=5 +tries=1 "$root_domain" "$type" >> "$scan_dir/dns.txt" || rc=$?
    done
    return "$rc"
}
cli_httpx() {
    command -v httpx >/dev/null 2>&1 || return 127
    httpx -h 2>&1 | grep -qi probe || return 2
    printf '%s\n' "$target" | httpx -silent -rate-limit "$cli_rate" -threads "$cli_threads" -o "$scan_dir/live.txt"
}
scan_url() {
    if [[ -s "$scan_dir/base-url.txt" ]]; then head -n 1 "$scan_dir/base-url.txt"
    else local host="$target"; [[ "$host" == *:* ]] && host="[$host]"; echo "https://$host"; fi
}
cli_nuclei() {
    command -v nuclei >/dev/null 2>&1 || return 127
    local -a args=()
    [[ "$cli_severity" != all ]] && args=(-severity "$cli_severity")
    nuclei -u "$(scan_url)" "${args[@]}" -jsonl -o "$scan_dir/nuclei.jsonl" -rl "$cli_rate" -c "$cli_threads"
}
cli_nikto() {
    command -v nikto >/dev/null 2>&1 || return 127
    LC_ALL=C nikto -h "$(scan_url)" -Format json -output "$scan_dir/nikto.json" -maxtime "$cli_timeout"
}
cli_directory() {
    [[ "$cli_directory_allowed" == true ]] || { echo 'Directory discovery declined.'; return 4; }
    [[ -r "$wordlist" && -f "$wordlist" ]] || { echo 'Readable wordlist unavailable; set RECONATOR_WORDLIST or --wordlist.'; return 4; }
    command -v ffuf >/dev/null 2>&1 || return 127
    ffuf -w "$wordlist" -u "$(scan_url)/FUZZ" -rate "$cli_rate" -t "$cli_threads" \
        -timeout "$cli_http_timeout" -of json -o "$scan_dir/directories.json"
}
