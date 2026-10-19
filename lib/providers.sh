#!/usr/bin/env bash
# Shared globals are supplied by main.sh and the CLI scan context.
# shellcheck disable=SC2154
# Provider adapters keep raw evidence and distinguish failures from empty results.
provider_run() {
    local provider="$1" rc=0
    mkdir -p "$scan_dir/providers/$provider" || return 1
    local out
    out="$(cd -- "$scan_dir/providers/$provider" && pwd)" || return 1
    case "$provider" in
        theharvester)
            if ! command -v theHarvester >/dev/null 2>&1; then
                echo "[-] theHarvester missing. Skipping."
                return 127
            fi
            theHarvester -d "$root_domain" -b "${HARVESTER_SOURCES:-crtsh}" \
                -l "${HARVESTER_LIMIT:-500}" -f "$out/results.json" \
                > "$out/console.log" 2>&1 || rc=$?
            # Preserve the filename used by earlier Reconator versions.
            cp -- "$out/console.log" "$scan_dir/theharvester.txt"
            ;;
        oneforall)
            local script="${ONEFORALL_SCRIPT:-$RECONATOR_HOME/tools/OneForAll/oneforall.py}"
            local default_python=python3
            [[ -x "$RECONATOR_HOME/tools/OneForAll/.venv/bin/python" ]] && default_python="$RECONATOR_HOME/tools/OneForAll/.venv/bin/python"
            local python="${ONEFORALL_PYTHON:-$default_python}"
            if [[ ! -f "$script" ]] || ! command -v "$python" >/dev/null 2>&1; then
                echo "[-] OneForAll missing. Set ONEFORALL_SCRIPT and ONEFORALL_PYTHON."
                return 127
            fi
            (cd -- "$(dirname -- "$script")" && "$python" "$(basename -- "$script")" \
                --target "$root_domain" --brute False --dns False --req False \
                --takeover False --alive False --fmt json --path "$out/results.json" run) \
                > "$out/console.log" 2>&1 || rc=$?
            ;;
        sudomy)
            local script="${SUDOMY_SCRIPT:-$RECONATOR_HOME/tools/Sudomy/sudomy}"
            if [[ ! -f "$script" ]]; then
                echo "[-] Sudomy missing. Set SUDOMY_SCRIPT."
                return 127
            fi
            # Upstream uses unquoted output paths; fail clearly rather than split them.
            if [[ "$out" =~ [[:space:]] ]]; then
                echo "[-] Sudomy requires an output path without whitespace."
                return 2
            fi
            (local lock directory
             directory="$(dirname -- "$script")" || exit 1
             lock="$directory/.reconator.lock"
             mkdir "$lock" 2>/dev/null || { echo 'Sudomy working directory is busy.'; exit 75; }
             trap 'rmdir -- "$lock" 2>/dev/null' EXIT
             trap 'exit 143' TERM
             trap 'exit 130' INT
             export PATH="$directory/.venv/bin:$PATH:$directory/lib/bin"
             cd -- "$(dirname -- "$script")" && bash "$(basename -- "$script")" \
                -d "$root_domain" --no-probe -o "$out") \
                > "$out/console.log" 2>&1 || rc=$?
            ;;
        amass)
            local amass="${AMASS_BIN:-amass}" help
            local -a flags=()
            command -v "$amass" >/dev/null 2>&1 || { echo "[-] Amass missing."; return 127; }
            help="$("$amass" enum -h 2>&1)"
            if [[ "$help" != *'Usage:'* ]]; then
                printf '%s\n' "$help" > "$out/console.log"
                echo "[-] Amass initialization failed; see $out/console.log"
                return 1
            fi
            [[ "${AMASS_ACTIVE:-false}" == true ]] && flags+=(-active)
            [[ "$help" == *'-nocolor'* ]] && flags+=(-nocolor)
            if [[ "$help" == *'-passive'* && "${AMASS_ACTIVE:-false}" != true ]]; then flags+=(-passive); fi
            if [[ "$help" =~ (^|$'\n')[[:space:]]*-o[[:space:]] ]]; then
                if [[ "${AMASS_IP:-false}" == true && "$help" =~ (^|$'\n')[[:space:]]*-ip[[:space:]] ]]; then flags+=(-ip); fi
                "$amass" enum "${flags[@]}" -d "$root_domain" -dir "$out/database" \
                    -o "$out/subdomains.txt" > "$out/console.log" 2>&1 || rc=$?
                if [[ "${AMASS_IP:-false}" == true && "$rc" == 0 ]]; then
                    python3 "$RECONATOR_HOME/lib/amass_ip.py" "$out/subdomains.txt" "$out/hosts-with-ip.txt" "$root_domain" >> "$out/console.log" 2>&1 || rc=$?
                fi
            else
                "$amass" enum "${flags[@]}" -d "$root_domain" -dir "$out/database" \
                    > "$out/console.log" 2>&1 || rc=$?
                if (( rc == 0 )); then
                    "$amass" subs -d "$root_domain" -dir "$out/database" -names \
                        -o "$out/subdomains.txt" >> "$out/console.log" 2>&1 || rc=$?
                    if [[ "${AMASS_IP:-false}" == true && "$rc" == 0 ]]; then
                        "$amass" subs -d "$root_domain" -dir "$out/database" -ip -show \
                            -o "$out/hosts-with-ip.txt" >> "$out/console.log" 2>&1 || rc=$?
                    fi
                fi
            fi
            ;;
        crobat)
            command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || return 127
            curl --fail --silent --show-error --connect-timeout 5 --max-time 30 \
                "${CROBAT_API_BASE:-https://sonar.omnisint.io}/subdomains/$root_domain" \
                -o "$out/results.json" > "$out/console.log" 2>&1 || rc=$?
            if (( rc == 0 )); then
                python3 - "$out/results.json" "$out/subdomains.txt" <<'PYJSON' >> "$out/console.log" 2>&1 || rc=$?
import json, sys
from pathlib import Path
values = json.loads(Path(sys.argv[1]).read_text())
if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
    raise ValueError("Sonar response must be a JSON array of domain strings")
Path(sys.argv[2]).write_text("".join(v + "\n" for v in values))
PYJSON
            fi
            ;;
        *) echo "[-] Unsupported provider: $provider"; return 2 ;;
    esac
    printf '%s\n' "$rc" > "$out/exit-code"
    if (( rc )); then
        echo "[-] $provider failed ($rc). See $out/console.log"
        return "$rc"
    fi
    echo "[+] $provider finished. Results: $out"
}
