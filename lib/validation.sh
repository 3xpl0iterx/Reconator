#!/usr/bin/env bash
# Shared globals are supplied by main.sh and the CLI scan context.
# shellcheck disable=SC2154
normalize_target() {
    python3 "$RECONATOR_HOME/lib/targets.py" normalize "$1"
}
validate_root_domain() {
    python3 "$RECONATOR_HOME/lib/targets.py" domain "$root_domain" >/dev/null
}
validate_target() {
    target="$(normalize_target "$target")"
}
is_ip() {
    python3 "$RECONATOR_HOME/lib/targets.py" ip "$1" >/dev/null 2>&1
}
