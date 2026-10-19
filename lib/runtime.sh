#!/usr/bin/env bash
cancel_children() {
    local pid
    for pid in ${RECONATOR_CHILDREN:-}; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in ${RECONATOR_CHILDREN:-}; do wait "$pid" 2>/dev/null || true; done
    RECONATOR_CHILDREN=''
}
reconator_sigint() {
    # Foreground action subshells stop their work; the main process owns the prompt.
    if [[ "$BASHPID" != "$RECONATOR_ROOT_PID" ]]; then
        cancel_children
        exit 130
    fi
    if [[ "$RECONATOR_EXIT_ARMED" == true ]]; then
        printf '\n[+] Closing Reconator. Partial scan output is retained.\n'
        cancel_children
        exit 130
    fi
    RECONATOR_EXIT_ARMED=true
    printf '\n[!] Press Ctrl+C again to close Reconator.\n'
    cancel_children
}

reconator_install_signal_handler() {
    RECONATOR_ROOT_PID="$BASHPID"
    RECONATOR_EXIT_ARMED=false
    trap 'reconator_sigint' INT
    trap 'cancel_children; exit 143' TERM
    trap 'cancel_children' EXIT
}

# A signal-interrupted read must not be mistaken for EOF or an empty answer.
read() {
    local read_status
    while true; do
        builtin read -r "$@"
        read_status=$?
        if (( read_status > 128 )) && [[ "${RECONATOR_EXIT_ARMED:-false}" == true ]]; then
            continue
        fi
        if (( read_status == 0 )); then
            RECONATOR_EXIT_ARMED=false
        fi
        return "$read_status"
    done
}
