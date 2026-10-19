#!/usr/bin/env bash
# shellcheck source=../main.sh
# shellcheck source-path=SCRIPTDIR
source "${RECONATOR_HOME:?}/main.sh" || exit 1
"$@"
