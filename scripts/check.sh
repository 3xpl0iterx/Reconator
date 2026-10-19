#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")/.."
for file in main.sh reconator lib/*.sh scripts/*.sh; do bash -n "$file"; done
shellcheck -x main.sh reconator lib/*.sh scripts/*.sh
python3 tests/test_setup.py
python3 tests/test_packages.py
python3 tests/test_python_runtime.py
python3 tests/test_parsers.py
python3 tests/test_cli.py
python3 tests/test_interrupt.py
python3 tests/test_package.py
