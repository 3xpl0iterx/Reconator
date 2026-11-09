#!/usr/bin/env python3
"""Filter proxy diagnostics without delaying interactive, newline-free prompts."""
import os
import re

PREFIX = b'[proxychains]'


def emit(line):
    if line.startswith(PREFIX) and (
        re.search(rb'config file found:|preloading |DLL init:', line)
        or re.search(rb'\.\.\.\s*OK\s*$', line)
    ):
        return
    # stderr is a terminal or pipe; handle partial writes as well.
    while line:
        line = line[os.write(2, line):]


pending = b''
while True:
    chunk = os.read(0, 4096)
    if not chunk:
        break
    pending += chunk
    while b'\n' in pending:
        line, pending = pending.split(b'\n', 1)
        emit(line + b'\n')
    # Only proxy-prefixed diagnostics need a complete line for classification.
    if pending and not (pending.startswith(PREFIX) or PREFIX.startswith(pending)):
        emit(pending)
        pending = b''
if pending:
    emit(pending)
