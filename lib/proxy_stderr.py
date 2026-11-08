#!/usr/bin/env python3
"""Hide routine proxychains chatter; preserve connection failures and other stderr."""
import re
import sys

for line in sys.stdin:
    if line.startswith('[proxychains]'):
        if re.search(r'config file found:|preloading |DLL init:', line):
            continue
        if re.search(r'\.\.\.\s*OK\s*$', line):
            continue
    sys.stderr.write(line)
    sys.stderr.flush()
