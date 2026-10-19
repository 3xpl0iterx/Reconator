#!/usr/bin/env python3
"""Extract available v3/v4 address associations without requesting extra DNS scans."""
import ipaddress
import re
import sys
from pathlib import Path
from report import host_name

rows = set()
for line in Path(sys.argv[1]).read_text(errors='replace').splitlines():
    if not (host := host_name(line, sys.argv[3])): continue
    for token in re.findall(r'[0-9a-fA-F:.]+', line):
        try: address = str(ipaddress.ip_address(token))
        except ValueError: continue
        rows.add(host + '\t' + address)
Path(sys.argv[2]).write_text(''.join(row + '\n' for row in sorted(rows)))
print(f'Amass address associations exported: {len(rows)}')
