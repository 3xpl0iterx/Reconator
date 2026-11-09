"""Prompts must arrive while the writer remains open, before any newline."""
import os
from pathlib import Path
import select
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
process = subprocess.Popen([sys.executable, str(root / 'lib/proxy_stderr.py')], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    process.stdin.write(b'[proxy'); process.stdin.flush()
    process.stdin.write(b'chains] DLL init: test\n[?] Select an option: '); process.stdin.flush()
    assert select.select([process.stderr], [], [], 3)[0], 'prompt was buffered'
    assert os.read(process.stderr.fileno(), 4096) == b'[?] Select an option: '
    process.stdin.write(b'[proxychains] Strict chain ... OK\n[proxychains] connection refused\n'); process.stdin.flush()
    assert select.select([process.stderr], [], [], 3)[0], 'error was hidden'
    assert os.read(process.stderr.fileno(), 4096) == b'[proxychains] connection refused\n'
    process.stdin.close()
    assert process.wait(timeout=3) == 0
finally:
    if process.poll() is None:
        process.kill(); process.wait()
print('PASS: newline-free prompts, split proxy prefixes, hidden routine messages and visible errors.')
