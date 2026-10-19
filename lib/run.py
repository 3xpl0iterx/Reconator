#!/usr/bin/env python3
"""Run one module with a bounded lifetime and kill its complete process group."""
import os
import signal
import subprocess
import sys

child = None


def stop():
    if child is None: return
    try: os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError: return
    try: child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait()
    # A provider may have spawned descendants before its parent exited.
    try: os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError: pass


def interrupted(sig, frame):
    stop()
    sys.exit(130 if sig == signal.SIGINT else 143)


signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)
try:
    child = subprocess.Popen(sys.argv[2:], start_new_session=True)
    code = child.wait(timeout=int(sys.argv[1]))
    stop()
    sys.exit(code if code >= 0 else 128 - code)
except subprocess.TimeoutExpired:
    stop()
    print('Module timed out; partial evidence retained.', file=sys.stderr)
    sys.exit(124)
