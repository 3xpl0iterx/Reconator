"""Find a working provider interpreter without modifying pyenv selections."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def resolve_python(root, requested=None):
    candidates = []
    if requested:
        candidates = [shutil.which(requested) or requested]
    else:
        if sys.version_info[:2] == (3, 12):
            candidates.append(sys.executable)
        candidates.extend(filter(None, [shutil.which('python3.12')]))
        # Existing provider venv symlinks resolve to their real base interpreter.
        for provider in ('OneForAll', 'Sudomy'):
            candidates.append(str(root / 'tools' / provider / '.venv/bin/python'))
        pyenv_roots = [Path(os.environ.get('PYENV_ROOT', Path.home() / '.pyenv'))]
        pyenv = shutil.which('pyenv')
        if pyenv:
            try:
                result = subprocess.run([pyenv, 'root'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    pyenv_roots.append(Path(result.stdout.strip()))
            except (OSError, subprocess.SubprocessError):
                pass
        for directory in dict.fromkeys(pyenv_roots):
            versions = directory / 'versions'
            if versions.is_dir():
                installed = [p for p in versions.iterdir() if re.fullmatch(r'3\.12\.\d+', p.name)]
                installed.sort(key=lambda p: int(p.name.rsplit('.', 1)[1]), reverse=True)
                candidates.extend(str(p / 'bin/python3.12') for p in installed)
    seen = set()
    for candidate in candidates:
        executable = str(Path(candidate).expanduser().resolve())
        if executable in seen:
            continue
        seen.add(executable)
        try:
            result = subprocess.run([executable, '-c',
                'import sys, venv; assert sys.version_info[:2] == (3,12); print(sys.executable)'],
                capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and Path(result.stdout.strip()).is_absolute():
            return result.stdout.strip()
    if requested:
        raise RuntimeError(f'Requested Python interpreter is unavailable or is not Python 3.12 with venv support: {requested}')
    raise RuntimeError('No working Python 3.12 found. Install it separately and set --python /absolute/path/to/python3.12 or RECONATOR_PROVIDER_PYTHON. A pyenv shim alone is not a working interpreter.')
