"""Verify broken shim fallback and explicit interpreter selection without pyenv changes."""
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'setup'))
import python_runtime as runtime

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    pyenv_root = root/'custom-pyenv'
    shim = pyenv_root/'shims/python3.12'
    shim.parent.mkdir(parents=True)
    shim.write_text('#!/bin/sh\nexit 127\n'); shim.chmod(0o755)
    for version in ('3.12.9', '3.12.11', '3.13.1'):
        binary = pyenv_root/'versions'/version/'bin/python3.12'
        binary.parent.mkdir(parents=True); binary.touch()
    selected = pyenv_root/'versions/3.12.11/bin/python3.12'
    calls = []
    def probe(args, **kwargs):
        calls.append(args)
        if args[0] == str(selected):
            return subprocess.CompletedProcess(args, 0, str(selected)+'\n', '')
        return subprocess.CompletedProcess(args, 127, '', 'pyenv: command not found')
    with patch.dict(runtime.os.environ, {'PYENV_ROOT': str(pyenv_root)}), patch.object(runtime.sys, 'version_info', (3,14)), patch.object(runtime.shutil, 'which', side_effect=lambda n: str(shim) if n=='python3.12' else None), patch.object(runtime.subprocess, 'run', side_effect=probe):
        assert runtime.resolve_python(root) == str(selected)
        assert calls[0][0] == str(shim)
        assert not any('global' in args or 'local' in args or 'shell' in args for args in calls)
        # Explicit invalid overrides must fail rather than silently selecting another binary.
        try:
            runtime.resolve_python(root, str(shim))
        except RuntimeError as error:
            assert 'Requested Python interpreter' in str(error)
        else:
            raise AssertionError('explicit broken override accepted')
        assert runtime.resolve_python(root, str(selected)) == str(selected)
    # Existing venv symlinks should select the base interpreter without invoking pyenv.
    venv = root/'tools/OneForAll/.venv/bin/python'
    venv.parent.mkdir(parents=True);venv.symlink_to(selected)
    with patch.dict(runtime.os.environ, {'PYENV_ROOT': str(root/'missing')}), patch.object(runtime.sys, 'version_info', (3,14)), patch.object(runtime.shutil, 'which', return_value=None), patch.object(runtime.subprocess, 'run', side_effect=probe):
        assert runtime.resolve_python(root) == str(selected)
    # Wrong version, missing binary and hung shim must all be rejected clearly.
    for outcome in [subprocess.CompletedProcess([], 1, '', ''), FileNotFoundError(), subprocess.TimeoutExpired('python',10)]:
        def reject(*args, **kwargs):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        with patch.object(runtime.subprocess, 'run', side_effect=reject):
            try:
                runtime.resolve_python(root, str(selected))
            except RuntimeError:
                pass
            else:
                raise AssertionError('nonworking interpreter accepted')
print('PASS: broken pyenv shim fallback, numeric version ordering, venv base resolution, explicit overrides, missing/wrong Python and probe timeouts.')
