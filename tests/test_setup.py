"""Installer contracts: no-op plan, pinned versions, preserved configs, failure propagation."""
import contextlib
import hashlib
import zipfile
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('setup_installer', root/'setup/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    with patch.object(installer, 'ROOT', directory), patch.object(sys, 'argv', ['install.py', '--plan']), patch.object(installer, 'run', side_effect=AssertionError('plan must not execute commands')):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert installer.main() == 0
        plan = json.loads(output.getvalue())
        assert all('@' in v and '@latest' not in v for v in plan['go'].values())
        assert not list(directory.iterdir()), 'plan mutated filesystem'
    existing = directory/'tools/OneForAll'; existing.mkdir(parents=True)
    config = existing/'api.py'; config.write_text('user settings')
    with patch.object(installer, 'ROOT', directory), patch.object(installer.subprocess, 'check_output', return_value='different-revision\n'):
        try:
            installer.checkout('OneForAll', *installer.PROVIDERS['OneForAll'])
        except RuntimeError:
            pass
        else:
            raise AssertionError('must reject different checkout')
        assert config.read_text() == 'user settings'
    with patch.object(installer.subprocess, 'run', side_effect=subprocess.CalledProcessError(23, ['go'])):
        try:
            installer.run(['go', 'install', 'example@v1'])
        except subprocess.CalledProcessError as error:
            assert error.returncode == 23
        else:
            raise AssertionError('must propagate failed install')
# Exercise the installer orchestration in a clean directory with commands mocked.
# The separate package test exercises the actual released CLI with mocked tools.
with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    checkout_dirs = {}
    def checkout_mock(name, url, commit):
        path = directory/'tools'/name
        (path/'.venv/bin').mkdir(parents=True)
        (path/'.venv/bin/python').touch()
        if name == 'Sudomy':
            (path/'sudomy.api').write_text('USER_KEY="preserved"')
        checkout_dirs[name] = path
        return path
    commands = []
    def command_mock(args, **kwargs):
        commands.append(list(map(str, args)))
    with patch.object(installer, 'ROOT', directory), patch.object(sys, 'argv', ['install.py', '--python', '/fake/python']), patch.object(installer.os, 'geteuid', return_value=1000), patch.object(installer.shutil, 'which', return_value='/fake/python'), patch.object(installer, 'resolve_python', return_value='/fake/python'), patch.object(installer, 'checkout', side_effect=checkout_mock), patch.object(installer, 'install_amass'), patch.object(installer, 'run', side_effect=command_mock):
        assert installer.main() == 0
        assert len([cmd for cmd in commands if cmd[:2] == ['go', 'install']]) == len(installer.GO_TOOLS)
        assert commands[-1][-1] == 'doctor'
        assert not (directory/'tools/.install.lock').exists()
        assert (checkout_dirs['Sudomy']/'sudomy.api').read_text() == 'USER_KEY="preserved"'
        assert (checkout_dirs['Sudomy']/'sudomy.api').stat().st_mode & 0o777 == 0o600
    # A failed tool install must stop before claiming completion and release the lock.
    with patch.object(installer, 'ROOT', directory), patch.object(sys, 'argv', ['install.py', '--python', '/fake/python']), patch.object(installer.os, 'geteuid', return_value=1000), patch.object(installer.shutil, 'which', return_value='/fake/python'), patch.object(installer, 'resolve_python', return_value='/fake/python'), patch.object(installer, 'run', side_effect=subprocess.CalledProcessError(9, ['go'])):
        try:
            installer.main()
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError('installation failure swallowed')
        assert not (directory/'tools/.install.lock').exists()
result = subprocess.run(['bash', '-c', 'source lib/install.sh; heading(){ :; }; RECONATOR_HOME="$PWD"; install_dependencies'], cwd=root, input='n\n', capture_output=True, text=True)
assert result.returncode == 0 and 'cancelled' in result.stdout
print('Installer contract checks passed.')

# Only a checksum-verified binary may replace an existing installation.
with tempfile.TemporaryDirectory() as temp:
    binary = Path(temp)/'bin'; binary.mkdir()
    destination = binary/'amass'; destination.write_bytes(b'keep me')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as source:
        source.writestr('amass_Linux_amd64/amass', b'new verified executable')
    with patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(archive.getvalue())):
        try:
            installer.install_amass(binary)
        except RuntimeError as error:
            assert 'checksum mismatch' in str(error)
        else:
            raise AssertionError('invalid binary accepted')
        assert destination.read_bytes() == b'keep me'
    expected = dict(installer.AMASS, binary_sha256=hashlib.sha256(b'new verified executable').hexdigest())
    with patch.object(installer, 'AMASS', expected), patch.object(installer.urllib.request, 'urlopen', return_value=io.BytesIO(archive.getvalue())):
        installer.install_amass(binary)
        assert destination.read_bytes() == b'new verified executable'
        assert destination.stat().st_mode & 0o777 == 0o755
print('Amass checksum/atomic replacement checks passed.')

# A genuine fresh checkout must create Sudomy's ignored API file from .dist.
with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    origin = directory/'origin'; origin.mkdir()
    (origin/'sudomy.api.dist').write_text('SHODAN_API="example-placeholder"\n')
    (origin/'slack.conf').write_text('YOUR_WEBHOOK_URL="example-placeholder"\n')
    subprocess.run(['git','init',str(origin)],check=True,capture_output=True)
    subprocess.run(['git','-C',str(origin),'add','.'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(origin),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-m','fixture'],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(origin),'rev-parse','HEAD'],text=True).strip()
    clean = directory/'clean'; (clean/'tools').mkdir(parents=True)
    with patch.object(installer,'ROOT',clean):
        source=installer.checkout('Sudomy',str(origin),commit)
        assert (source/'sudomy.api').read_text()=='SHODAN_API=""\n'
        assert (source/'slack.conf').read_text()=='YOUR_WEBHOOK_URL=""\n'
        assert (source/'sudomy.api').stat().st_mode & 0o777 == 0o600
print('Fresh Sudomy template initialization passed.')
