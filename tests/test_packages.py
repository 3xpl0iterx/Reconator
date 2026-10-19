"""Offline package-manager selection, command routing and unavailable-package checks."""
import importlib.util
import io
import contextlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root/'setup'))
import packages
spec = importlib.util.spec_from_file_location('installer', root/'setup/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def which_for(*commands):
    return lambda command: '/mock/bin/' + command if command in commands else None


cases = [
    ({'ID': 'kali'}, ('apt-get',), 'apt'),
    ({'ID': 'ubuntu'}, ('apt-get', 'dnf'), 'apt'),
    ({'ID': 'fedora'}, ('apt-get', 'dnf'), 'dnf'),
    ({'ID': 'rocky'}, ('yum',), 'yum'),
    ({'ID': 'rocky'}, ('dnf5', 'yum'), 'dnf'),
    ({'ID': 'manjaro'}, ('pacman',), 'pacman'),
    ({'ID': 'opensuse-tumbleweed'}, ('zypper',), 'zypper'),
    ({'ID': 'alpine'}, ('apk',), 'apk'),
    ({'ID': 'custom', 'ID_LIKE': 'fedora rhel'}, ('dnf',), 'dnf'),
    ({'ID': 'custom'}, ('apt-get',), 'apt'),
    ({'ID': 'custom'}, ('dnf', 'yum'), 'dnf'),
    ({'ID': 'custom'}, ('dnf', 'apt-get'), None),
    ({'ID': 'fedora'}, ('apt-get',), None),
    ({}, (), None),
]
for release, commands, expected in cases:
    assert packages.detect_manager(release, which_for(*commands)) == expected, release

with tempfile.TemporaryDirectory() as temp:
    marker = Path(temp)/'must-not-exist'
    release_file = Path(temp)/'os-release'
    release_file.write_text(f'ID=kali\nID_LIKE="debian ubuntu"\nPRETTY_NAME="$(touch {marker})"\n')
    release = packages.read_release(release_file)
    assert release['ID_LIKE'] == 'debian ubuntu'
    assert not marker.exists(), 'os-release must never be executed'
    assert packages.read_release(Path(temp)/'missing') == {}

# Every backend routes through its own install syntax and probes only missing tools.
expected_prefixes = {
    'apt': ['sudo', 'apt-get', 'install', '-y', '--no-upgrade'],
    'dnf': ['sudo', 'dnf', 'install', '-y'],
    'yum': ['sudo', 'yum', 'install', '-y'],
    'pacman': ['sudo', 'pacman', '-S', '--needed', '--noconfirm'],
    'zypper': ['sudo', 'zypper', '--non-interactive', 'install'],
    'apk': ['sudo', 'apk', 'add'],
}
for manager, spec in packages.MANAGERS.items():
    which = which_for(*spec['commands'], 'sudo', 'nikto')
    plan = packages.package_plan(manager, release={'ID': 'fixture'}, which=which)
    calls = []
    queries = []
    def query(args, **kwargs):
        queries.append(args)
        package = args[-1]
        if package != spec['optional']['ffuf']:
            return subprocess.CompletedProcess(args, 1, '', 'unavailable')
        output = {'zypper': '<stream><solvable name="ffuf"/></stream>',
                  'apk': 'ffuf-2.1.0-r0\n'}.get(manager, 'Package: ffuf\n')
        return subprocess.CompletedProcess(args, 0, output, '')
    missing = packages.install_system(plan, calls.append, which, query)
    assert missing == ['theHarvester'], (manager, missing)
    install_calls = [call for call in calls if call[:len(expected_prefixes[manager])] == expected_prefixes[manager]]
    assert len(install_calls) == 2, (manager, calls)
    assert install_calls[0][len(expected_prefixes[manager]):] == plan['packages']
    assert install_calls[1][-1] == spec['optional']['ffuf']
    assert not any(args[-1] == 'nikto' for args in queries), 'installed tool should be skipped'
    assert not any('-Sy' in call or '-Syu' in call for call in calls), 'no automatic system upgrade'

# Exact metadata matches matter when a successful search has no package results.
for manager, output in [('apk', 'ffuf-extra-1.0\n'), ('zypper', '<stream/>'), ('apt', '')]:
    package = 'missing'
    assert not packages.optional_available(manager, manager, package,
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, output, ''))

plan = packages.package_plan('dnf', {}, which_for('dnf5', 'sudo'))
calls = []
packages.install_system(plan, calls.append, which_for('dnf5', 'sudo', 'nikto', 'ffuf', 'theHarvester'))
assert calls[0][:4] == ['sudo', 'dnf5', 'install', '-y']

# Unsupported/missing manager and missing sudo fail before executing install commands.
for plan, which in [(packages.package_plan('auto', {}, which_for()), which_for('sudo')),
                    (packages.package_plan('apt', {}, which_for()), which_for('sudo')),
                    (packages.package_plan('apt', {}, which_for('apt-get')), which_for('apt-get'))]:
    with patch.object(packages, 'optional_available', side_effect=AssertionError('must not query')):
        try:
            packages.install_system(plan, lambda args: (_ for _ in ()).throw(AssertionError('must not install')), which)
        except RuntimeError:
            pass
        else:
            raise AssertionError('preflight did not fail')

# Package-manager failures propagate; do not try another manager or continue tools.
plan = packages.package_plan('apt', {}, which_for('apt-get'))
with patch.object(packages, 'optional_available', side_effect=AssertionError('must stop')):
    try:
        packages.install_system(plan, lambda args: (_ for _ in ()).throw(subprocess.CalledProcessError(42, args)), which_for('sudo'))
    except subprocess.CalledProcessError as error:
        assert error.returncode == 42
    else:
        raise AssertionError('install error swallowed')

# --plan works for every backend without installed commands or package mutations.
for manager in packages.MANAGERS:
    with patch.object(sys, 'argv', ['install.py', '--plan', '--package-manager', manager]), patch.object(installer, 'run', side_effect=AssertionError('plan changed system')):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            assert installer.main() == 0
        assert json.loads(output.getvalue())['system']['manager'] == manager

# OS-only setup must not require Python 3.12, clone providers or build tools.
with patch.object(sys, 'argv', ['install.py', '--system-only']), patch.object(installer.os, 'geteuid', return_value=1000), patch.object(installer, 'package_plan', return_value={'manager': 'apt', 'available': True}), patch.object(installer, 'install_system', return_value=[]) as system, patch.object(installer, 'run', side_effect=AssertionError('unexpected build')), patch.object(installer, 'checkout', side_effect=AssertionError('unexpected checkout')):
    assert installer.main() == 0
    system.assert_called_once()
print('PASS: six package backends, distro detection, previews, OS-only setup, missing packages and failure propagation. No OS packages installed.')
