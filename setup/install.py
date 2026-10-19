#!/usr/bin/env python3
"""Explicit, pinned optional-tool setup. Does not scan targets or modify shell files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

# Keep import working when loaded by the offline tests as well as executed directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from packages import MANAGERS, install_system, package_plan
from python_runtime import resolve_python

ROOT = Path(__file__).resolve().parents[1]
GO_TOOLS = {
    'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0',
    'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0',
    'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1',
    'crobat': 'github.com/cgboal/sonarsearch/cmd/crobat@v0.0.0-20230421223706-f5e49c7a67cd',
}
AMASS = {
    'url': 'https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip',
    'binary_sha256': 'a1a4c46d92072b5724696ee180cbf09023d4ab943b9a82d2c5ab20b112bfcf32',
    'version': '4.2.0',
}
PROVIDERS = {
    'OneForAll': ('https://github.com/shmilylty/OneForAll.git', 'e5255ae7009d12779d98be192b099c3c300dfd8a'),
    'Sudomy': ('https://github.com/screetsec/Sudomy.git', 'd7d9d416d20f7cc56640668d48de8394691afe30'),
}


def run(args, **kwargs):
    print('+ ' + ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def checkout(name, url, commit):
    destination = ROOT / 'tools' / name
    if destination.exists():
        # Preserve local API/config edits. Never reset an existing checkout.
        actual = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != commit:
            raise RuntimeError(f'{name}: existing checkout differs from pinned commit; preserve it and configure an external installation, or move it aside yourself.')
        return destination
    # Failed downloads/builds never masquerade as a complete provider checkout.
    staging = ROOT / 'tools' / ('.install-' + name)
    if staging.exists():
        raise RuntimeError(f'Interrupted setup exists at {staging}; inspect/move it before retrying.')
    run(['git', 'init', staging])
    run(['git', '-C', staging, 'remote', 'add', 'origin', url])
    run(['git', '-C', staging, 'fetch', '--depth=1', 'origin', commit])
    run(['git', '-C', staging, 'checkout', '--detach', 'FETCH_HEAD'])
    if name == 'Sudomy':
        api = staging / 'sudomy.api'
        if not api.exists():
            template = staging / 'sudomy.api.dist'
            if not template.is_file():
                raise RuntimeError('Sudomy API template missing from pinned checkout.')
            shutil.copyfile(template, api)
        # Fresh upstream examples must never enable credentials or notifications.
        for filename in ['sudomy.api', 'slack.conf']:
            path = staging / filename
            if path.exists():
                path.write_text(re.sub(r'(?m)^([A-Za-z_][A-Za-z_0-9]*)=.*$', r'\1=""', path.read_text()))
                path.chmod(0o600)
    staging.rename(destination)
    return destination


def install_amass(binary):
    """Use the verified legacy binary, avoiding old libraries on new Go compilers."""
    destination = binary / 'amass'
    if destination.is_file() and hashlib.sha256(destination.read_bytes()).hexdigest() == AMASS['binary_sha256']:
        print('Verified existing Amass 4.2.0 binary.')
        return
    with tempfile.TemporaryDirectory(prefix='.amass-', dir=binary.parent) as temp:
        archive = Path(temp) / 'amass.zip'
        with urllib.request.urlopen(AMASS['url'], timeout=30) as response, archive.open('wb') as output:
            shutil.copyfileobj(response, output)
        with zipfile.ZipFile(archive) as source:
            names = [name for name in source.namelist() if Path(name).name == 'amass']
            if len(names) != 1:
                raise RuntimeError('Unexpected Amass release archive layout.')
            data = source.read(names[0])
        if hashlib.sha256(data).hexdigest() != AMASS['binary_sha256']:
            raise RuntimeError('Amass binary checksum mismatch; existing binary preserved.')
        staging = Path(temp) / 'amass'
        staging.write_bytes(data)
        staging.chmod(0o755)
        staging.replace(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='Show setup plan without changing files or downloading')
    parser.add_argument('--system', action='store_true', help='Install OS packages using the detected Linux package manager (uses sudo)')
    parser.add_argument('--system-only', action='store_true', help='Install only OS dependencies; no provider Python environment or tool builds')
    parser.add_argument('--package-manager', choices=['auto', *MANAGERS], default='auto', help='Override automatic package-manager detection; --plan can preview other managers')
    parser.add_argument('--python', default=os.environ.get('RECONATOR_PROVIDER_PYTHON'), help='Python 3.12 interpreter; auto-detects working system/pyenv/provider interpreters by default')
    args = parser.parse_args()
    args.system = args.system or args.system_only
    plan = package_plan(args.package_manager) if args.plan or args.system else None
    if args.plan:
        print(json.dumps({'platform': 'Linux x86_64; Bash >=5; Python 3.12 for providers', 'system': plan, 'amass': AMASS,
                          'go': GO_TOOLS, 'providers': PROVIDERS, 'python': args.python or 'auto (verified Python 3.12)'}, indent=2))
        return 0
    if sys.platform != 'linux':
        raise RuntimeError('Automatic setup supports Linux only.')
    if platform.machine().lower() not in {'x86_64', 'amd64'}:
        raise RuntimeError('Automatic setup supports x86_64 only; configure external tools manually on other architectures.')
    if os.geteuid() == 0:
        raise RuntimeError('Run as your regular user; --system uses sudo only for OS packages.')
    if args.system and (not plan.get('manager') or not plan.get('available')):
        raise RuntimeError(plan.get('error', 'Selected package manager is not installed.'))
    if args.system_only:
        unavailable = install_system(plan, run)
        print('OS dependency installation finished. Provider environments and tool builds were not installed.')
        if unavailable:
            raise RuntimeError('Tools still need manual installation: ' + ', '.join(unavailable))
        return 0
    # Check the required interpreter before making any system/package changes.
    python = resolve_python(ROOT, args.python)
    print(f'Using verified provider Python: {python}')
    if args.system:
        install_system(plan, run)
    for tool in ['git', 'go']:
        if not shutil.which(tool):
            raise RuntimeError(f'{tool} missing; install prerequisites first (see README).')
    tools = ROOT / 'tools'
    tools.mkdir(exist_ok=True)
    # Serialize installations without deleting an existing user's lock.
    lock = tools / '.install.lock'
    lock.mkdir()
    try:
        binary = tools / 'bin'
        binary.mkdir(exist_ok=True)
        env = dict(os.environ, GOBIN=str(binary))
        for package in GO_TOOLS.values():
            run(['go', 'install', package], env=env)
        install_amass(binary)
        for name, (url, commit) in PROVIDERS.items():
            directory = checkout(name, url, commit)
            venv_python = directory / '.venv/bin/python'
            if not venv_python.exists():
                run([python, '-m', 'venv', directory / '.venv'])
            run([venv_python, '-c', 'import sys; assert sys.version_info[:2] == (3,12), "Existing venv must use Python 3.12"'])
            run([venv_python, '-m', 'pip', 'install', '-r', ROOT / 'setup' / (name.lower() + '-requirements.txt')])
            run([venv_python, '-m', 'pip', 'check'])
            if name == 'Sudomy':
                api = directory / 'sudomy.api'
                if api.exists():
                    api.chmod(0o600)
                # Keep upstream/source license and local configuration intact.
        (tools / 'setup-versions.json').write_text(json.dumps({'go': GO_TOOLS, 'amass': AMASS, 'providers': PROVIDERS}, indent=2) + '\n')
        run([ROOT / 'reconator', 'doctor'])
        print('Setup checks passed. Configure your API keys locally. Doctor does not validate live services.')
    finally:
        lock.rmdir()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Setup failed: {error}', file=sys.stderr)
        sys.exit(1)
