"""Distribution-aware Linux package plans; no changes during detection/planning."""
from pathlib import Path
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET

MANAGERS = {
    'apt': {
        'commands': ('apt-get',),
        'refresh': ('apt-get', 'update'),
        'install': ('apt-get', 'install', '-y', '--no-upgrade'),
        'packages': ('bash', 'git', 'curl', 'jq', 'golang-go', 'build-essential',
                     'pkg-config', 'libpcap-dev', 'nmap', 'whois', 'dnsutils',
                     'iputils-ping', 'python3', 'python3-venv', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theharvester'},
    },
    'dnf': {
        'commands': ('dnf', 'dnf5'),
        'refresh': (),  # DNF refreshes metadata when needed during install/list.
        'install': ('dnf', 'install', '-y'),
        'packages': ('bash', 'git', 'curl', 'jq', 'golang', 'gcc', 'gcc-c++', 'make',
                     'pkgconf-pkg-config', 'libpcap-devel', 'nmap', 'whois',
                     'bind-utils', 'iputils', 'python3', 'python3-pip', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theHarvester'},
    },
    'yum': {
        'commands': ('yum',),
        'refresh': (),
        'install': ('yum', 'install', '-y'),
        'packages': ('bash', 'git', 'curl', 'jq', 'golang', 'gcc', 'gcc-c++', 'make',
                     'pkgconfig', 'libpcap-devel', 'nmap', 'whois', 'bind-utils',
                     'iputils', 'python3', 'python3-pip', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theHarvester'},
    },
    'pacman': {
        'commands': ('pacman',),
        'refresh': (),  # Never use -Sy alone: avoid creating a partial upgrade.
        'install': ('pacman', '-S', '--needed', '--noconfirm'),
        'packages': ('bash', 'git', 'curl', 'jq', 'go', 'base-devel', 'pkgconf',
                     'libpcap', 'nmap', 'whois', 'bind', 'iputils', 'python',
                     'python-pip', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theharvester'},
    },
    'zypper': {
        'commands': ('zypper',),
        'refresh': ('zypper', '--non-interactive', 'refresh'),
        'install': ('zypper', '--non-interactive', 'install'),
        'packages': ('bash', 'git', 'curl', 'jq', 'go', 'gcc', 'gcc-c++', 'make',
                     'pkg-config', 'libpcap-devel', 'nmap', 'whois', 'bind-utils',
                     'iputils', 'python3', 'python3-pip', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theHarvester'},
    },
    'apk': {
        'commands': ('apk',),
        'refresh': ('apk', 'update'),
        'install': ('apk', 'add'),
        'packages': ('bash', 'git', 'curl', 'jq', 'go', 'build-base', 'pkgconf',
                     'libpcap-dev', 'nmap', 'whois', 'bind-tools', 'iputils',
                     'python3', 'py3-pip', 'parallel', 'bc'),
        'optional': {'nikto': 'nikto', 'ffuf': 'ffuf', 'theHarvester': 'theharvester'},
    },
}
FAMILIES = {
    'debian': ('apt',), 'ubuntu': ('apt',), 'kali': ('apt',), 'linuxmint': ('apt',),
    'fedora': ('dnf', 'yum'), 'rhel': ('dnf', 'yum'), 'centos': ('dnf', 'yum'),
    'rocky': ('dnf', 'yum'), 'almalinux': ('dnf', 'yum'), 'amzn': ('dnf', 'yum'),
    'arch': ('pacman',), 'manjaro': ('pacman',),
    'opensuse': ('zypper',), 'opensuse-leap': ('zypper',),
    'opensuse-tumbleweed': ('zypper',), 'suse': ('zypper',), 'sles': ('zypper',),
    'alpine': ('apk',),
}


def read_release(path=Path('/etc/os-release')):
    """Read quoted os-release values without executing shell input."""
    values = {}
    try:
        text = path.read_text()
    except FileNotFoundError:
        return values
    for line in text.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, value = line.split('=', 1)
        parts = shlex.split(value, comments=True)
        values[key] = ' '.join(parts)
    return values


def manager_command(manager, which=shutil.which):
    return next((command for command in MANAGERS[manager]['commands'] if which(command)), None)


def detect_manager(release, which=shutil.which):
    # Prefer the actual distribution, even if a foreign manager is also installed.
    for family in [release.get('ID', ''), *release.get('ID_LIKE', '').split()]:
        if family in FAMILIES:
            return next((name for name in FAMILIES[family] if manager_command(name, which)), None)
    available = [name for name in MANAGERS if manager_command(name, which)]
    # DNF and its YUM compatibility command count as one family.
    if 'dnf' in available and 'yum' in available:
        available.remove('yum')
    return available[0] if len(available) == 1 else None


def package_plan(requested='auto', release=None, which=shutil.which):
    release = read_release() if release is None else release
    manager = detect_manager(release, which) if requested == 'auto' else requested
    if manager is None:
        return {'distribution': release.get('PRETTY_NAME', release.get('ID', 'unknown')),
                'manager': None, 'error': 'No unambiguous supported package manager detected. Use --package-manager or install OS dependencies manually.'}
    spec = MANAGERS[manager]
    command = manager_command(manager, which) or spec['commands'][0]
    install = [command, *spec['install'][1:]]
    refresh = [command, *spec['refresh'][1:]] if spec['refresh'] else []
    return {'distribution': release.get('PRETTY_NAME', release.get('ID', 'unknown')),
            'manager': manager, 'command': command,
            'available': manager_command(manager, which) is not None,
            'packages': list(spec['packages']), 'optional_tools': dict(spec['optional']),
            'refresh': refresh, 'install': install}


def optional_available(manager, command, package, query=subprocess.run):
    """Check exact optional package metadata in the configured repositories."""
    args = {
        'apt': ['apt-cache', 'show', package],
        'dnf': [command, '-q', 'list', package],
        'yum': [command, '-q', 'list', package],
        'pacman': [command, '-Si', package],
        'zypper': [command, '--xmlout', 'search', '--match-exact', '--type', 'package', package],
        'apk': [command, 'search', '--exact', package],
    }[manager]
    result = query(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        return False
    if manager == 'zypper':
        try:
            return any(item.get('name') == package for item in ET.fromstring(result.stdout).iter('solvable'))
        except ET.ParseError:
            return False
    if manager == 'apk':
        return any(line.startswith(package + '-') for line in result.stdout.splitlines())
    return bool(result.stdout.strip())


def install_system(plan, run, which=shutil.which, query=subprocess.run):
    if not plan.get('manager') or not plan.get('available'):
        raise RuntimeError(plan.get('error', 'Selected package manager is not installed.'))
    if not which('sudo'):
        raise RuntimeError('sudo is required for OS packages; install them as an administrator, then omit --system.')
    if plan['refresh']:
        run(['sudo', *plan['refresh']])
    run(['sudo', *plan['install'], *plan['packages']])
    unavailable = []
    packages = []
    for tool, package in plan['optional_tools'].items():
        if which(tool):
            print(f'Already available: {tool}')
        elif optional_available(plan['manager'], plan['command'], package, query):
            packages.append(package)
        else:
            unavailable.append(tool)
            print(f'Not available in configured repositories: {tool} ({package}). Install it separately; doctor will report it missing.')
    if packages:
        run(['sudo', *plan['install'], *packages])
    return unavailable
