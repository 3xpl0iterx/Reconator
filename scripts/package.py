#!/usr/bin/env python3
"""Build a source-only archive from an explicit allowlist."""
from pathlib import Path
import argparse
import hashlib
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ['main.sh', 'reconator', 'README.md', 'CHANGELOG.md', 'LICENSE', '.gitignore']
DIRECTORIES = ['lib', 'tests', 'setup', 'scripts', '.github']
FORBIDDEN = {'.env', 'slack.conf', 'sudomy.api'}


def build(destination):
    version = re.search(r"VERSION='([^']+)'", (ROOT / 'main.sh').read_text()).group(1)
    paths = [ROOT / name for name in FILES]
    for directory in DIRECTORIES:
        paths.extend(path for path in (ROOT / directory).rglob('*') if path.is_file()
                     and '__pycache__' not in path.parts and path.suffix not in {'.pyc', '.log', '.tmp'})
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f'Reconator-{version}-source.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
        for path in sorted(paths):
            if path.is_symlink():
                raise ValueError(f'Refusing symlink in source release: {path}')
            if path.name in FORBIDDEN or path.name.startswith('.env.') or path.suffix == '.api':
                raise ValueError(f'Local configuration must not ship: {path}')
            data = path.read_bytes()
            # Additional defense, not an exhaustive credential audit.
            if re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}', data):
                raise ValueError(f'Possible credential in release: {path}')
            info = zipfile.ZipInfo('Reconator-' + version + '/' + path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if path.stat().st_mode & 0o111 else 0o100644) << 16
            output.writestr(info, data)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(digest + '  ' + archive.name + '\n')
    print(archive)
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    build(parser.parse_args().destination.resolve())
