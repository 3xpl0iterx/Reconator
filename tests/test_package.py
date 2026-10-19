"""Verify source distribution, permissions and clean-checkout CLI."""
import hashlib
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packager', root/'scripts/package.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)
with tempfile.TemporaryDirectory() as temp:
    destination = Path(temp)
    archive = packager.build(destination)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive.with_suffix('.zip.sha256').read_text().startswith(digest)
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        assert any(name.endswith('/LICENSE') for name in names)
        assert any(name.endswith('/setup/install.py') for name in names)
        assert not any('/tools/' in name or '/results/' in name or '/work/' in name or '__pycache__' in name for name in names)
        source.extractall(destination/'unpacked')
        for entry in source.infolist():
            os.chmod(destination/'unpacked'/entry.filename, (entry.external_attr >> 16) & 0o777)
    checkout = next((destination/'unpacked').iterdir())
    env = dict(os.environ, RECONATOR_TOOL_BIN=str(destination/'empty'), RECONATOR_RESULTS=str(destination/'results'))
    result = subprocess.run([str(checkout/'reconator'), '--help'], cwd=destination, env=env, capture_output=True, text=True)
    assert result.returncode == 0 and 'Full Recon' in result.stdout, result
    result = subprocess.run(['python3', str(checkout/'setup/install.py'), '--plan'], cwd=destination, env=env, capture_output=True)
    assert result.returncode == 0
    subprocess.run(['python3', str(checkout/'tests/test_cli.py')], cwd=destination, env=env, check=True, timeout=180)
print('Source archive, permissions and clean-checkout mocked integrations passed.')
