"""Saved fixtures exercise real parsers and native curl against an owned local API."""
import functools
import http.server
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

project = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project/'lib'))
import report

with tempfile.TemporaryDirectory(dir=os.environ.get('RECONATOR_TEST_TMPDIR')) as temp:
    folder=Path(temp); fixture=project/'tests/fixtures'
    (folder/'nmap.xml').write_bytes((fixture/'nmap.xml').read_bytes())
    ports, scripts=report.nmap_data(folder)
    (folder/'nmap.actual.txt').write_text('\n'.join(ports)+'\n')
    subprocess.run(['diff','-u',str(fixture/'nmap.expected.txt'),str(folder/'nmap.actual.txt')],check=True)
    assert scripts[0][0]=='http-server-header'
    result=subprocess.run(['bash','-c','source "$1/main.sh"; parse_whois "$2"','test',str(project),str(fixture/'whois.txt')],capture_output=True,text=True,check=True)
    (folder/'whois.actual.txt').write_text(result.stdout)
    subprocess.run(['diff','-u',str(fixture/'whois.expected.txt'),str(folder/'whois.actual.txt')],check=True)
    (folder/'domain.txt').write_text('example.com\n');(folder/'mode.txt').write_text('web\n')
    (folder/'http.txt').write_bytes((fixture/'http.txt').read_bytes())
    import state
    state.record(folder,'http','success','0','http.txt')
    report.build(folder)
    data=json.loads((folder/'reports/report.json').read_text())
    assert data['findings'][0]['evidence']==(fixture/'http.txt').read_text().strip()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            self.wfile.write(b'["www.example.com","badexample.com","www.example.com"]')
        def log_message(self,*args): pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        env={**os.environ,'CROBAT_API_BASE':f'http://127.0.0.1:{server.server_port}','NO_PROXY':'127.0.0.1'}
        subprocess.run(['bash','-c','source "$1/main.sh"; root_domain=example.com; scan_dir="$2"; provider_run crobat','test',str(project),str(folder)],env=env,check=True,capture_output=True)
        assert report.provider_data(folder,'crobat')[0]==['www.example.com']
    finally: server.shutdown();server.server_close();thread.join()
print('PASS: saved Nmap/WHOIS/header parser fixtures and real curl against an owned local API; no external targets.')
