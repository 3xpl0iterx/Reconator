"""Offline CLI, parser and integration regression tests. All network tools mocked."""
from pathlib import Path
import json
import os
import subprocess
import tempfile

project = Path(__file__).resolve().parents[1]


def run(args, env, cwd, expected=0, input=None):
    result = subprocess.run([str(project/'reconator'), *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=30, input=input)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    return result


with tempfile.TemporaryDirectory(dir=os.environ.get('RECONATOR_TEST_TMPDIR')) as temp:
    t = Path(temp).resolve(); binary = t/'bin'; binary.mkdir(); out = t/'results'; calls = t/'calls'
    mock = r'''#!/usr/bin/env python3
import os, sys, json, time
from pathlib import Path
name = Path(sys.argv[0]).name; args = sys.argv[1:]; fixture=Path(os.environ['FIXTURES'])
with open(os.environ['CALLS'],'a') as f: f.write(name+' '+json.dumps(args)+'\n')
def arg(n): return args[args.index(n)+1]
def write(path,text):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
if name=='theHarvester':
 assert arg('-f').endswith('.json')
 write(str(Path(arg('-f')).with_suffix('.json')),json.dumps({'hosts':['www.example.com','WWW.EXAMPLE.COM','badexample.com','evil.org','mail.example.com:1.2.3.4'],'emails':['person@example.com','other@evil.org'],'ips':['192.0.2.1']}))
 sys.exit(int(os.environ.get('FAIL_HARVESTER','0')))
elif name=='subfinder': write(arg('-o'),'www.example.com\napi.example.com\n')
elif name=='amass':
 if '-h' in args:
  print('Usage: amass enum [options] -d DOMAIN\n  -dir string' + ('\n  -o string\n  -nocolor\n  -passive' if os.environ.get('AMASS_V4') else ''));sys.exit(0)
 if args[0]=='subs': write(arg('-o'),'www.example.com\namass.example.com\n')
 if args[0]=='enum' and '-o' in args:
  assert '-ip' not in args
  write(arg('-o'),'www.example.com (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n')
elif name=='curl':
 if '-o' in args:
  write(arg('-o'),os.environ.get('CROBAT_RESPONSE','["www.example.com","sonar.example.com"]'))
 else:
  if args[-1].startswith('https:'):
   print('curl: (7) Failed to connect to fixture:443',file=sys.stderr);sys.exit(7)
  print((fixture/'http.txt').read_text().replace('200 OK',os.environ.get('HTTP_STATUS','200 OK')))
elif name=='httpx':
 if '-h' in args: print('ProjectDiscovery probe');sys.exit(0)
 write(arg('-o'),'http://example.com\n')
elif name=='nmap':
 if os.environ.get('SLEEP_NMAP'): time.sleep(20)
 write(arg('-oN'),'PORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http\n135/tcp filtered msrpc\n')
 write(arg('-oX'),(fixture/'nmap.xml').read_text())
elif name=='nuclei': write(arg('-o'),(fixture/'nuclei.jsonl').read_text())
elif name=='nikto': write(arg('-output'),(fixture/'nikto.json').read_text())
elif name=='whois': print('No recognized fields' if os.environ.get('WHOIS_EMPTY') else (fixture/'whois.txt').read_text())
elif name=='ping': sys.exit(1 if os.environ.get('PING_NO_REPLY') else 0)
elif name=='dig': print(';; ANSWER SECTION:\nexample.com. 60 IN A 192.0.2.1')
elif name=='ffuf': write(arg('-o'),json.dumps({'results':[{'url':'http://example.com/test','status':200}]}))
else: raise RuntimeError('Unmocked tool: '+name)
'''
    for name in ['theHarvester','subfinder','amass','curl','httpx','nmap','nuclei','nikto','whois','ping','dig','ffuf']:
        file=binary/name;file.write_text(mock);file.chmod(0o755)
    one=t/'oneforall.py';one.write_text("import sys,json\nfrom pathlib import Path\nassert sys.argv[sys.argv.index('--brute')+1]=='False'\nassert sys.argv[sys.argv.index('--req')+1]=='False'\nassert sys.argv[sys.argv.index('--takeover')+1]=='False'\nPath(sys.argv[sys.argv.index('--path')+1]).write_text(json.dumps([{'subdomain':'one.example.com'},{'subdomain':'www.example.com'}]))\n")
    sud=t/'sudomy';sud.write_text('#!/bin/bash\n[[ "$3" == --no-probe ]] || exit 90\nmkdir -p "$5/export/example.com"\nprintf "sudomy.example.com\\nwww.example.com\\n" > "$5/export/example.com/subdomain.txt"\n')
    env={**os.environ,'RECONATOR_TOOL_BIN':str(binary),'PATH':f'{binary}:'+os.environ['PATH'],'CALLS':str(calls),
         'FIXTURES':str(project/'tests/fixtures'),'ONEFORALL_PYTHON':'python3','ONEFORALL_SCRIPT':str(one),'SUDOMY_SCRIPT':str(sud)}
    run(['--help'],env,t);run(['--version'],env,t)
    result=run([],{**env,'RECONATOR_RESULTS':str(t/'menu')},t,input='03\nexample.com\nwww.example.com\nN\n\n99\n\n00\n')
    assert 'VPN' not in result.stdout and 'Proton' not in result.stdout
    assert 'Reports:' in result.stdout and 'Created by 3xpl0iter' in result.stdout and 'curl: (7)' not in result.stdout+result.stderr
    menu_scan=next((t/'menu/example.com').iterdir());assert (menu_scan/'reports/report.json').exists()
    base=['scan','-d','example.com','--mode','subdomains','--providers','all','--output',str(out),'--resume']
    run(base,env,t); scan=next((out/'example.com').iterdir());summary=json.loads((scan/'reports/report.json').read_text())
    assert summary['unique_subdomains']==7,summary
    assert 'badexample.com' not in (scan/'subdomains_uniq.txt').read_text()
    before=calls.read_text();run(base,env,t);assert calls.read_text()==before,'successful phases reran'
    (scan/'state/theharvester.ok').unlink();run(base,{**env,'FAIL_HARVESTER':'7'},t,1)
    summary=json.loads((scan/'reports/report.json').read_text());assert summary['phases']['theharvester']['status']=='failed'
    failed_tool=json.loads((scan/'reports/tools/theharvester/report.json').read_text());assert failed_tool['phase']['status']=='failed' and not failed_tool['findings']
    run(base,env,t);assert (scan/'state/theharvester.ok').exists()
    run(base,{**env,'HARVESTER_LIMIT':'250'},t);assert list((scan/'archive').iterdir())
    run(base,env,t)
    for args in [['-d','-bad.example.com'],['-d','bad-.example.com'],['-d','example.com','--providers','oops'],
                 ['-d','example.com','--nmap-only','--nikto-only'],['-d','example.com','--severity','madeup'],
                 ['-d','example.com','--jobs','9'],['-d','example.com','--timeout','0']]:
        run(['scan',*args,'--output',str(out)],env,t,2)
    (t/'targets.txt').write_text('Example.com\nexample.com\n# comment\n\n')
    before=calls.read_text();run(['enum','-t','targets.txt','--providers','subfinder','--output','relative-output'],env,t)
    assert calls.read_text()[len(before):].count('subfinder ')==1
    assert (t/'relative-output/example.com').exists()
    (t/'scope.txt').write_text('example.com\n192.0.2.0/24\n');(t/'exclude.txt').write_text('blocked.example.com\n')
    run(['active','-d','evil.org','--scope',str(t/'scope.txt'),'--output',str(out)],env,t,2)
    run(['active','-d','blocked.example.com','--exclude',str(t/'exclude.txt'),'--output',str(out)],env,t,2)
    run(['active','-d','192.0.2.1','--scope',str(t/'scope.txt'),'--output',str(out)],env,t)
    web_out=t/'web';result=run(['web','-d','example.com','--output',str(web_out)],env,t)
    assert 'curl: (7)' not in result.stdout+result.stderr
    assert 'HTTPS unavailable; trying HTTP.' in result.stdout
    web=next((web_out/'example.com').iterdir()); data=json.loads((web/'reports/report.json').read_text())
    assert data['severity_counts']['critical']==1 and data['severity_counts']['high']==1,data
    assert data['severity_counts']['medium']==2 and data['severity_counts']['low']==1,data
    assert data['severity_counts']['unknown']>=2,data
    assert any(row['source']=='nikto' and 'Critical keyword' in row['name'] and row['severity']=='unknown' for row in data['findings'])
    assert 'curl: (7)' in (web/'http-errors.log').read_text()
    nuclei_args=[line for line in calls.read_text().splitlines() if line.startswith('nuclei ')][-1]
    assert '-severity' not in nuclei_args,'all severity still filtered'
    run(['http','-d','example.com','--output',str(t/'404')],{**env,'HTTP_STATUS':'404 Not Found'},t)
    run(['full','-d','example.com','--target','www.example.com','--directory','--wordlist',str(project/'tests/fixtures/whois.txt'),'--output',str(t/'full')],env,t)
    full=next((t/'full/example.com').iterdir());data=json.loads((full/'reports/report.json').read_text())
    assert {'subfinder','theharvester','oneforall','sudomy','amass','crobat','ping','nmap','http','whois','dns','httpx','nuclei','nikto','directory'}<=set(data['phases'])
    assert data['phases']['directory']['completed'];assert (full/'manifest.tsv').exists()
    for module in data['phases']:
        tool={'http':'curl','dns':'dig','directory':'ffuf'}.get(module,module)
        folder=full/'reports/tools'/tool
        per_tool=json.loads((folder/'report.json').read_text())
        assert per_tool['module']==module
        assert (folder/'report.md').exists() and (folder/'findings.csv').exists()
        for level in ['critical','high','medium','low','info','unknown']:
            items=json.loads((folder/(level+'.json')).read_text())
            assert all(row['severity']==level for row in items)
    assert (full/'reports/tools/index.md').exists()
    assert json.loads((full/'reports/tools/nuclei/critical.json').read_text())
    assert json.loads((full/'reports/tools/nikto/unknown.json').read_text())
    assert any(row['matched_at']=='www.example.com' for row in json.loads((full/'reports/tools/subfinder/info.json').read_text()))

    run(['directory','-d','example.com','--directory','--wordlist',str(t/'missing'),'--output',str(t/'skip')],env,t)
    skip=next((t/'skip/example.com').iterdir());assert (skip/'state/directory.status').read_text().strip()=='skipped'
    run(['passive','-d','example.com','--providers','subfinder','--output',str(t/'no-data')],{**env,'WHOIS_EMPTY':'1'},t)
    nd=next((t/'no-data/example.com').iterdir());assert (nd/'state/whois.status').read_text().strip()=='no_data'
    run(['scan','-d','example.com','--nmap-only','--timeout','1','--output',str(t/'timeout')],{**env,'SLEEP_NMAP':'1'},t,1)
    timeout=next((t/'timeout/example.com').iterdir());assert (timeout/'state/nmap.status').read_text().strip()=='timeout'
    run(['enum','-d','example.com','--providers','crobat','--output',str(out)],{**env,'CROBAT_RESPONSE':'<html>Error</html>'},t,1)
    (scan/'.lock').mkdir();run(base,env,t,1);(scan/'.lock').rmdir()
    (t/'batch.txt').write_text('example.com\nother.example.com\n')
    run(['enum','-t',str(t/'batch.txt'),'--providers','subfinder','--jobs','2','--output',str(t/'batch')],env,t)
    run(['enum','-d','example.com','--providers','amass','--amass-ip','--output',str(t/'amass-v4')],{**env,'AMASS_V4':'1'},t)
    av4=next((t/'amass-v4/example.com').iterdir());assert '192.0.2.1' in (av4/'providers/amass/hosts-with-ip.txt').read_text()
    run(['compare',str(web),str(web)],env,t);assert (web/'reports/comparison.json').exists()
    legacy=t/'example.com/legacy';legacy.mkdir(parents=True);old='www.example.com\nwww.example.com\n';(legacy/'subdomains.txt').write_text(old)
    run(['report',str(legacy)],env,t);assert (legacy/'subdomains.txt').read_text()==old
    for file in [project/'main.sh',project/'reconator',*(project/'lib').glob('*.sh')]: subprocess.run(['bash','-n',str(file)],check=True)
    print('PASS: all providers, Full Recon integration, severity/dedup/provenance, HTTP fallback/404, manifests, resume/failure retries, validation/scope/exclusions/IPs, wordlists/no-data/timeouts, batch concurrency, comparison and legacy preservation. All network tools mocked.')
