#!/usr/bin/env python3
"""Offline evidence normalization: severity is never inferred from a keyword."""
import collections
import csv
import hashlib
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import state
from tool_reports import write_tools

PROVIDERS = {'subfinder', 'amass', 'crobat', 'theharvester', 'oneforall', 'sudomy'}
SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown']


def read(path):
    return path.read_text(errors='replace')


def host_name(value, root):
    if not isinstance(value, str): return None
    value = value.strip().lower().rstrip('.')
    value = value.split(':', 1)[0].split()[0] if value else ''
    if len(value) > 253: return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')): return None
    return value if value == root or value.endswith('.' + root) else None


def provider_data(scan, name):
    folder = scan / 'providers' / name
    root = read(scan / 'domain.txt').strip() if (scan / 'domain.txt').exists() else scan.parent.name
    observations = []
    if name in ('subfinder', 'amass', 'crobat'):
        values = read(folder / 'subdomains.txt').splitlines()
        if name == 'amass' and (folder / 'hosts-with-ip.txt').exists():
            for line in read(folder / 'hosts-with-ip.txt').splitlines():
                if line.strip(): observations.append(('Discovered address association', line))
    elif name == 'theharvester':
        data = json.loads(read(folder / 'results.json'))
        if not isinstance(data, dict) or not isinstance(data.get('hosts', []), list): raise ValueError('Invalid theHarvester export')
        values = data.get('hosts', [])
        for key in ('emails', 'ips'):
            for value in data.get(key, []):
                if not isinstance(value, str): continue
                if key == 'emails' and not value.lower().endswith('@' + root): continue
                if key == 'ips':
                    try: ipaddress.ip_address(value)
                    except ValueError: continue
                observations.append((f'Discovered {key[:-1]}', value))
    elif name == 'oneforall':
        data = json.loads(read(folder / 'results.json'))
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data): raise ValueError('OneForAll export must be a row list')
        values = [row.get('subdomain', '') for row in data]
    else:
        files = list(folder.rglob('subdomain.txt'))
        if not files: raise FileNotFoundError('Sudomy subdomain.txt export missing')
        values = [line for file in files for line in read(file).splitlines()]
    return sorted(set(host for value in values if (host := host_name(value, root)))), observations


def nmap_data(scan):
    ports, scripts = [], []
    if (scan / 'nmap.xml').exists():
        root = ET.fromstring(read(scan / 'nmap.xml'))
        if root.tag != 'nmaprun': raise ValueError('Unexpected Nmap XML root')
        for host in root.findall('host'):
            for port in host.findall('ports/port'):
                status = port.find('state')
                if status is not None and status.get('state') == 'open':
                    service = port.find('service')
                    ports.append(f"{port.get('portid')}/{port.get('protocol')} " + (' '.join(service.get(key, '') for key in ('name', 'product', 'version', 'extrainfo')).strip() if service is not None else ''))
                for script in port.findall('script'):
                    scripts.append((script.get('id', ''), script.get('output', ''), port.get('portid', ''), any((elem.text or '').strip().upper() == 'VULNERABLE' for elem in script.findall('.//elem[@key="state"]'))))
            for script in host.findall('hostscript/script'):
                scripts.append((script.get('id', ''), script.get('output', ''), 'host', any((elem.text or '').strip().upper() == 'VULNERABLE' for elem in script.findall('.//elem[@key="state"]'))))
    else:
        for line in read(scan / 'nmap.txt').splitlines():
            match = re.match(r'^(\d+/(?:tcp|udp))\s+open\s+(.+)', line)
            if match: ports.append(match.group(1) + ' ' + match.group(2))
    return ports, scripts


def rows_json(path):
    data = json.loads(read(path))
    if isinstance(data, dict): return [data]
    if isinstance(data, list) and all(isinstance(row, dict) for row in data): return data
    raise ValueError('JSON export must be an object or object list')


def validate(scan, name):
    if name in PROVIDERS:
        domains, observations = provider_data(scan, name)
        return bool(domains or observations)
    if name == 'nmap':
        ports, scripts = nmap_data(scan)
        return bool(ports or scripts)
    if name == 'nuclei':
        lines = [line for line in read(scan / 'nuclei.jsonl').splitlines() if line.strip()]
        for line in lines:
            data = json.loads(line)
            if not isinstance(data, dict) or not isinstance(data.get('info'), dict): raise ValueError('Invalid Nuclei finding')
        return bool(lines)
    if name == 'nikto': return any(row.get('vulnerabilities', []) for row in rows_json(scan / 'nikto.json'))
    if name == 'directory':
        data = json.loads(read(scan / 'directories.json'))
        if not isinstance(data, dict) or not isinstance(data.get('results'), list): raise ValueError('Invalid ffuf export')
        return bool(data['results'])
    if name == 'httpx': return bool(read(scan / 'live.txt').strip())
    if name == 'http':
        text = read(scan / 'http.txt').strip()
        if text and not re.search(r'^HTTP/[0-9.]+ [0-9]{3}', text, re.M): raise ValueError('Invalid HTTP header export')
        return bool(text)
    if name in ('whois', 'dns'): return bool(read(scan / (name + '.txt')).strip())
    return True


def escape(text):
    text = str(text).replace('\n', ' ')
    for character in '\\`*[]<>|': text = text.replace(character, '\\' + character)
    return text


def build(scan):
    legacy = not (scan / 'domain.txt').exists()
    domain = read(scan / 'domain.txt').strip() if not legacy else scan.parent.name
    target = read(scan / 'target.txt').strip() if (scan / 'target.txt').exists() else domain
    statuses = {}
    for file in sorted((scan / 'state').glob('*.exit')):
        name = file.stem
        code = int(read(file))
        status_file = file.with_suffix('.status')
        status = read(status_file).strip() if status_file.exists() else ('success' if (file.with_suffix('.ok')).exists() else 'failed')
        statuses[name] = {'status': status, 'exit_code': code, 'completed': status in ('success', 'no_data'),
                          'evidence': read(file.with_suffix('.files')).strip() if file.with_suffix('.files').exists() else f'logs/{name}.log'}
    evidence = collections.defaultdict(set)
    findings, warnings = [], []

    def add(source, name, value, severity='info', category='observation', template='', matched='', cvss=None):
        severity = str(severity).lower()
        if severity not in SEVERITIES: severity = 'unknown'
        findings.append({'source': source, 'name': str(name), 'severity': severity,
                         'category': category, 'template_id': template, 'matched_at': matched or target,
                         'evidence': str(value), 'cvss_score': cvss, 'requires_verification': category == 'potential_vulnerability',
                         'partial': statuses.get(source, {}).get('status') == 'interrupted'})

    def parse(name, action):
        # Parse successful or interrupted evidence; never reuse stale failed output.
        if not legacy and name not in statuses: return
        if name in statuses and statuses[name]['status'] not in ('success', 'no_data', 'interrupted'): return
        start = len(findings)
        old_evidence = {host: set(providers) for host, providers in evidence.items()}
        try: action()
        except (OSError, ValueError, TypeError, AttributeError, ET.ParseError) as exc:
            warnings.append(f'{name}: {exc}')
            if statuses.get(name, {}).get('status') != 'interrupted':
                del findings[start:]
                evidence.clear(); evidence.update(old_evidence)
            if name in statuses and statuses[name]['completed']:
                state.record(scan, name, 'failed', '65', f'logs/{name}.log')
                statuses[name].update(status='failed', exit_code=65, completed=False)

    for folder in sorted((scan / 'providers').glob('*')):
        name = folder.name
        if name not in PROVIDERS: continue
        def provider(name=name):
            hosts, extras = provider_data(scan, name)
            for host in hosts: evidence[host].add(name)
            for label, value in extras: add(name, label, value)
        parse(name, provider)
    if legacy and (scan / 'subdomains.txt').exists():
        for value in read(scan / 'subdomains.txt').splitlines():
            if host := host_name(value, domain): evidence[host].add('legacy-import')
    for host, providers in evidence.items(): add(','.join(sorted(providers)), 'Discovered asset', host, category='asset', matched=host)

    def nuclei():
        for line in read(scan / 'nuclei.jsonl').splitlines():
            if not line.strip(): continue
            raw = json.loads(line); info = raw['info']
            add('nuclei', info.get('name', 'Unnamed template'), raw.get('matched-at', ''), info.get('severity', 'unknown'),
                'potential_vulnerability', raw.get('template-id', ''), raw.get('matched-at', target), info.get('classification', {}).get('cvss-score'))
    if (scan / 'nuclei.jsonl').exists(): parse('nuclei', nuclei)
    def nikto():
        for row in rows_json(scan / 'nikto.json'):
            for item in row.get('vulnerabilities', []):
                if not isinstance(item, dict): raise ValueError('Invalid Nikto finding')
                add('nikto', item.get('msg', item.get('message', 'Nikto observation')), json.dumps(item, sort_keys=True),
                    item.get('severity', 'unknown'), 'potential_vulnerability', str(item.get('id', '')), item.get('url', target))
    if (scan / 'nikto.json').exists(): parse('nikto', nikto)
    def nmap():
        ports, scripts = nmap_data(scan)
        for value in ports: add('nmap', 'Open port/service', value)
        for name, output, port, vulnerable in scripts: add('nmap', name, output, 'unknown' if vulnerable else 'info', 'potential_vulnerability' if vulnerable else 'observation', name, f'{target}:{port}')
    if (scan / 'nmap.xml').exists() or (scan / 'nmap.txt').exists(): parse('nmap', nmap)
    for name in ('whois', 'http', 'dns'):
        file = scan / (name + '.txt')
        if file.exists():
            def text(name=name, file=file):
                value = read(file).strip()
                title = {'whois': 'Domain registration', 'http': 'HTTP response headers', 'dns': 'DNS records'}[name]
                if name == 'whois':
                    try:
                        ipaddress.ip_address(domain)
                        title = 'IP registration'
                    except ValueError:
                        pass
                if value: add(name, title, value)
            parse(name, text)
    if (scan / 'live.txt').exists():
        def live():
            for url in read(scan / 'live.txt').splitlines():
                if url.strip(): add('httpx', 'Responsive HTTP endpoint', url.strip(), matched=url.strip())
        parse('httpx', live)
    if (scan / 'directories.json').exists():
        def directory():
            for item in json.loads(read(scan / 'directories.json'))['results']:
                add('directory', 'Discovered HTTP path', f"HTTP {item.get('status', 'unknown')}", matched=item.get('url', target))
        parse('directory', directory)
    if 'ping' in statuses:
        add('ping', 'ICMP reachability observation', statuses['ping']['status'])
    unique = {}
    for row in findings:
        key = tuple(str(row[field]) for field in ('source', 'name', 'matched_at', 'template_id', 'evidence'))
        unique[key] = row
    findings = sorted(unique.values(), key=lambda row: (SEVERITIES.index(row['severity']), row['source'], row['name'], row['matched_at']))
    counts = {severity: sum(row['severity'] == severity for row in findings) for severity in SEVERITIES}
    rows = [{'domain': host, 'providers': sorted(providers)} for host, providers in sorted(evidence.items())]
    incomplete = any(s['status'] in ('failed', 'timeout', 'interrupted', 'running', 'pending') or s['exit_code'] == 127 for s in statuses.values()) or bool(warnings)
    overall = read(scan / 'scan-status.txt').strip() if (scan / 'scan-status.txt').exists() else 'legacy'
    if incomplete and overall == 'complete': overall = 'incomplete'; (scan / 'scan-status.txt').write_text(overall + '\n')
    summary = {'version': read(scan / 'version.txt').strip() if (scan / 'version.txt').exists() else 'legacy', 'domain': domain, 'target': target, 'mode': read(scan / 'mode.txt').strip() if (scan / 'mode.txt').exists() else 'legacy',
               'status': overall, 'coverage_complete': not incomplete and not legacy and not any(s['status'] == 'skipped' for s in statuses.values()), 'unique_subdomains': len(rows),
               'phases': statuses, 'severity_counts': counts, 'subdomains': rows, 'findings': findings, 'warnings': warnings}
    reports = scan / 'reports'; reports.mkdir(exist_ok=True)
    merged = reports if legacy else scan
    state.atomic(merged / 'subdomains_uniq.txt', ''.join(row['domain'] + '\n' for row in rows))
    if not legacy: state.atomic(scan / 'subdomains.txt', ''.join(row['domain'] + '\n' for row in rows for _ in row['providers']))
    state.atomic(reports / 'report.json', json.dumps(summary, indent=2) + '\n')
    for severity in SEVERITIES:
        state.atomic(reports / (severity + '.json'), json.dumps([row for row in findings if row['severity'] == severity], indent=2) + '\n')
    with (reports / 'subdomains.csv').open('w', newline='') as file:
        writer = csv.writer(file); writer.writerow(['domain', 'providers']); writer.writerows((row['domain'], ','.join(row['providers'])) for row in rows)
    def csv_safe(value):
        return "'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else value
    with (reports / 'findings.csv').open('w', newline='') as file:
        fields = ['source', 'name', 'severity', 'category', 'template_id', 'matched_at', 'evidence', 'cvss_score', 'requires_verification', 'partial']
        writer = csv.DictWriter(file, fieldnames=fields); writer.writeheader(); writer.writerows({key: csv_safe(value) for key, value in row.items()} for row in findings)
    tool_links = write_tools(reports, summary)
    lines = ['# Reconator report', '', f'Domain: {escape(domain)}', f'Active target: {escape(target)}', f'Status: {overall}',
             f'Unique in-scope assets: {len(rows)}', '', '| Module | Status | Exit | Evidence |', '|---|---|---|---|']
    lines += [f'| {name} | {status["status"]} | {status["exit_code"]} | {status["evidence"]} |' for name, status in statuses.items()]
    lines += ['', 'Reported severity is retained where available. Asset/port/header observations are informational. Unknown findings require review; severity and CVSS are not guessed.', '']
    for severity in SEVERITIES:
        lines += [f'## {severity.capitalize()} ({counts[severity]})', '']
        for row in findings:
            if row['severity'] == severity:
                lines += [f'- **{escape(row["name"])}** ({escape(row["source"])}) — {escape(row["matched_at"])}',
                          '  Evidence: ' + escape(row['evidence'])[:2000]]
        lines += ['']
    lines += ['## Reports by tool', ''] + tool_links + ['']
    if warnings: lines += ['## Parser warnings', ''] + ['- ' + escape(w) for w in warnings]
    state.atomic(reports / 'report.md', '\n'.join(lines) + '\n')
    print(f'[+] Scan {overall}: {len(rows)} unique assets; {len(findings)} observations/findings')
    print('[+] Severity: ' + ', '.join(f'{name}={count}' for name, count in counts.items()))
    print(f'[+] Reports: {reports}/report.md, report.json, findings.csv')
    print(f'[+] Per-tool reports: {reports}/tools/index.md')
    return bool(warnings)


def compare(a, b):
    before = json.loads(read(a / 'reports/report.json')); after = json.loads(read(b / 'reports/report.json'))
    if before['domain'] != after['domain'] or before.get('target') != after.get('target'): raise ValueError('Compare scans of the same root and active target')
    old = {row['domain'] for row in before['subdomains']}; new = {row['domain'] for row in after['subdomains']}
    def keys(data): return {json.dumps({k: row.get(k) for k in ('source', 'name', 'matched_at', 'template_id', 'evidence')}, sort_keys=True) for row in data['findings']}
    old_findings, new_findings = keys(before), keys(after)
    data = {'added_assets': sorted(new - old), 'removed_assets': sorted(old - new),
            'added_findings': [json.loads(row) for row in sorted(new_findings - old_findings)],
            'removed_findings': [json.loads(row) for row in sorted(old_findings - new_findings)],
            'coverage_warning': not before.get('coverage_complete') or not after.get('coverage_complete')}
    state.atomic(b / 'reports/comparison.json', json.dumps(data, indent=2) + '\n')
    print(json.dumps(data, indent=2))
    if data['coverage_warning']: print('[!] Incomplete coverage can explain differences; missing evidence does not prove an issue was resolved.')


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'validate': sys.exit(0 if validate(Path(sys.argv[2]), sys.argv[3]) else 3)
        elif sys.argv[1] == 'compare': compare(Path(sys.argv[2]), Path(sys.argv[3]))
        else: sys.exit(int(build(Path(sys.argv[1]))))
    except (OSError, ValueError, KeyError, TypeError, IndexError, ET.ParseError) as exc:
        print(f'[-] Invalid/missing evidence: {exc}', file=sys.stderr); sys.exit(65)
