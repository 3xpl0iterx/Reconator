"""Independent evidence and severity reports for every scheduled module."""
import csv
import re
from pathlib import Path
import json
import state

SEVERITIES = ('critical', 'high', 'medium', 'low', 'info', 'unknown')


def markdown(value):
    value = str(value).replace('\n', ' ')
    for character in '\\`*[]<>|': value = value.replace(character, '\\' + character)
    return value


def csv_safe(value):
    return "'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else value


def write_tools(reports, summary):
    findings, phases = summary['findings'], summary['phases']
    names = set(phases)
    for row in findings: names.update(row['source'].split(','))
    names = sorted(name for name in names if re.fullmatch(r'[a-z0-9_-]+', name))
    index = ['# Reports by tool', '', '| Tool | Status | Critical | High | Medium | Low | Info | Unknown |', '|---|---|---|---|---|---|---|---|']
    links = []
    for name in names:
        tool = {'http': 'curl', 'dns': 'dig', 'directory': 'ffuf'}.get(name, name)
        folder = reports / 'tools' / tool
        folder.mkdir(parents=True, exist_ok=True)
        rows = [row for row in findings if name in row['source'].split(',')]
        counts = {level: sum(row['severity'] == level for row in rows) for level in SEVERITIES}
        phase = phases.get(name, {'status': 'legacy', 'exit_code': None, 'completed': False, 'evidence': '-'})
        data = {'tool': tool, 'module': name, 'domain': summary['domain'], 'target': summary['target'], 'phase': phase,
                'severity_counts': counts, 'findings': rows, 'scan_status': summary['status'],
                'note': 'Empty findings do not prove a clean scan. Review module status and raw evidence.'}
        state.atomic(folder / 'report.json', json.dumps(data, indent=2) + '\n')
        for level in SEVERITIES:
            state.atomic(folder / (level + '.json'), json.dumps([row for row in rows if row['severity'] == level], indent=2) + '\n')
        fields = ['source', 'name', 'severity', 'category', 'template_id', 'matched_at', 'evidence', 'cvss_score', 'requires_verification', 'partial']
        with (folder / 'findings.csv').open('w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows({key: csv_safe(value) for key, value in row.items()} for row in rows)
        lines = [f'# {tool} report', '', f'Status: **{phase["status"]}** (exit {phase["exit_code"]})',
                 f'Target: {markdown(summary["target"])}', f'Raw evidence: {markdown(phase["evidence"])}', '',
                 'Severity is retained when justified by evidence. Assets and normal observations are informational; unclassified issues remain unknown.', '']
        if not rows: lines += ['No normalized findings available. Check the module status and raw evidence; this does not prove there are no issues.', '']
        for level in SEVERITIES:
            lines += [f'## {level.capitalize()} ({counts[level]})', '']
            for row in rows:
                if row['severity'] == level:
                    lines += [f'- **{markdown(row["name"])}** — {markdown(row["matched_at"])}',
                              '  Evidence: ' + markdown(row['evidence'])[:2000]]
            lines += ['']
        state.atomic(folder / 'report.md', '\n'.join(lines) + '\n')
        index.append(f'| [{tool}]({tool}/report.md) | {phase["status"]} | ' + ' | '.join(str(counts[level]) for level in SEVERITIES) + ' |')
        links.append(f'- [{tool}](tools/{tool}/report.md) — {phase["status"]}')
    (reports / 'tools').mkdir(exist_ok=True)
    state.atomic(reports / 'tools/index.md', '\n'.join(index) + '\n')
    return links
