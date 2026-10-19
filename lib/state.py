#!/usr/bin/env python3
import csv
import os
import sys
from pathlib import Path


def atomic(path, text):
    temp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    temp.write_text(text)
    temp.replace(path)


def record(scan, name, status, code, evidence='-'):
    state = scan / 'state'
    state.mkdir(parents=True, exist_ok=True)
    atomic(state / (name + '.exit'), str(code) + '\n')
    atomic(state / (name + '.status'), status + '\n')
    atomic(state / (name + '.files'), evidence + '\n')
    marker = state / (name + '.ok')
    if status in ('success', 'no_data'):
        marker.touch()
    else:
        marker.unlink(missing_ok=True)
    rows = []
    for file in sorted(state.glob('*.status')):
        n = file.stem
        rows.append([n, file.read_text().strip(), (state / (n + '.exit')).read_text().strip(),
                     (state / (n + '.files')).read_text().strip()])
    import io
    data = io.StringIO()
    writer = csv.writer(data, delimiter='\t', lineterminator='\n')
    writer.writerow(['module', 'status', 'exit_code', 'files'])
    writer.writerows(rows)
    atomic(scan / 'manifest.tsv', data.getvalue())


if __name__ == '__main__':
    record(Path(sys.argv[1]), *sys.argv[2:])
