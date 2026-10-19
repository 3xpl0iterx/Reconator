#!/usr/bin/env python3
import ipaddress
import re
import sys
from urllib.parse import urlsplit
from pathlib import Path


def domain(value, require_dot=True):
    value = value.lower()
    if len(value) > 253 or (require_dot and '.' not in value) or value.split('.')[-1].isdigit():
        raise ValueError('Enter a valid bare domain with at least two labels')
    for label in value.split('.'):
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            raise ValueError('Domain labels must be 1–63 letters/digits/hyphens without edge hyphens')
    return value


def normalize(value):
    if not value or any(c.isspace() for c in value) or value.startswith('-'):
        raise ValueError('Invalid target')
    if value.startswith(('http://', 'https://')):
        parsed = urlsplit(value)
        if parsed.username or parsed.password or not parsed.hostname:
            raise ValueError('Target URLs must not contain credentials')
        if parsed.port not in (None, 80, 443):
            raise ValueError('Custom URL ports are not supported yet; use a bare host')
        value = parsed.hostname
    elif value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return domain(value, require_dot=False)


def entries(file):
    return [line.strip() for line in Path(file).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def within(host, rule):
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        rule = domain(rule)
        return host == rule or host.endswith('.' + rule)


if __name__ == '__main__':
    try:
        command, value = sys.argv[1:3]
        if command == 'normalize': print(normalize(value))
        elif command == 'domain': print(domain(value))
        elif command == 'ip': print(ipaddress.ip_address(value))
        elif command == 'filter':
            hosts = sorted(set(normalize(v) for v in entries(value)))
            scope = entries(sys.argv[3]) if sys.argv[3] else []
            excluded = entries(sys.argv[4]) if sys.argv[4] else []
            # Validate every rule before any network work starts.
            for rule in scope + excluded:
                try: ipaddress.ip_network(rule, strict=False)
                except ValueError: domain(rule)
            for host in hosts:
                if scope and not any(within(host, rule) for rule in scope):
                    raise ValueError(f'Target outside supplied scope: {host}')
                if not any(within(host, rule) for rule in excluded): print(host)
    except (ValueError, OSError, IndexError) as exc:
        print(f'[-] {exc}', file=sys.stderr)
        sys.exit(2)
