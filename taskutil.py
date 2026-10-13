#!/usr/bin/env python3
"""
taskutil — companion utility for the infrastructure around Taskwarrior 2.6.2:
repos, mirrors, servers and hooks. (tw-sanity-check looks after the task
data itself; taskutil looks after everything around it.)

Commands
  taskutil web probe [--port N]   Probe a running tw-web from outside, the way
                                  an attacker would. Exit 0 ok, 1 warnings,
                                  2 failures.

Every command takes --json for machine-readable output (tw-web's Health panel,
timers). Standard library only.
"""
import argparse
import base64
import json
import os
import socket
import subprocess
import sys

__version__ = '0.1.0'

OK, WARN, FAIL = 'ok', 'warn', 'fail'
EVIL_ORIGIN = 'https://evil.example'
EVIL_HOST = 'attacker.example'


# ── helpers ───────────────────────────────────────────────────────────────────

def _tailscale_ips():
    try:
        r = subprocess.run(['tailscale', 'ip'], capture_output=True, text=True, timeout=5)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _local_ips():
    try:
        r = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5)
        return r.stdout.split()
    except Exception:
        return []


def _netloc(ip, port):
    return f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'


def _raw_request(ip, port, lines, timeout=5):
    """Send a raw HTTP/1.1 request; return the status code, or None if the connection was refused."""
    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
    except OSError:
        return None
    try:
        s.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
        head = s.recv(256).split(b'\r\n', 1)[0].decode(errors='replace')
        parts = head.split()
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
    except OSError:
        return -1
    finally:
        s.close()


def _get(ip, port, path, host=None, extra=()):
    return _raw_request(ip, port, [f'GET {path} HTTP/1.1',
                                   f'Host: {host or _netloc(ip, port)}',
                                   'Connection: close', *extra])


def _check(name, status, detail, finding=''):
    return {'check': name, 'status': status, 'detail': detail, 'finding': finding}


# ── web probe ─────────────────────────────────────────────────────────────────

def probe_target(ip, port):
    """Probe one address tw-web serves on. Nothing here runs a command on the server:
    the WebSocket probe closes before sending one."""
    where = _netloc(ip, port)
    out = []

    code = _get(ip, port, '/api/health', host=f'{EVIL_HOST}:{port}')
    out.append(_check(f'{where} foreign Host refused', OK if code == 400 else FAIL,
                      f'HTTP {code} for Host: {EVIL_HOST}', 'S4'))

    code = _get(ip, port, '/console')
    out.append(_check(f'{where} debugger console off', OK if code == 404 else FAIL,
                      f'HTTP {code} for /console', 'S3'))

    key = base64.b64encode(os.urandom(16)).decode()
    code = _get(ip, port, '/ws/pty', extra=(
        'Upgrade: websocket', 'Connection: Upgrade', f'Sec-WebSocket-Key: {key}',
        'Sec-WebSocket-Version: 13', f'Origin: {EVIL_ORIGIN}'))
    out.append(_check(f'{where} terminal socket refuses foreign Origin', OK if code == 403 else FAIL,
                      f'HTTP {code} for a WebSocket from {EVIL_ORIGIN}', 'S1'))

    body = '{}'
    code = _raw_request(ip, port, [
        'POST /api/debug HTTP/1.1', f'Host: {where}', f'Origin: {EVIL_ORIGIN}',
        'Content-Type: text/plain', f'Content-Length: {len(body)}', 'Connection: close',
        '', body])
    out.append(_check(f'{where} cross-site POST refused', OK if code == 403 else FAIL,
                      f'HTTP {code} for POST from {EVIL_ORIGIN}', 'S5'))

    code = _get(ip, port, '/.git/config')
    out.append(_check(f'{where} repo internals hidden', OK if code == 404 else WARN,
                      f'HTTP {code} for /.git/config', 'S7'))
    return out


def web_probe(port):
    checks = []
    tail = _tailscale_ips()

    # 1. Is it up on localhost at all?
    if _get('127.0.0.1', port, '/manifest.json', host=f'localhost:{port}') is None:
        return [_check(f'tw-web on localhost:{port}', FAIL, 'connection refused — is it running?')]

    # 2. Every address that answers must be loopback or Tailscale.
    for ip in _local_ips():
        if ip.startswith('127.') or ip == '::1':
            continue
        reachable = _get(ip, port, '/manifest.json') is not None
        if ip in tail:
            checks.append(_check(f'{_netloc(ip, port)} (Tailscale)', OK,
                                 'reachable' if reachable else 'not bound (localhost only)'))
        else:
            checks.append(_check(f'{_netloc(ip, port)} (LAN/public) not reachable',
                                 FAIL if reachable else OK,
                                 'ANSWERS — exposed beyond localhost and Tailscale' if reachable else 'connection refused',
                                 'S2'))

    # 3. Attack probes on every address that serves tw-web.
    targets = ['127.0.0.1'] + [ip for ip in tail if _get(ip, port, '/manifest.json') is not None]
    for ip in targets:
        checks += probe_target(ip, port)
    return checks


# ── CLI ───────────────────────────────────────────────────────────────────────

def _report(checks, as_json):
    worst = FAIL if any(c['status'] == FAIL for c in checks) else WARN if any(c['status'] == WARN for c in checks) else OK
    if as_json:
        print(json.dumps({'status': worst, 'checks': checks}, indent=2))
    else:
        mark = {OK: '  ok ', WARN: ' warn', FAIL: ' FAIL'}
        for c in checks:
            tag = f' [{c["finding"]}]' if c['finding'] else ''
            print(f'{mark[c["status"]]}  {c["check"]}{tag} — {c["detail"]}')
        print(f'\n{worst.upper()}: {sum(c["status"] == OK for c in checks)}/{len(checks)} checks ok')
    return {OK: 0, WARN: 1, FAIL: 2}[worst]


def main(argv=None):
    p = argparse.ArgumentParser(prog='taskutil', description=__doc__.split('\n\n')[0])
    p.add_argument('--version', action='version', version=f'taskutil {__version__}')
    sub = p.add_subparsers(dest='cmd', required=True)
    web = sub.add_parser('web', help='tw-web server checks').add_subparsers(dest='web_cmd', required=True)
    pr = web.add_parser('probe', help='probe a running tw-web from outside')
    pr.add_argument('--port', type=int, default=int(os.environ.get('TW_WEB_PORT', 5000)))
    pr.add_argument('--json', action='store_true')
    a = p.parse_args(argv)

    if a.cmd == 'web' and a.web_cmd == 'probe':
        return _report(web_probe(a.port), a.json)
    return 2


if __name__ == '__main__':
    sys.exit(main())
