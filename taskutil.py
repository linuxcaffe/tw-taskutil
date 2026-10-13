#!/usr/bin/env python3
"""
taskutil — companion utility for the infrastructure around Taskwarrior 2.6.2:
repos, mirrors, servers and hooks. (tw-sanity-check looks after the task
data itself; taskutil looks after everything around it.)

Commands
  taskutil snapshot [--dir D] [-m MSG]
                                  Commit the task dir (git) without pushing.
                                  Does nothing when there's nothing to commit.
  taskutil stale [--dir D ...] [--max-age DAYS] [--mirror-age DAYS] [--no-fetch] [--notify]
                                  Warn when uncommitted changes or unpushed
                                  commits get old, or a mirror is unreachable
                                  or has commits this repo lacks. Read-only.
  taskutil config check [--taskrc F]
                                  Every `include` in the TASKRC chain must
                                  resolve, as Taskwarrior resolves it; then
                                  `task` itself must start. Read-only.
  taskutil web probe [--port N]   Probe a running tw-web from outside, the way
                                  an attacker would.

Exit 0 ok, 1 warnings, 2 failures. The task dir is $TW_TASK_DIR, else ~/.task
(the same rule as gittw).

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
import time
from pathlib import Path

__version__ = '0.3.0'

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


# ── git repos: snapshot, stale ────────────────────────────────────────────────

GIT_BUSY = ('MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'REBASE_HEAD', 'rebase-merge',
            'rebase-apply', 'index.lock')


def task_dir():
    return Path(os.environ.get('TW_TASK_DIR') or Path.home() / '.task')


def _git(d, *args, timeout=30, env=None):
    """Run git in d; return (returncode, stdout). Never prompts for credentials."""
    e = dict(os.environ, GIT_TERMINAL_PROMPT='0', **(env or {}))
    e.setdefault('GIT_SSH_COMMAND', 'ssh -o BatchMode=yes -o ConnectTimeout=10')
    try:
        r = subprocess.run(['git', '-C', str(d), *args], capture_output=True, text=True,
                           timeout=timeout, env=e)
    except subprocess.TimeoutExpired:
        return 124, 'timed out'
    return r.returncode, (r.stdout if r.returncode == 0 else r.stderr).strip()


def _git_dir(d):
    code, out = _git(d, 'rev-parse', '--show-toplevel', '--absolute-git-dir')
    if code != 0:
        return None
    top, gdir = out.splitlines()
    return Path(gdir) if Path(top).resolve() == Path(d).resolve() else None


def _busy(gdir):
    return next((f for f in GIT_BUSY if (gdir / f).exists()), None)


def _ago(seconds):
    seconds = max(0, seconds)
    if seconds < 3600:
        return f'{int(seconds // 60)} min'
    if seconds < 2 * 86400:
        return f'{seconds / 3600:.0f} h'
    return f'{seconds / 86400:.0f} days'


def _plural(n, word):
    return f'{n} {word}{"" if n == 1 else "s"}'


def snapshot(d, message=None):
    d = Path(d)
    name = f'snapshot {d}'
    gdir = _git_dir(d)
    if gdir is None:
        return [_check(name, FAIL, 'not the top of a git repository')]
    busy = _busy(gdir)
    if busy:
        what = 'a merge' if busy == 'MERGE_HEAD' else 'git is busy' if busy == 'index.lock' else 'an operation'
        return [_check(name, WARN, f'skipped: {what} in progress ({busy})')]
    code, out = _git(d, 'status', '--porcelain')
    if code != 0:
        return [_check(name, FAIL, out)]
    if not out:
        return [_check(name, OK, 'nothing to commit')]
    n = len(out.splitlines())
    if message:
        msg = f'taskutil: {message}'
    else:
        msg = f'taskutil: snapshot {time.strftime("%Y-%m-%d %H:%M")} ({_plural(n, "file")} changed)'
    for args in (('add', '-A'), ('commit', '-q', '-m', msg)):
        code, out = _git(d, *args, timeout=120)
        if code != 0:
            return [_check(name, FAIL, f'git {args[0]}: {out}')]
    _, head = _git(d, 'rev-parse', '--short', 'HEAD')
    return [_check(name, OK, f'committed {head} ({_plural(n, "file")}), not pushed')]


def _display_url(url):
    """Drop any user:password@ from an https URL before printing it."""
    if '://' in url and '@' in url.split('://', 1)[1].split('/', 1)[0]:
        scheme, rest = url.split('://', 1)
        return f'{scheme}://{rest.split("@", 1)[1]}'
    return url


def _mirror_urls(d):
    """Every distinct URL this repo fetches from or pushes to, in config order."""
    code, out = _git(d, 'config', '--get-regexp', r'^remote\..*\.(url|pushurl)$')
    urls = []
    for line in out.splitlines() if code == 0 else []:
        url = line.split(None, 1)[1]
        if url not in urls:
            urls.append(url)
    return urls


def _check_mirror(d, url, branch, head, mirror_age, now):
    name = f'{d.name} → {_display_url(url)}'
    code, out = _git(d, 'ls-remote', url, f'refs/heads/{branch}', timeout=45)
    if code != 0:
        first = out.splitlines()[-1] if out else f'exit {code}'
        return _check(name, WARN, f'unreachable: {first}')
    if not out:
        return _check(name, WARN, f'branch {branch} is not on this mirror (never pushed?)')
    remote = out.split()[0]
    if remote == head:
        return _check(name, OK, 'up to date')
    if _git(d, 'cat-file', '-e', f'{remote}^{{commit}}')[0] != 0:
        return _check(name, WARN, f'has commits not here (fetch/pull from it)')
    if _git(d, 'merge-base', '--is-ancestor', remote, head)[0] != 0:
        return _check(name, WARN, f'has diverged from {branch} here')
    _, dates = _git(d, 'log', '--format=%ct', f'{remote}..{head}')
    stamps = [int(x) for x in dates.split()]
    age = now - min(stamps)
    detail = f'{_plural(len(stamps), "commit")} not pushed, oldest {_ago(age)} old'
    return _check(name, WARN if age > mirror_age else OK, detail)


def stale(dirs, max_age=2 * 86400, mirror_age=7 * 86400, fetch=True, now=None):
    now = now or time.time()
    checks = []
    for d in map(Path, dirs):
        gdir = _git_dir(d) if d.is_dir() else None
        if gdir is None:
            checks.append(_check(f'{d} is a git repository', FAIL, 'not the top of a git repository'))
            continue
        code, last = _git(d, 'log', '-1', '--format=%ct')
        last_age = now - int(last) if code == 0 and last else None
        _, status = _git(d, 'status', '--porcelain')
        n = len(status.splitlines()) if status else 0
        busy = _busy(gdir)
        if busy:
            checks.append(_check(f'{d.name} working tree', WARN, f'{busy} present: a git operation is unfinished'))
        elif not n:
            checks.append(_check(f'{d.name} working tree', OK, 'clean'))
        else:
            since = 'never committed' if last_age is None else f'last commit {_ago(last_age)} ago'
            old = last_age is None or last_age > max_age
            checks.append(_check(f'{d.name} working tree', WARN if old else OK,
                                 f'{_plural(n, "file")} uncommitted, {since}'
                                 + (' (taskutil snapshot)' if old else '')))
        if not fetch:
            continue
        code, branch = _git(d, 'rev-parse', '--abbrev-ref', 'HEAD')
        _, head = _git(d, 'rev-parse', 'HEAD')
        if code != 0 or branch == 'HEAD':
            checks.append(_check(f'{d.name} mirrors', WARN, 'detached HEAD: mirrors not checked'))
            continue
        urls = _mirror_urls(d)
        if not urls:
            checks.append(_check(f'{d.name} mirrors', WARN, 'no remotes: nothing mirrors this repo'))
        for url in urls:
            checks.append(_check_mirror(d, url, branch, head, mirror_age, now))
    return checks


# ── config: include chain ─────────────────────────────────────────────────────

SYSTEM_RC_DIR = Path('/usr/share/taskwarrior')
INCLUDE_RE = __import__('re').compile(r'^\s*include\s+(\S.*?)\s*$')


def _resolve_include(value, including_file):
    """Where Taskwarrior 2.6.2 looks for `include value` (verified on the binary):
    absolute or ~ as written; else the including file's folder; else the system folder."""
    p = Path(os.path.expanduser(value))
    if p.is_absolute():
        return [p]
    return [including_file.parent / p, SYSTEM_RC_DIR / p]


def _walk_includes(rcfile, seen, found, missing):
    rcfile = rcfile.resolve()
    if rcfile in seen:
        return
    seen.add(rcfile)
    for n, line in enumerate(rcfile.read_text(errors='replace').splitlines(), 1):
        m = INCLUDE_RE.match(line)
        if not m:
            continue
        candidates = _resolve_include(m.group(1), rcfile)
        hit = next((c for c in candidates if c.is_file()), None)
        if hit is None:
            missing.append((rcfile, n, m.group(1)))
        else:
            found.append(hit)
            _walk_includes(hit, seen, found, missing)


def config_check(taskrc=None):
    rc = Path(taskrc or os.environ.get('TASKRC') or Path.home() / '.taskrc').expanduser()
    if not rc.is_file():
        return [_check(f'taskrc {rc}', FAIL, 'not found')]
    found, missing = [], []
    _walk_includes(rc, set(), found, missing)
    home = str(Path.home())
    short = lambda p: str(p).replace(home, '~', 1)
    checks = [_check(f'{short(f)} line {n}', FAIL,
                     f'include {value}: file not found (comment the line out, or restore the file)')
              for f, n, value in missing]
    if not missing:
        checks.append(_check(f'includes in {short(rc)}', OK, f'{_plural(len(found), "include")}, all found'))
    # Taskwarrior has the last word: does it start with this rc?
    try:
        r = subprocess.run(['task', 'rc.hooks=off', '_version'], capture_output=True, text=True,
                           timeout=15, env=dict(os.environ, TASKRC=str(rc)))
        if r.returncode == 0:
            checks.append(_check('task starts', OK, f'task {r.stdout.strip()}'))
        else:
            checks.append(_check('task starts', FAIL, (r.stderr or r.stdout).strip().splitlines()[-1]))
    except FileNotFoundError:
        checks.append(_check('task starts', WARN, 'task not installed'))
    except subprocess.TimeoutExpired:
        checks.append(_check('task starts', FAIL, 'task timed out'))
    return checks


def _notify(checks, title='taskutil stale'):
    bad = [c for c in checks if c['status'] != OK]
    if not bad:
        return
    body = '\n'.join(f'{c["check"]}: {c["detail"]}' for c in bad[:6])
    urgency = 'critical' if any(c['status'] == FAIL for c in bad) else 'normal'
    try:
        subprocess.run(['notify-send', '-u', urgency, '-a', 'taskutil', title, body],
                       timeout=10, capture_output=True)
    except Exception:
        pass


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
    sn = sub.add_parser('snapshot', help='commit the task dir without pushing')
    sn.add_argument('--dir', help='repository (default: $TW_TASK_DIR or ~/.task)')
    sn.add_argument('-m', '--message', help='commit message after "taskutil: "')
    sn.add_argument('--json', action='store_true')
    st = sub.add_parser('stale', help='warn about old uncommitted work and lagging mirrors')
    st.add_argument('--dir', action='append', help='repository; repeat for several (default: task dir)')
    st.add_argument('--max-age', type=float, default=2, metavar='DAYS',
                    help='uncommitted changes older than this warn (default 2)')
    st.add_argument('--mirror-age', type=float, default=7, metavar='DAYS',
                    help='unpushed commits older than this warn (default 7)')
    st.add_argument('--no-fetch', action='store_true', help='skip the mirrors (offline)')
    st.add_argument('--notify', action='store_true', help='desktop notification when something is wrong')
    st.add_argument('--json', action='store_true')
    cf = sub.add_parser('config', help='Taskwarrior configuration checks').add_subparsers(dest='config_cmd', required=True)
    cc = cf.add_parser('check', help='every include resolves and task starts')
    cc.add_argument('--taskrc', help='rc file (default: $TASKRC or ~/.taskrc)')
    cc.add_argument('--notify', action='store_true', help='desktop notification when something is wrong')
    cc.add_argument('--json', action='store_true')
    web = sub.add_parser('web', help='tw-web server checks').add_subparsers(dest='web_cmd', required=True)
    pr = web.add_parser('probe', help='probe a running tw-web from outside')
    pr.add_argument('--port', type=int, default=int(os.environ.get('TW_WEB_PORT', 5000)))
    pr.add_argument('--json', action='store_true')
    a = p.parse_args(argv)

    if a.cmd == 'snapshot':
        return _report(snapshot(a.dir or task_dir(), a.message), a.json)
    if a.cmd == 'stale':
        checks = stale(a.dir or [task_dir()], a.max_age * 86400, a.mirror_age * 86400, not a.no_fetch)
        if a.notify:
            _notify(checks)
        return _report(checks, a.json)
    if a.cmd == 'config' and a.config_cmd == 'check':
        checks = config_check(a.taskrc)
        if a.notify:
            _notify(checks, 'taskutil config check')
        return _report(checks, a.json)
    if a.cmd == 'web' and a.web_cmd == 'probe':
        return _report(web_probe(a.port), a.json)
    return 2


if __name__ == '__main__':
    sys.exit(main())
