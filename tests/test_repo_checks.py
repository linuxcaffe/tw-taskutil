"""taskutil snapshot / stale, against throwaway git repos.

Every test builds its own task dir and two bare "mirrors" under tmp_path and passes
--dir, so nothing here can touch ~/.task or reach the network.
"""
import importlib.util
import json
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('taskutil', ROOT / 'taskutil.py')
taskutil = importlib.util.module_from_spec(spec)
spec.loader.exec_module(taskutil)

DAY = 86400


@pytest.fixture(autouse=True)
def git_env(monkeypatch, tmp_path):
    """Isolate git from the user's config, and refuse to run against the real ~/.task."""
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(tmp_path / 'gitconfig'))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    for k in ('AUTHOR', 'COMMITTER'):
        monkeypatch.setenv(f'GIT_{k}_NAME', 'test')
        monkeypatch.setenv(f'GIT_{k}_EMAIL', 'test@example.invalid')
        monkeypatch.delenv(f'GIT_{k}_DATE', raising=False)
    monkeypatch.setenv('TW_TASK_DIR', str(tmp_path / 'not-the-real-task-dir'))


def git(d, *args, date=None, env=None):
    import os
    e = dict(os.environ)
    if date is not None:
        stamp = f'@{int(date)} +0000'
        e['GIT_AUTHOR_DATE'] = e['GIT_COMMITTER_DATE'] = stamp
    r = subprocess.run(['git', '-C', str(d), *args], capture_output=True, text=True, env=e)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def commit(d, name='pending.data', text='x', age=0):
    p = Path(d) / name
    p.write_text(p.read_text() + text if p.exists() else text)
    git(d, 'add', '-A')
    git(d, 'commit', '-qm', f'edit {name}', date=time.time() - age)


@pytest.fixture
def repos(tmp_path):
    """task/ with one commit, pushed to two bare mirrors the way ~/.task is set up:
    origin fetches mirror_a and pushes to both; github fetches mirror_b."""
    a, b, task = tmp_path / 'mirror_a.git', tmp_path / 'mirror_b.git', tmp_path / 'task'
    for m in (a, b):
        subprocess.run(['git', 'init', '-q', '--bare', '-b', 'master', str(m)], check=True)
    subprocess.run(['git', 'init', '-q', '-b', 'master', str(task)], check=True)
    (task / '.gitignore').write_text('undo.data\n')
    commit(task, age=3600)
    git(task, 'remote', 'add', 'origin', str(a))
    git(task, 'remote', 'set-url', '--add', '--push', 'origin', str(a))
    git(task, 'remote', 'set-url', '--add', '--push', 'origin', str(b))
    git(task, 'remote', 'add', 'github', str(b))
    git(task, 'push', '-q', 'origin', 'master')
    return {'task': task, 'a': a, 'b': b}


def run(capsys, *argv):
    code = taskutil.main([*argv, '--json'])
    out = json.loads(capsys.readouterr().out)
    return code, out


def statuses(out):
    return [(c['status'], c['check'], c['detail']) for c in out['checks']]


# ── snapshot ──────────────────────────────────────────────────────────────────

def test_snapshot_clean_is_a_no_op(repos, capsys):
    head = git(repos['task'], 'rev-parse', 'HEAD')
    code, out = run(capsys, 'snapshot', '--dir', str(repos['task']))
    assert code == 0 and git(repos['task'], 'rev-parse', 'HEAD') == head
    assert 'nothing to commit' in out['checks'][0]['detail']


def test_snapshot_commits_without_pushing(repos, capsys):
    t = repos['task']
    (t / 'pending.data').write_text('changed')
    (t / 'completed.data').write_text('new file')
    (t / 'undo.data').write_text('ignored')
    mirror_head = git(repos['a'], 'rev-parse', 'master')
    code, out = run(capsys, 'snapshot', '--dir', str(t))
    assert code == 0
    assert git(t, 'status', '--porcelain') == '?? undo.data' or git(t, 'status', '--porcelain') == ''
    assert git(t, 'log', '-1', '--format=%s').startswith('taskutil: snapshot')
    assert '2 files' in git(t, 'log', '-1', '--format=%s')
    assert git(repos['a'], 'rev-parse', 'master') == mirror_head      # not pushed
    assert git(repos['b'], 'rev-parse', 'master') == mirror_head


def test_snapshot_custom_message(repos, capsys):
    (repos['task'] / 'pending.data').write_text('changed')
    run(capsys, 'snapshot', '--dir', str(repos['task']), '-m', 'before tw-web dev')
    assert git(repos['task'], 'log', '-1', '--format=%s') == 'taskutil: before tw-web dev'


def test_snapshot_not_a_repo_fails(tmp_path, capsys):
    (tmp_path / 'plain').mkdir()
    code, _ = run(capsys, 'snapshot', '--dir', str(tmp_path / 'plain'))
    assert code == 2


def test_snapshot_skips_mid_merge(repos, capsys):
    t = repos['task']
    (t / 'pending.data').write_text('changed')
    (t / '.git' / 'MERGE_HEAD').write_text(git(t, 'rev-parse', 'HEAD'))
    head = git(t, 'rev-parse', 'HEAD')
    code, out = run(capsys, 'snapshot', '--dir', str(t))
    assert code == 1 and git(t, 'rev-parse', 'HEAD') == head
    assert 'merge' in out['checks'][0]['detail']


def test_snapshot_default_dir_is_tw_task_dir(repos, capsys, monkeypatch):
    monkeypatch.setenv('TW_TASK_DIR', str(repos['task']))
    (repos['task'] / 'pending.data').write_text('changed')
    code, _ = run(capsys, 'snapshot')
    assert code == 0 and git(repos['task'], 'status', '--porcelain') == ''


# ── stale ─────────────────────────────────────────────────────────────────────

def test_stale_fresh_repo_is_ok(repos, capsys):
    code, out = run(capsys, 'stale', '--dir', str(repos['task']))
    assert code == 0, statuses(out)
    names = ' '.join(c['check'] for c in out['checks'])
    assert str(repos['a']) in names and str(repos['b']) in names


def test_stale_old_uncommitted_changes_warn(tmp_path, capsys):
    t = tmp_path / 'old'
    subprocess.run(['git', 'init', '-q', '-b', 'master', str(t)], check=True)
    commit(t, age=5 * DAY)
    (t / 'pending.data').write_text('changed')
    code, out = run(capsys, 'stale', '--dir', str(t), '--no-fetch')
    assert code == 1
    assert any(s == 'warn' and 'uncommitted' in d for s, _, d in statuses(out))


def test_stale_recent_uncommitted_changes_ok(repos, capsys):
    (repos['task'] / 'pending.data').write_text('changed')
    code, out = run(capsys, 'stale', '--dir', str(repos['task']))
    assert code == 0, statuses(out)


def test_stale_unpushed_to_one_mirror_names_it(repos, capsys):
    t = repos['task']
    commit(t, age=10 * DAY)
    git(t, 'push', '-q', 'github', 'master')          # reaches mirror_b only
    code, out = run(capsys, 'stale', '--dir', str(t))
    assert code == 1
    warned = [(c, d) for s, c, d in statuses(out) if s == 'warn']
    assert len(warned) == 1 and str(repos['a']) in warned[0][0] and '1 commit' in warned[0][1]


def test_stale_recent_unpushed_commit_is_ok(repos, capsys):
    commit(repos['task'])
    code, out = run(capsys, 'stale', '--dir', str(repos['task']))
    assert code == 0, statuses(out)


def test_stale_unreachable_mirror_warns(repos, capsys):
    git(repos['task'], 'remote', 'set-url', 'github', str(repos['task'].parent / 'gone.git'))
    code, out = run(capsys, 'stale', '--dir', str(repos['task']))
    assert code == 1
    assert any(s == 'warn' and 'unreachable' in d for s, _, d in statuses(out))


def test_stale_mirror_with_newer_commits_warns(repos, tmp_path, capsys):
    other = tmp_path / 'other-machine'
    subprocess.run(['git', 'clone', '-q', str(repos['a']), str(other)], check=True)
    commit(other, name='other.data')
    git(other, 'push', '-q', 'origin', 'master')
    code, out = run(capsys, 'stale', '--dir', str(repos['task']))
    assert code == 1
    assert any(s == 'warn' and 'not here' in d for s, _, d in statuses(out))


def test_stale_no_fetch_skips_mirrors(repos, capsys):
    git(repos['task'], 'remote', 'set-url', 'github', str(repos['task'].parent / 'gone.git'))
    code, out = run(capsys, 'stale', '--dir', str(repos['task']), '--no-fetch')
    assert code == 0, statuses(out)


def test_stale_several_dirs(repos, tmp_path, capsys):
    code, out = run(capsys, 'stale', '--dir', str(repos['task']), '--dir', str(tmp_path / 'nope'))
    assert code == 2
    assert any(s == 'fail' and 'nope' in c for s, c, _ in statuses(out))


def test_stale_never_changes_the_repo(repos, capsys):
    t = repos['task']
    before = git(t, 'for-each-ref'), git(t, 'rev-parse', 'HEAD')
    run(capsys, 'stale', '--dir', str(t))
    assert (git(t, 'for-each-ref'), git(t, 'rev-parse', 'HEAD')) == before
