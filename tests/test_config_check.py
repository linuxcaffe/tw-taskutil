"""taskutil config check: every `include` in the TASKRC chain must resolve, the way
Taskwarrior 2.6.2 resolves it (absolute or ~; relative to the including file's folder;
else the system theme folder). Throwaway rc files only."""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('taskutil', ROOT / 'taskutil.py')
taskutil = importlib.util.module_from_spec(spec)
spec.loader.exec_module(taskutil)


@pytest.fixture
def rc(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    (tmp_path / 'home').mkdir()
    (tmp_path / 'data').mkdir()

    def write(body, name='taskrc'):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        return p
    write.dir = tmp_path
    return write


def run(capsys, rcfile, *extra):
    code = taskutil.main(['config', 'check', '--taskrc', str(rcfile), *extra, '--json'])
    return code, json.loads(capsys.readouterr().out)


def details(out):
    return ' '.join(f"{c['check']} {c['detail']}" for c in out['checks'])


def test_all_includes_resolve(rc, capsys):
    rc('x.a=1\n', 'config/a.rc')
    rc('include nested.rc\n', 'config/b.rc')
    rc('y=1\n', 'config/nested.rc')
    (rc.dir / 'home' / '.task').mkdir()
    (rc.dir / 'home' / '.task' / 'tilde.rc').write_text('z=1\n')
    top = rc(f'data.location={rc.dir}/data\n'
             f'include {rc.dir}/config/a.rc\n'
             'include config/b.rc\n'               # relative to this file's folder
             'include ~/.task/tilde.rc\n'
             '#include /nowhere/commented.rc\n')
    code, out = run(capsys, top)
    assert code == 0, details(out)
    assert '4 includes' in details(out)


def test_missing_include_fails_and_is_named(rc, capsys):
    top = rc(f'data.location={rc.dir}/data\ninclude ~/.task/config/daily-email.rc\n')
    code, out = run(capsys, top)
    assert code == 2
    assert 'daily-email.rc' in details(out) and 'line 2' in details(out)


def test_missing_nested_include_names_the_including_file(rc, capsys):
    rc('include gone.rc\n', 'config/included.rc')
    top = rc(f'data.location={rc.dir}/data\ninclude config/included.rc\n')
    code, out = run(capsys, top)
    assert code == 2
    assert 'included.rc' in details(out) and 'gone.rc' in details(out)


def test_indented_include_counts(rc, capsys):
    top = rc(f'data.location={rc.dir}/data\n   include /nowhere/x.rc\n')
    assert run(capsys, top)[0] == 2


def test_relative_resolves_from_including_file_not_top(rc, capsys):
    rc('include nested.rc\n', 'config/outer.rc')
    rc('y=1\n', 'nested.rc')                       # next to the top rc, not next to outer.rc
    top = rc(f'data.location={rc.dir}/data\ninclude config/outer.rc\n')
    assert run(capsys, top)[0] == 2


@pytest.mark.skipif(not Path('/usr/share/taskwarrior/dark-256.theme').exists(),
                    reason='no system themes installed')
def test_system_theme_resolves(rc, capsys):
    top = rc(f'data.location={rc.dir}/data\ninclude dark-256.theme\n')
    assert run(capsys, top)[0] == 0


def test_include_cycle_does_not_hang(rc, capsys):
    rc('include b.rc\n', 'config/a.rc')
    rc('include a.rc\n', 'config/b.rc')
    top = rc(f'data.location={rc.dir}/data\ninclude config/a.rc\n')
    code, out = run(capsys, top)
    assert code in (0, 1, 2)


def test_missing_taskrc_fails(rc, capsys):
    code, out = run(capsys, rc.dir / 'nope')
    assert code == 2


@pytest.mark.skipif(not shutil.which('task'), reason='task not installed')
def test_task_itself_agrees(rc, capsys):
    top = rc(f'data.location={rc.dir}/data\nhooks=off\ninclude /nowhere/x.rc\n')
    code, out = run(capsys, top)
    assert any('Could not read include file' in c['detail'] for c in out['checks'])
