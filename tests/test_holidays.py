"""taskutil holidays: runs tw-holidata's `holidata` (it owns the settings and the data);
taskutil only finds it, reports its checks and nags. A fake `holidata` stands in here, so
nothing touches the network or ~/.task."""
import importlib.util
import json
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('taskutil', ROOT / 'taskutil.py')
taskutil = importlib.util.module_from_spec(spec)
spec.loader.exec_module(taskutil)


@pytest.fixture
def tdir(tmp_path, monkeypatch):
    d = tmp_path / 'task'
    (d / 'config').mkdir(parents=True)
    (d / 'scripts').mkdir()
    monkeypatch.setenv('TW_TASK_DIR', str(d))
    monkeypatch.setenv('PATH', str(tmp_path / 'bin'))      # no real holidata on PATH
    return d


def fake_holidata(tdir, status='ok', checks=None, code=0):
    """A holidata in the task dir's scripts/ (where tw -I puts it) that logs its argv."""
    script = tdir / 'scripts' / 'holidata'
    out = json.dumps({'status': status, 'checks': checks or [
        {'check': 'coverage', 'status': status, 'detail': 'through 2027-12-26'}]})
    script.write_text(f"#!/bin/sh\necho \"$@\" >> {tdir / 'argv.log'}\necho '{out}'\nexit {code}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def run(capsys, *args):
    code = taskutil.main(['holidays', *args, '--json'])
    return code, json.loads(capsys.readouterr().out)


def test_not_installed_is_ok(tdir, capsys):
    code, out = run(capsys, 'check')
    assert code == 0 and 'not installed' in out['checks'][0]['detail']


def test_settings_without_holidata_warns(tdir, capsys):
    (tdir / 'config' / 'holidata.rc').write_text('holidata.locale = en-CA\n')
    code, out = run(capsys, 'check')
    assert code == 1 and 'tw -I holidata' in out['checks'][0]['detail']


def test_check_reports_holidatas_checks(tdir, capsys):
    fake_holidata(tdir, 'warn', [{'check': 'coverage', 'status': 'warn',
                                  'detail': 'holidays end 2026-12-26: run holidata refresh'}], code=1)
    code, out = run(capsys, 'check')
    assert code == 1
    assert out['checks'] == [{'check': 'holidays coverage', 'status': 'warn', 'finding': '',
                              'detail': 'holidays end 2026-12-26: run holidata refresh'}]
    assert (tdir / 'argv.log').read_text().split() == ['check', '--json']


def test_check_survives_garbage(tdir, capsys):
    script = fake_holidata(tdir)
    script.write_text('#!/bin/sh\necho oops\nexit 2\n')
    code, out = run(capsys, 'check')
    assert code == 2 and 'oops' in out['checks'][0]['detail']


def test_refresh_runs_holidata_refresh(tdir, capsys):
    fake_holidata(tdir)
    code, out = run(capsys, 'refresh')
    assert code == 0
    assert (tdir / 'argv.log').read_text().split() == ['refresh', '--json']


def test_refresh_without_holidata(tdir, capsys):
    code, out = run(capsys, 'refresh')
    assert code == 2 and 'tw -I holidata' in out['checks'][0]['detail']
