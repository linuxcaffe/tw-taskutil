# tw-taskutil

`taskutil` — a small companion utility for the infrastructure **around** Taskwarrior 2.6.2: repos, mirrors, servers and hooks.

[tw-sanity-check](https://github.com/linuxcaffe/tw-sanity-check) looks after the task data itself. `taskutil` looks after everything around it. They don't overlap.

Single Python file, standard library only. Every command takes `--json`. Exit codes: `0` ok, `1` warnings, `2` failures.

## Commands

| Command | Does |
|---|---|
| `taskutil snapshot [--dir D] [-m MSG]` | Commits the task dir (`$TW_TASK_DIR`, else `~/.task`, as gittw) without pushing. Does nothing when clean; skips (warns) mid-merge or rebase. tw-web's launcher runs it on every start. |
| `taskutil stale [--dir D …] [--max-age 2] [--mirror-age 7] [--no-fetch] [--notify]` | Read-only. Warns when uncommitted changes are older than `--max-age` days, when a mirror (every fetch *and* push URL, via `git ls-remote`) is unreachable, lacks the branch, has commits this repo doesn't, or is missing commits older than `--mirror-age` days. `--notify` sends a desktop notification when anything isn't ok. |
| `taskutil config check [--taskrc F] [--notify]` | Read-only. Follows `.taskrc` (or `$TASKRC`) and every `include`, resolving paths as Taskwarrior 2.6.2 does (absolute or `~`; the including file's folder; `/usr/share/taskwarrior`), names any missing file with its line, then checks that `task` itself starts. Catches an uninstall that leaves an `include` behind. tw-web's launcher and the daily timer run it. |
| `taskutil holidays check\|refresh [--notify]` | Runs [tw-holidata](https://github.com/linuxcaffe/tw-holidata)'s `holidata check` or `refresh` and reports its checks: holidays ending within 60 days, settings changed since the last refresh, `task` not seeing them. tw-holidata owns the settings and the data; taskutil keeps no copy. Says nothing when holidata isn't installed. The daily timer runs `check`. |
| `taskutil web probe [--port N]` | Probes a running [tw-web](https://github.com/linuxcaffe/tw-web) from outside, the way an attacker would: which interfaces answer, foreign `Host` (DNS rebinding), the debugger console, a foreign-origin WebSocket to the terminal, a cross-site POST, exposed repo files. Sends no command to the server. |

Planned: `fixture`, `hooks check`, `web start|stop|status|clean`. Design: `tw:docs/tw-web-dev-infra-plan.md`, section "taskutil".

## Install

```bash
ln -s ~/dev/tw-taskutil/taskutil.py ~/.local/bin/taskutil
```

Daily checks, `stale`, `config check` and `holidays check` (systemd user timer, notifies only when something is wrong):

```bash
ln -s ~/dev/tw-taskutil/systemd/taskutil-stale.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now taskutil-stale.timer
```

## Tests

```bash
python3 -m pytest -q tests/     # throwaway git repos only; never touches ~/.task or the network
```
