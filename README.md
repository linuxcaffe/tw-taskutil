# tw-taskutil

`taskutil` — a small companion utility for the infrastructure **around** Taskwarrior 2.6.2: repos, mirrors, servers and hooks.

[tw-sanity-check](https://github.com/linuxcaffe/tw-sanity-check) looks after the task data itself. `taskutil` looks after everything around it. They don't overlap.

Single Python file, standard library only. Every command takes `--json`. Exit codes: `0` ok, `1` warnings, `2` failures.

## Commands

| Command | Does |
|---|---|
| `taskutil web probe [--port N]` | Probes a running [tw-web](https://github.com/linuxcaffe/tw-web) from outside, the way an attacker would: which interfaces answer, foreign `Host` (DNS rebinding), the debugger console, a foreign-origin WebSocket to the terminal, a cross-site POST, exposed repo files. Sends no command to the server. |

Planned: `snapshot`, `stale`, `fixture`, `hooks check`, `web start|stop|status|clean`. Design: `tw:docs/tw-web-dev-infra-plan.md`, section "taskutil".

## Install

```bash
ln -s ~/dev/tw-taskutil/taskutil.py ~/.local/bin/taskutil
```
