# How preinstall-review works

## Pipeline

1. **Fetch.** A local directory is used in place. A git URL is cloned with
   `--depth 1`, no submodules and git hooks disabled. Cloning does not run
   repository code.
2. **Static inventory** (`scripts/inventory.py`). Walks the tree with
   `lstat` and never follows symlinks. Detects the layout (single skill,
   plugin or marketplace), parses `plugin.json`, `hooks/hooks.json`,
   `.mcp.json`, `.lsp.json`, `monitors/monitors.json`, `bin/`,
   `settings.json` and `package.json`, and scans text files.
3. **Sandbox run** (`sandbox/runner.py` inside Docker). The host sends the
   candidate and the run plan as a tar stream on stdin. No host directory is
   mounted into the container.
4. **Classification** (`scripts/review.py`). Parses the strace output, the
   sinkhole log and the filesystem diffs, and turns them into findings.

## Container settings

| Setting | Why |
| --- | --- |
| `--network none` | Nothing can leave. Attempts are still visible. |
| `--dns 127.0.0.1` + sinkhole | Every name lookup is logged and answered with 127.0.0.2, where listeners on ports 22, 25, 80, 443, 3000, 5000, 8000, 8080, 8443 and 9000 capture the first 4 KB sent. |
| `--read-only` root, tmpfs for `/tmp`, `/work`, home | Nothing persists after the run. |
| `--cap-drop ALL` then `SETUID`, `SETGID`, `SYS_PTRACE`, `CHOWN`, `KILL`, `DAC_READ_SEARCH` | Only what root inside the container needs to trace, switch to the candidate user, plant decoys, read diffs and kill leftovers. The candidate user has no capabilities. |
| `--security-opt no-new-privileges` | setuid binaries cannot raise privileges. |
| `--pids-limit 256 --memory 1g --cpus 1` | Fork bombs and memory exhaustion stay inside. |
| `--init` | Orphaned processes are reaped, so zombies are not mistaken for persistence. |

The runner, strace and the sinkhole run as root inside the container. The
candidate runs as uid 1001 and cannot read `/tmp/run` (mode 700) where the
evidence is written, nor the runner's `/proc` entries.

## Entry points

| Kind | Runs automatically in Claude Code | How it is exercised |
| --- | --- | --- |
| Hook (`type: command`) | Yes, on its event | Shell form through `bash -c`, exec form as argv, with a sample event JSON on stdin |
| Hook (`type: http`) | Yes | Not run; reported as data sent to a remote URL |
| MCP stdio server | Yes, at startup | Started with `initialize`, `initialized` and `tools/list` on stdin |
| MCP remote / bundle URL | Yes | Not fetched; reported |
| LSP server | Yes | Started with empty stdin |
| Monitor | Yes (`when: always`) | `bash -c` |
| ``!`command` `` in SKILL.md | Yes, when the skill loads | `bash -c` |
| `bin/` file | When Claude runs that command | Run with no arguments; name checked against common commands |
| `package.json` install scripts | When dependencies are installed | `bash -c` |
| Other scripts (`.sh`, `.py`, `.js`, executables) | When called | Run with no arguments |

`${CLAUDE_PLUGIN_ROOT}`, `${CLAUDE_PLUGIN_DATA}` and `${CLAUDE_PROJECT_DIR}`
are substituted with sandbox paths; `${user_config.*}` becomes a placeholder.
At most 40 entry points run per plugin. Entry points that run on their own
(hooks, MCP and LSP servers, monitors, ``!`command` `` lines) go first; the
rest are listed as not run.

`report.json` has a `not_reviewed` list: the sandbox skipped with
`--static-only`, marketplace entries hosted elsewhere or missing from the
repository, remote MCP servers and bundles, and entry points cut by the cap.
The sandbox run is refused on a Windows host, because paths and execute bits
do not survive the transfer into the container.

## Decoys

Planted in the candidate's home and in a fake project: SSH keys and config,
`~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, the GitHub CLI token
file, `~/.npmrc`, Docker config, `~/.claude.json`, `~/.claude/settings.json`,
`~/.claude/CLAUDE.md`, shell rc files, a keychain file, and in the project
`.env`, `CLAUDE.md`, `.claude/settings.json`, `.mcp.json` and `.git/hooks/`.
Environment variables `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`,
`AWS_SECRET_ACCESS_KEY` and `NPM_TOKEN` carry canaries too.

Each secret holds a random canary. A canary found in DNS names or captured
payloads, raw, hex or base64 at any alignment, is reported as exfiltration.

## Finding categories

| Category | Severity | Source | Meaning |
| --- | --- | --- | --- |
| `exfiltration` | high | sandbox | A canary left through DNS or a connection |
| `credential_access` | high | sandbox | A decoy credential file was opened |
| `secret_staging` | high | sandbox | A canary was written into a new file |
| `config_tampering` | high | sandbox | Claude, shell, SSH or git-hook config changed |
| `persistence` | high | sandbox | Processes kept running after the entry point returned |
| `destructive` | high | sandbox | Files deleted outside the package, data dir and /tmp |
| `path_shadowing` | high | static | `bin/` file named like a common command |
| `hidden_unicode` | high/medium | static | Tag characters, bidi controls or zero-width characters |
| `remote_hook`, `remote_bundle` | high | static | Data sent to, or code fetched from, a remote URL |
| `path_escape`, `symlink` | high/info | static | Paths or links pointing outside the package |
| `plan_truncated` | high/medium | static | Entry points not run because of the cap; high if one runs on its own |
| `network` | medium | sandbox | DNS queries or connection attempts |
| `remote_source`, `missing_source` | medium | static | Marketplace entry hosted elsewhere, or pointing to a directory that is not there; not reviewed |
| `credential_probe` | medium | sandbox | Looked for credential files that do not exist |
| `process_snooping` | medium | sandbox | Read another process's environment |
| `suspicious_program` | medium | sandbox | Ran curl, wget, nc, ssh, base64, crontab, nohup... |
| `writes` | medium | sandbox | Wrote outside its own directories |
| `timeout` | medium | sandbox | Main process still running at the time limit |
| `binary`, `large_file` | medium | static | Compiled code or files over 5 MB |
| `pipe_to_shell`, `decode_and_run`, `sensitive_path`, `agent_config_write`, `permission_bypass` | medium | static | Text patterns; leads, not verdicts |
| `skill_shell_injection`, `install_script`, `mcp_bundle`, `remote_mcp` | medium | static | Code that runs at load or install time |
| `autorun`, `url`, `raw_ip`, `dynamic_code`, `hook` | info | static | Context |
