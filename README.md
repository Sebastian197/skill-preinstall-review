# skill-preinstall-review

Review a third-party Claude Code skill, plugin or plugin marketplace
**before** you install it. The review runs the package's code inside a locked
Docker container with no network, fake credentials and syscall tracing, then
reports what the code actually did next to what it claims to do.

## Why

A skill or plugin runs with your agent's permissions: it can read your files
and credentials, reach the network and rewrite your agent's configuration.
Marketplaces have already shipped malicious skills at scale: Koi Security
found 341 malicious skills among the 2,857 on ClawHub in February 2026
([CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-openclaw-clawhub-supply-chain-risk-2026070/)).
Scanners that only read package files can be evaded: in the SkillCloak study
from HKUST, a packing technique got past every scanner tested more than 90%
of the time
([Help Net Security](https://www.helpnetsecurity.com/2026/07/09/malicious-ai-agent-skills-scan/)).
This tool watches behavior instead of reading text alone.

## What it checks

**Static, nothing executed:** plugin layout and every component that runs on
its own (hooks, MCP servers, LSP servers, monitors, `bin/` files, install
scripts, ``!`command` `` lines in SKILL.md); invisible Unicode used to smuggle
instructions (tag characters are decoded); symlinks and paths escaping the
package; `bin/` files that shadow commands like `git`; HTTP hooks and remote
MCP bundles; binaries, oversized files and suspicious text patterns.

**Sandbox, every entry point run once as an unprivileged user:**

- network attempts, answered by a local DNS and TCP sinkhole that logs the
  hostnames and the first bytes sent;
- decoy SSH keys, cloud and Git credentials, tokens, `.env` and Claude
  configuration, each with a unique canary, found again in traffic raw, hex
  or base64;
- files changed in the home directory and the project, including
  `CLAUDE.md`, `.claude/settings.json`, shell rc files and git hooks;
- processes left running after a hook or script returned;
- programs executed and files read.

See [how-it-works.md](plugins/skill-preinstall-review/skills/preinstall-review/references/how-it-works.md)
for the container settings and the full list of finding categories.

## Requirements

- Docker (Docker Desktop on macOS and Windows, or the Docker engine on
  Linux). The first run builds the sandbox image and needs network for that.
- Python 3 on the host. Standard library only.

Tested on macOS 13 (Intel) with Docker Engine 20.10.22 and Python 3.11.

## Install

As a Claude Code plugin:

```text
/plugin marketplace add Sebastian197/skill-preinstall-review
/plugin install skill-preinstall-review@skill-preinstall-review
```

As a standalone skill, for agents that read the Agent Skills format:

```bash
npx skills add Sebastian197/skill-preinstall-review
```

## Use

Ask Claude before installing something, for example: "review this skill
before I install it: https://github.com/someone/some-skill". The skill runs
the review and answers with a verdict, a declared-vs-observed table and the
evidence.

The script also works on its own:

```bash
python3 plugins/skill-preinstall-review/skills/preinstall-review/scripts/review.py \
  https://github.com/someone/some-skill --out ./review
```

It writes `report.md` and `report.json` and prints a one-line JSON summary.
`--timeout` sets seconds per entry point (default 15). `--static-only` skips
the sandbox and is much weaker.

## Limits

No finding does not mean safe.

- Each entry point runs once with sample input. Code keyed to a date, an
  argument, a real project or repeated runs is not triggered.
- Code can detect the container and behave only here.
- SKILL.md instructions are text for the model. What Claude would do after
  reading them is not executed; the static scan covers part of that.
- Remote content (MCP bundle URLs, remote MCP servers, marketplace entries
  hosted elsewhere, dependencies downloaded at runtime) is not fetched.
- The container shares a kernel with Docker's VM or the Linux host; kernel
  exploits are out of scope.

## Tests

```bash
cd tests && python3 -m unittest -v
```

The end-to-end tests run the real sandbox and are skipped when Docker is
not running. `tests/fixtures/exfil-plugin` imitates a malicious plugin so the
sandbox has something to catch. Its scripts exit immediately unless they run
as the sandbox's `candidate` user, so they do nothing on a real machine. Your
own security tools may still flag them.

## License

Apache-2.0
