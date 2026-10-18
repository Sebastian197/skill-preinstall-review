# Skill pre-install review

Review a third-party skill, plugin or plugin marketplace **before** you
install it. The skill runs the package's code inside a locked Docker
container with no network, fake credentials and syscall tracing, then tells
you what the code actually did next to what it claims to do, with a verdict
and the evidence behind it.

**Claude Code only.** The review needs a local shell, Python 3 and Docker,
so it does not run on claude.ai or in Cowork.

## How to use it

Ask before installing something, for example: "review this plugin before I
install it: https://github.com/someone/some-plugin". You get a verdict (do
not install, install after checking, or no problems observed), a table of
declared versus observed behavior, and `report.md` / `report.json` with the
full evidence. It never calls a package safe: anything the run did not
trigger was not observed.

## What it detects

- Network attempts, through a local DNS and TCP sinkhole that records the
  hostnames and the first bytes sent.
- Reads of decoy SSH keys, cloud and Git credentials, tokens and `.env`
  files, and those canary values leaving in any encoding.
- Changes to `CLAUDE.md`, `.claude/settings.json`, shell rc files, SSH
  config and git hooks.
- Processes left running after a hook or script returned.
- Statically: everything that runs on its own (hooks, MCP and LSP servers,
  monitors, `bin/` files, install scripts, `` !`command` `` lines), invisible
  Unicode used to smuggle instructions, symlinks escaping the package,
  `bin/` files that shadow commands like `git`, HTTP hooks and remote MCP
  bundles.

## What this plugin runs, sends and fetches

The plugin has no hooks, MCP servers or background processes. When the skill
is used, Claude runs `scripts/review.py`, which:

- runs `git clone --depth 1` on the repository you ask it to review (git
  hooks disabled, no submodules) into a temporary directory;
- on first use, runs `docker build` on `sandbox/Dockerfile`, which downloads
  the pinned `debian:bookworm-slim` image and Debian packages (strace,
  python3, nodejs, curl and others) from their public mirrors;
- runs the reviewed package's code in a Docker container started with
  `--network none`, a read-only root filesystem, all capabilities dropped
  except the few the in-container tracer needs, and resource limits; the
  container is removed when the run ends;
- writes `report.md` and `report.json` to a local directory.

It sends nothing anywhere: no telemetry, no uploads. The container has no
network, and nothing from your machine is mounted into it; the reviewed
package is passed in as a tar stream.

## Limits

Each entry point runs once with sample input, so code keyed to a date, an
argument or a real project is not triggered. Code can detect the container.
What Claude would do after reading a skill's instructions is not executed.
Remote content is not fetched. The container shares a kernel with Docker's
VM or the Linux host.

Source, tests and details: https://github.com/Sebastian197/skill-preinstall-review

## License

Apache-2.0
