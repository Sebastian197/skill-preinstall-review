#!/usr/bin/env python3
"""Review a skill or plugin before installing it.

    review.py <path-or-git-url> [--out DIR] [--timeout SECONDS] [--static-only]

Takes a static inventory without executing anything, then runs every entry
point (hooks, MCP servers, scripts, bin/ files...) inside a Docker container
with no network, decoy secrets and syscall tracing. Writes report.md and
report.json. Exit codes: 0 report written, 2 usage or setup error.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inventory  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.normpath(os.path.join(HERE, "..", "sandbox"))
IMAGE_NAME = "preinstall-review-sandbox"
MAX_INPUT = 300 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024
IS_WINDOWS = os.name == "nt"
# Findings that mean part of the candidate was never looked at.
NOT_REVIEWED = ("remote_source", "missing_source", "remote_bundle", "remote_mcp", "plan_truncated")


def tool_version():
    manifest = inventory.load_json(os.path.join(HERE, "..", "..", "..", ".claude-plugin", "plugin.json"))
    version = manifest.get("version") if isinstance(manifest, dict) else None
    return version if isinstance(version, str) else "unknown"


HOME = "/home/candidate"
PROJECT = "/work/project"
OWN_DIRS = ("/work/plugin", "/work/data", "/tmp")

SECRET_DECOYS = (
    "/.ssh/id_", "/.aws/credentials", "/.netrc", "/.git-credentials", "/.config/gh/hosts.yml",
    "/.npmrc", "/.docker/config.json", "/.claude.json", "/Library/Keychains/", "/work/project/.env",
)
CONFIG_TARGETS = (
    f"{HOME}/.claude/", f"{HOME}/.claude.json", f"{PROJECT}/CLAUDE.md", f"{PROJECT}/.claude/",
    f"{PROJECT}/.mcp.json", f"{HOME}/.bashrc", f"{HOME}/.zshrc", f"{HOME}/.profile",
    f"{HOME}/.bash_profile", f"{HOME}/.ssh/", f"{PROJECT}/.git/hooks/", f"{HOME}/Library/LaunchAgents/",
    f"{HOME}/.config/autostart/",
)
NOISE_PREFIXES = (
    "/usr/", "/lib", "/bin/", "/sbin/", "/etc/ld.so", "/etc/nsswitch.conf", "/etc/localtime",
    "/etc/passwd", "/etc/group", "/etc/host.conf", "/etc/resolv.conf", "/etc/hosts", "/etc/gai.conf",
    "/etc/ssl/", "/etc/mime.types", "/etc/inputrc", "/etc/bash.bashrc", "/etc/profile",
    "/proc/self/", "/proc/thread-self/", "/sys/", "/dev/null", "/dev/urandom", "/dev/random",
    "/dev/tty", "/dev/pts", "/opt/spr/", "/etc/terminfo", "/etc/python3", "/etc/wgetrc", "/etc/gitconfig",
    "/etc/ssh/ssh_config",
)
SUSPICIOUS_PROGRAMS = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "socat", "telnet",
    "base64", "openssl", "crontab", "at", "security", "osascript", "launchctl", "systemctl",
    "nohup", "setsid", "disown", "xxd", "gpg",
}


# Source handling


def fetch_source(source, workdir):
    if re.match(r"^(https://|git@|ssh://)", source) or source.endswith(".git"):
        dest = os.path.join(workdir, "candidate")
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                        "clone", "--depth", "1", "--no-recurse-submodules", source, dest],
                       check=True, stdout=subprocess.DEVNULL)
        return dest
    path = os.path.abspath(os.path.expanduser(source))
    if not os.path.isdir(path):
        raise SystemExit(f"error: {source} is not a directory or a git URL")
    return path


# Docker


def docker_available():
    try:
        subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def image_tag():
    h = hashlib.sha256()
    for name in sorted(os.listdir(SANDBOX_DIR)):
        with open(os.path.join(SANDBOX_DIR, name), "rb") as fh:
            h.update(name.encode() + b"\0" + fh.read())
    return f"{IMAGE_NAME}:{h.hexdigest()[:12]}"


def ensure_image():
    tag = image_tag()
    exists = subprocess.run(["docker", "image", "inspect", tag], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode == 0
    if not exists:
        print(f"building sandbox image {tag} (first run only)...", file=sys.stderr)
        subprocess.run(["docker", "build", "-q", "-t", tag, SANDBOX_DIR], check=True, stdout=subprocess.DEVNULL)
    return tag


def build_input(plugin_root, entries, plan_entries, timeout, nonce):
    buf = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=buf, mode="w") as tar:
        plan = json.dumps({"nonce": nonce, "timeout": timeout, "entries": plan_entries}).encode()
        info = tarfile.TarInfo("plan.json")
        info.size = len(plan)
        tar.addfile(info, io.BytesIO(plan))
        for e in entries:
            name = "candidate/" + e["path"]
            path = os.path.join(plugin_root, e["path"])
            if e["kind"] == "dir":
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            elif e["kind"] == "symlink":
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = e["target"]
                tar.addfile(info)
            elif e["kind"] == "file":
                total += e["size"]
                if total > MAX_INPUT:
                    raise SystemExit("error: candidate is larger than the 300 MB sandbox limit")
                info = tarfile.TarInfo(name)
                info.size = e["size"]
                info.mode = 0o755 if e["mode"] & 0o111 else 0o644
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def run_sandbox(tag, payload, nonce, timeout, n_entries):
    name = "spr-" + nonce[:12]
    cmd = [
        "docker", "run", "--rm", "-i", "--init", "--name", name,
        "--network", "none", "--dns", "127.0.0.1",
        "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
        "--cap-add", "SYS_PTRACE", "--cap-add", "CHOWN", "--cap-add", "KILL",
        "--cap-add", "DAC_READ_SEARCH",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,size=256m,mode=1777",
        "--tmpfs", "/work:rw,exec,size=512m",
        "--tmpfs", f"{HOME}:rw,exec,size=64m,mode=755",
        "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
        tag,
    ]
    budget = n_entries * (timeout + 10) + 60
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(payload, timeout=budget)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.communicate()
        raise SystemExit(f"error: sandbox exceeded its {budget}s budget and was killed") from None
    marker = f"SPR-RESULT {nonce} ".encode()
    for line in out[:MAX_OUTPUT].splitlines():
        if line.startswith(marker):
            return json.loads(line[len(marker):].decode("utf-8"))
    raise SystemExit("error: sandbox produced no result\n" + err.decode("utf-8", "replace")[-2000:])


# Trace parsing

LINE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unescape(s):
    return re.sub(r"\\x([0-9a-fA-F]{2})|\\(.)",
                  lambda m: chr(int(m.group(1), 16)) if m.group(1) else
                  {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(2), m.group(2)), s)


def parse_trace(text):
    events = []
    for raw in text.splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        call, args, ret, errno = m.groups()
        ok = ret != "?" and not ret.startswith("-")
        strings = [unescape(s) for s in QUOTED.findall(args)]
        ev = {"call": call, "ok": ok, "errno": errno}
        if call in ("execve", "execveat"):
            argv_part = args[args.find("["):args.find("]") + 1] if "[" in args else ""
            ev["path"] = strings[0] if strings else ""
            ev["argv"] = [unescape(s) for s in QUOTED.findall(argv_part)]
        elif call in ("open", "openat", "creat"):
            ev["path"] = strings[0] if strings else ""
            flag_text = args.split('",', 1)[1] if '",' in args else ""
            ev["write"] = call == "creat" or any(f in flag_text for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
        elif call in ("unlink", "unlinkat", "mkdir", "mkdirat", "chmod", "fchmodat"):
            ev["path"] = strings[0] if strings else ""
        elif call in ("rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat"):
            ev["path"] = strings[0] if strings else ""
            ev["path2"] = strings[1] if len(strings) > 1 else ""
        elif call in ("connect", "sendto", "sendmsg", "bind"):
            fam = re.search(r"sa_family=(\w+)", args)
            port = re.search(r"sin6?_port=htons\((\d+)\)", args)
            addr = re.search(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', args)
            ev["family"] = fam.group(1) if fam else None
            ev["port"] = int(port.group(1)) if port else None
            ev["addr"] = (addr.group(1) or addr.group(2)) if addr else None
            if ev["family"] == "AF_UNIX":
                ev["addr"] = strings[0] if strings else None
        events.append(ev)
    return events


# Findings from the sandbox


def encodings(token):
    """Forms a canary takes when sent raw, hex-encoded or base64-encoded.

    Inside a larger base64 blob the token can start at any of three byte
    alignments; the characters that depend only on token bytes are the ones
    kept here, so a match holds whatever surrounds the token.
    """
    raw = token.encode()
    forms = {token, token.lower(), raw.hex(), raw.hex().upper()}
    for pad in (b"", b"A", b"AA"):
        b = base64.b64encode(pad + raw).decode()
        core = b[:-4] if not pad else b[4:-4]
        forms.add(core)
        forms.add(core.replace("+", "-").replace("/", "_"))
    return {f for f in forms if len(f) >= 12}


def leaked_canaries(text, canaries):
    found = []
    for label, token in canaries.items():
        if any(form in text for form in encodings(token)):
            found.append(label)
    return found


def classify_entry(entry, result, canaries):
    findings = []
    label = entry["label"]

    def add(severity, category, title, detail="", **evidence):
        findings.append({"severity": severity, "category": category, "title": f"{label}: {title}",
                         "detail": detail, "evidence": evidence, "source": "sandbox", "entry": entry["id"]})

    events = []
    for pid, text in result["traces"].items():
        for ev in parse_trace(text):
            ev["pid"] = pid
            events.append(ev)

    net_text = json.dumps(result["net"])
    leaks = leaked_canaries(net_text, canaries)
    if leaks:
        add("high", "exfiltration", "sent decoy secrets over the network",
            "Canary values planted in fake credentials left the process in a DNS query or a connection.",
            canaries=leaks, network=result["net"][:20])

    dns = sorted({r["name"] for r in result["net"] if r.get("kind") == "dns"})
    tcp = [r for r in result["net"] if r.get("kind") == "tcp"]
    remote = sorted({f"{e['addr']}:{e['port']}" for e in events
                     if e["call"] == "connect" and e.get("family") in ("AF_INET", "AF_INET6")
                     and e.get("addr") not in ("127.0.0.1", "127.0.0.2", "::1")})
    if dns or tcp or remote:
        add("medium", "network", "tried to reach the network",
            "The sandbox has no network; these are attempts, answered by a local sinkhole or refused.",
            dns_names=dns[:50], connections=[{k: r.get(k) for k in ("port", "http_host", "tls_sni", "request_line")} for r in tcp][:20],
            direct_addresses=remote[:50])

    opened = [e for e in events if e["call"] in ("open", "openat", "creat") and e.get("path")]
    secret_reads = sorted({e["path"] for e in opened if e["ok"] and _is_secret(e["path"])})
    secret_probes = sorted({e["path"] for e in opened if not e["ok"] and _is_secret_like(e["path"])})
    if secret_reads:
        add("high", "credential_access", "opened decoy credential files",
            "These files exist only as bait. Nothing in a skill's normal job needs them.",
            paths=secret_reads)
    if secret_probes:
        add("medium", "credential_probe", "looked for credential files that do not exist", paths=secret_probes[:30])
    env_reads = [e["path"] for e in opened if re.match(r"^/proc/(\d+|1)/environ$", e["path"])]
    if env_reads:
        add("medium", "process_snooping", "read another process's environment", paths=sorted(set(env_reads)))

    changes = result["fs_changes"]
    config = [c for c in changes if any(c["path"].startswith(t) or c["path"] == t.rstrip("/") for t in CONFIG_TARGETS)]
    if config:
        add("high", "config_tampering", "changed agent, shell or SSH configuration",
            "Writes here persist after the session and can change what Claude or your shell does next.",
            changes=[{k: c.get(k) for k in ("path", "change", "content_head", "link_target")} for c in config])
    removed = [c["path"] for c in changes if c["change"] == "removed" and not c["path"].startswith(OWN_DIRS)]
    if removed:
        add("high", "destructive", "deleted files outside its own directories", paths=removed[:50])
    other_writes = [c["path"] for c in changes if c not in config and c["change"] != "removed"
                    and not c["path"].startswith(OWN_DIRS)]
    if other_writes:
        add("medium", "writes", "wrote files outside its own directories", paths=other_writes[:50])
    staged = [c["path"] for c in changes if leaked_canaries(c.get("content_head", ""), canaries)]
    if staged:
        add("high", "secret_staging", "copied decoy secret values into new files", paths=staged)

    background = result.get("background_processes") or []
    if not entry.get("long_running"):
        background = background or result["leftover_processes"]
    if background:
        add("high", "persistence", "left processes running after it finished",
            "The entry point returned but something it started kept running. A hook or script that does "
            "this is trying to stay resident.", processes=background[:20])

    programs = []
    for e in events:
        if e["call"] in ("execve", "execveat") and e["ok"]:
            prog = os.path.basename(e["path"])
            programs.append(" ".join(e.get("argv") or [e["path"]])[:300])
            if prog in SUSPICIOUS_PROGRAMS:
                add("medium", "suspicious_program", f"ran {prog}", command=" ".join(e.get("argv") or [])[:300])
    interesting_reads = sorted({e["path"] for e in opened if e["ok"] and not e.get("write")
                                and not e["path"].startswith(NOISE_PREFIXES)
                                and not e["path"].startswith("/work/plugin") and not _is_secret(e["path"])})
    if result["timed_out"] and result.get("main_still_running") and not entry.get("long_running"):
        add("medium", "timeout", "was still running when the time limit hit",
            "Behavior after the limit was not observed.")
    summary = {
        "id": entry["id"], "label": label, "kind": entry["kind"], "autorun": entry.get("autorun", False),
        "argv": entry["argv"], "exit_code": result["exit_code"], "timed_out": result["timed_out"],
        "duration_s": result["duration_s"], "programs": _dedupe(programs)[:40],
        "files_read": [p for p in interesting_reads][:60],
        "stdout_head_untrusted": result["stdout_head"][:2000], "stderr_head_untrusted": result["stderr_head"][:2000],
        "traces_truncated": result["traces_truncated"],
    }
    return findings, summary


def _is_secret(path):
    return any(marker in path for marker in SECRET_DECOYS)


def _is_secret_like(path):
    return _is_secret(path) or bool(re.search(r"/\.ssh/|/\.aws/|/\.gnupg/|/\.kube/config|credentials|\.pem$|\.key$", path))


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# Report

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def render_markdown(report):
    lines = [f"# Pre-install review: {report['target']}", ""]
    lines.append(f"- Source: `{report['source']}`")
    lines.append(f"- Layout: {report['layout']}")
    lines.append(f"- Sandbox: {report['sandbox']}")
    lines.append(f"- Reviewed at: {report['reviewed_at']}")
    lines.append("")
    counts = {s: sum(1 for f in report["findings"] if f["severity"] == s) for s in SEVERITY_ORDER}
    lines.append(f"**Findings:** {counts['high']} high, {counts['medium']} medium, {counts['info']} info.")
    lines.append("")
    lines.append("> No finding is not the same as safe. The sandbox only sees what ran during this review; "
                 "see the limits section.")
    lines.append("")
    if report["not_reviewed"]:
        lines.append("## Not reviewed")
        lines.append("")
        for item in report["not_reviewed"]:
            lines.append(f"- {item}")
        lines.append("")
    for plugin in report["plugins"]:
        lines.append(f"## Declared: {plugin['name']}")
        manifest = plugin["manifest"]
        if manifest.get("description"):
            lines.append(f"- Plugin description: {manifest['description']}")
        for skill in plugin["skills"]:
            lines.append(f"- Skill `{skill.get('name', skill['dir'])}`: {skill.get('description', '(no description)')}")
            if skill.get("allowed-tools"):
                lines.append(f"  - allowed-tools: {skill['allowed-tools']}")
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f in sorted(report["findings"], key=lambda f: SEVERITY_ORDER[f["severity"]]):
        lines.append(f"### [{f['severity'].upper()}] {f['title']}")
        if f.get("detail"):
            lines.append(f["detail"])
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(f["evidence"], indent=2, ensure_ascii=True)[:3000])
        lines.append("```")
        lines.append("")
    lines.append("## What ran")
    lines.append("")
    for s in report["entries"]:
        flag = "runs automatically" if s["autorun"] else "runs when called"
        status = "timed out" if s["timed_out"] else f"exit {s['exit_code']}"
        lines.append(f"- **{s['label']}** ({s['kind']}, {flag}): {status} in {s['duration_s']}s")
        for p in s["programs"][:10]:
            lines.append(f"  - exec `{p}`")
        for p in s["files_read"][:10]:
            lines.append(f"  - read `{p}`")
    if not report["entries"]:
        lines.append("Sandbox skipped." if report["sandbox"].startswith("skipped") else "Nothing was executed.")
    lines.append("")
    lines.append("## Limits of this review")
    lines.append("")
    for limit in LIMITS:
        lines.append(f"- {limit}")
    lines.append("")
    return "\n".join(lines)


LIMITS = [
    "Each entry point ran once, with no arguments and sample input. Code that waits for a date, a specific "
    "argument, a real project, or many runs before acting was not triggered.",
    "Code can detect that it runs in a container and behave well only here.",
    "Instructions in SKILL.md are text for Claude. What Claude would do after reading them is not executed "
    "here; read the static findings and the skill text for that.",
    "Remote sources (MCP bundle URLs, remote MCP servers, marketplace entries hosted elsewhere, packages "
    "fetched at runtime) were not downloaded or reviewed.",
    "The container shares the kernel of Docker's VM (macOS, Windows) or of the host (Linux). A kernel "
    "exploit is out of scope.",
    "Pattern matches in the static scan are leads, not verdicts: legitimate tools use subprocess, URLs and "
    "base64 too.",
]


# Main


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("source", help="local directory or git URL of the skill, plugin or marketplace")
    ap.add_argument("--out", help="directory for report.md and report.json")
    ap.add_argument("--timeout", type=int, default=15, help="seconds per entry point (default 15)")
    ap.add_argument("--static-only", action="store_true", help="skip the sandbox")
    args = ap.parse_args(argv)

    workdir = tempfile.mkdtemp(prefix="preinstall-review-")
    try:
        root = fetch_source(args.source, workdir)
        layout, targets, findings = inventory.detect_targets(root)
        all_entries = inventory.walk(root)
        findings += inventory.scan_files(root, all_entries)

        sandbox_state = "skipped (--static-only)" if args.static_only else "docker"
        tag = None
        if not args.static_only:
            if IS_WINDOWS:
                print("error: the sandbox run is not supported on a Windows host yet: paths and execute bits do not "
                      "survive the transfer, so entry points would fail to start and the report would miss them. "
                      "Run the review from macOS, Linux or WSL, or pass --static-only for a static review "
                      "(much weaker: it cannot see what the code does).", file=sys.stderr)
                return 2
            if not docker_available():
                print("error: Docker is not running. Start Docker, or pass --static-only for a static review "
                      "(much weaker: it cannot see what the code does).", file=sys.stderr)
                return 2
            tag = ensure_image()
            sandbox_state = f"docker, image {tag}, no network, decoy secrets, strace"

        plugins, summaries = [], []
        for name, plugin_root in targets:
            comps = inventory.plugin_components(plugin_root)
            entries = inventory.walk(plugin_root)
            plan, notes = inventory.entry_points(plugin_root, comps, entries)
            findings += notes
            plugins.append({"name": comps["manifest"].get("name") or name, "root": os.path.relpath(plugin_root, root),
                            "manifest": {k: comps["manifest"].get(k) for k in ("name", "version", "description", "author", "repository")
                                         if comps["manifest"].get(k)},
                            "skills": comps["skills"], "hooks": len(comps["hooks"]), "mcp": len(comps["mcp"]),
                            "monitors": len(comps["monitors"]), "bin": comps["bin"]})
            if tag and plan:
                nonce = secrets.token_hex(16)
                payload = build_input(plugin_root, entries, plan, args.timeout, nonce)
                result = run_sandbox(tag, payload, nonce, args.timeout, len(plan))
                if result.get("sinkhole_errors"):
                    findings.append(inventory.finding("info", "sandbox", "Sinkhole could not open some ports",
                                                      errors=result["sinkhole_errors"]))
                for entry, res in zip(plan, result["entries"]):
                    f, s = classify_entry(entry, res, result["canaries"])
                    findings += f
                    summaries.append(s)

        not_reviewed = [f["title"] for f in findings if f["category"] in NOT_REVIEWED]
        if args.static_only:
            not_reviewed.insert(0, "The sandbox did not run (--static-only): no code was executed, so its "
                                   "behavior was not observed.")
        target_name = plugins[0]["name"] if len(plugins) == 1 else os.path.basename(os.path.abspath(root))
        report = {
            "tool": f"preinstall-review {tool_version()}", "target": target_name, "source": args.source,
            "layout": layout, "sandbox": sandbox_state, "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "not_reviewed": not_reviewed,
            "plugins": plugins, "findings": sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]]),
            "entries": summaries, "limits": LIMITS,
        }
        out = args.out or os.path.join(os.getcwd(), f"preinstall-review-{re.sub(r'[^A-Za-z0-9_.-]', '_', target_name)}")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=True)
        with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
        print(json.dumps({"report_md": os.path.join(out, "report.md"), "report_json": os.path.join(out, "report.json"),
                          "high": counts["high"], "medium": counts["medium"], "info": counts["info"],
                          "entry_points_run": len(summaries)}))
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
