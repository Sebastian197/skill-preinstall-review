"""In-container runner for preinstall-review.

Reads a tar stream on stdin holding plan.json and candidate/, plants decoy
secrets, then runs every entry point from the plan under strace as the
unprivileged `candidate` user. Writes one result line to stdout:

    SPR-RESULT <nonce> <json>

The runner, strace and the sinkhole run as root inside the container. The
candidate runs as uid 1001, so it cannot read /tmp/run (mode 700) or the
runner's /proc entries, and cannot forge the evidence.
"""

import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sinkhole import Sinkhole  # noqa: E402

RUN_DIR = "/tmp/run"
PLUGIN = "/work/plugin"
DATA = "/work/data"
PROJECT = "/work/project"
HOME = "/home/candidate"
CANDIDATE_UID = 1001

SNAPSHOT_ROOTS = (HOME, "/work", "/tmp")
HASH_LIMIT = 2 * 1024 * 1024
HEAD_LIMIT = 8 * 1024
TRACE_LIMIT = 4 * 1024 * 1024

TRACED = ",".join([
    "execve", "execveat", "open", "openat", "creat", "unlink", "unlinkat",
    "rename", "renameat", "renameat2", "connect", "sendto", "sendmsg", "bind",
    "chmod", "fchmodat", "symlink", "symlinkat", "link", "linkat", "mkdir", "mkdirat",
])


def main():
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    os.chmod(RUN_DIR, 0o700)
    plan = extract_input(sys.stdin.buffer)
    nonce = plan["nonce"]
    canaries, decoy_paths = plant_decoys()
    chown_tree("/work")
    chown_tree(HOME)

    net_log = os.path.join(RUN_DIR, "net.jsonl")
    open(net_log, "w").close()
    Sinkhole(net_log).start()
    time.sleep(0.2)

    results = []
    for index, entry in enumerate(plan["entries"]):
        results.append(run_entry(index, entry, plan, canaries, net_log))

    out = {
        "nonce": nonce,
        "canaries": canaries,
        "decoy_paths": decoy_paths,
        "entries": results,
        "sinkhole_errors": [r for r in read_net(net_log, 0)[0] if r.get("kind") == "sinkhole_error"],
    }
    sys.stdout.write("SPR-RESULT " + nonce + " " + json.dumps(out) + "\n")
    sys.stdout.flush()


# Input


def extract_input(stream):
    """Unpack plan.json and candidate/ from the host's tar stream.

    The host builds this tar from an lstat walk, so names are already
    relative and free of "..". Symlinks are created last so that no regular
    member can be written through one.
    """
    plan = None
    symlinks = []
    os.makedirs(PLUGIN, exist_ok=True)
    with tarfile.open(fileobj=stream, mode="r|") as tar:
        for member in tar:
            name = member.name
            if name == "plan.json":
                plan = json.loads(tar.extractfile(member).read().decode("utf-8"))
                continue
            if not name.startswith("candidate/") or ".." in name.split("/"):
                continue
            rel = name[len("candidate/"):]
            if not rel:
                continue
            dest = os.path.join(PLUGIN, rel)
            if member.issym():
                symlinks.append((dest, member.linkname))
            elif member.isdir():
                os.makedirs(dest, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    shutil.copyfileobj(tar.extractfile(member), fh)
                os.chmod(dest, 0o755 if member.mode & 0o111 else 0o644)
    for dest, target in symlinks:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if not os.path.lexists(dest):
            os.symlink(target, dest)
    if plan is None:
        raise SystemExit("plan.json missing from input")
    return plan


# Decoys


def plant_decoys():
    """Write fake secrets and agent config. Each carries its own canary."""
    canaries = {}

    def token(label):
        value = "SPRCANARY" + secrets.token_hex(10)
        canaries[label] = value
        return value

    files = {
        f"{HOME}/.ssh/id_ed25519": lambda: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + token("ssh_ed25519") + "\n-----END OPENSSH PRIVATE KEY-----\n",
        f"{HOME}/.ssh/id_rsa": lambda: "-----BEGIN RSA PRIVATE KEY-----\n" + token("ssh_rsa") + "\n-----END RSA PRIVATE KEY-----\n",
        f"{HOME}/.ssh/config": lambda: "Host prod\n  HostName 10.0.0.5\n  User deploy\n",
        f"{HOME}/.aws/credentials": lambda: "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = " + token("aws_file_secret") + "\n",
        f"{HOME}/.netrc": lambda: "machine api.github.com login bot password " + token("netrc") + "\n",
        f"{HOME}/.git-credentials": lambda: "https://bot:" + token("git_credentials") + "@github.com\n",
        f"{HOME}/.config/gh/hosts.yml": lambda: "github.com:\n  oauth_token: " + token("gh_cli") + "\n  user: bot\n",
        f"{HOME}/.npmrc": lambda: "//registry.npmjs.org/:_authToken=" + token("npmrc") + "\n",
        f"{HOME}/.docker/config.json": lambda: json.dumps({"auths": {"ghcr.io": {"auth": token("docker")}}}),
        f"{HOME}/.claude.json": lambda: json.dumps({"oauthAccount": {"accessToken": token("claude_json")}}),
        f"{HOME}/.claude/settings.json": lambda: json.dumps({"permissions": {"allow": []}}, indent=2),
        f"{HOME}/.claude/CLAUDE.md": lambda: "# Personal instructions\n",
        f"{HOME}/.bashrc": lambda: "# bashrc\n",
        f"{HOME}/.zshrc": lambda: "# zshrc\n",
        f"{HOME}/.profile": lambda: "# profile\n",
        f"{HOME}/Library/Keychains/login.keychain-db": lambda: token("keychain"),
        f"{PROJECT}/.env": lambda: "DATABASE_URL=postgres://app:" + token("dotenv") + "@db/app\n",
        f"{PROJECT}/CLAUDE.md": lambda: "# Project instructions\n",
        f"{PROJECT}/.claude/settings.json": lambda: json.dumps({"hooks": {}}, indent=2),
        f"{PROJECT}/.mcp.json": lambda: json.dumps({"mcpServers": {}}),
        f"{PROJECT}/.git/config": lambda: "[remote \"origin\"]\n\turl = https://github.com/acme/app.git\n",
        f"{PROJECT}/src/app.py": lambda: "print('hello')\n",
    }
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content())
    os.makedirs(f"{PROJECT}/.git/hooks", exist_ok=True)
    os.makedirs(DATA, exist_ok=True)
    os.chmod(f"{HOME}/.ssh", 0o700)
    for env_name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN",
                     "AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"):
        token("env_" + env_name)
    return canaries, sorted(files)


def chown_tree(root):
    for dirpath, dirnames, filenames in os.walk(root):
        os.lchown(dirpath, CANDIDATE_UID, CANDIDATE_UID)
        for name in dirnames + filenames:
            os.lchown(os.path.join(dirpath, name), CANDIDATE_UID, CANDIDATE_UID)


# Running entries


def run_entry(index, entry, plan, canaries, net_log):
    before_net = count_lines(net_log)
    before = snapshot()
    trace_prefix = os.path.join(RUN_DIR, f"tr{index}")
    env = {
        "HOME": HOME, "USER": "candidate", "LOGNAME": "candidate", "SHELL": "/bin/bash",
        "PATH": f"{PLUGIN}/bin:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8", "TERM": "dumb",
        "CLAUDE_PLUGIN_ROOT": PLUGIN, "CLAUDE_PLUGIN_DATA": DATA, "CLAUDE_PROJECT_DIR": PROJECT,
        "ANTHROPIC_API_KEY": canaries["env_ANTHROPIC_API_KEY"],
        "OPENAI_API_KEY": canaries["env_OPENAI_API_KEY"],
        "GITHUB_TOKEN": canaries["env_GITHUB_TOKEN"],
        "AWS_SECRET_ACCESS_KEY": canaries["env_AWS_SECRET_ACCESS_KEY"],
        "NPM_TOKEN": canaries["env_NPM_TOKEN"],
    }
    env.update({k: str(v) for k, v in (entry.get("env") or {}).items()})
    cmd = ["strace", "-ff", "-qq", "-s", "256", "-u", "candidate", "-o", trace_prefix,
           "-e", "trace=" + TRACED, "-e", "signal=none", "--"] + entry["argv"]
    cwd = entry.get("cwd") or PROJECT
    timeout = float(plan.get("timeout", 15))
    started = time.time()
    timed_out = False
    main_alive = False
    background = []
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate((entry.get("stdin") or "").encode("utf-8"), timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        # strace -f waits for every traced descendant, so a timeout also
        # happens when the entry returned but left something running. Tell
        # the two apart before killing anything.
        running = candidate_processes()
        main_alive = any(ppid == proc.pid for _, ppid, _ in running)
        if not main_alive:
            background = [cmd for _, _, cmd in running]
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    duration = round(time.time() - started, 2)
    leftovers = sweep_candidate_processes()
    after = snapshot()
    net, _ = read_net(net_log, before_net)
    traces, truncated = collect_traces(trace_prefix)
    return {
        "id": entry["id"],
        "argv": entry["argv"],
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "main_still_running": main_alive,
        "background_processes": background,
        "duration_s": duration,
        "stdout_head": stdout[:HEAD_LIMIT].decode("utf-8", "replace"),
        "stderr_head": stderr[:HEAD_LIMIT].decode("utf-8", "replace"),
        "leftover_processes": leftovers,
        "fs_changes": diff_snapshots(before, after),
        "net": [r for r in net if r.get("kind") != "sinkhole_error"],
        "traces": traces,
        "traces_truncated": truncated,
    }


def candidate_processes():
    """(pid, ppid, cmdline) for every live, non-zombie candidate process."""
    procs = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/status") as fh:
                fields = dict(l.split(":", 1) for l in fh.read().splitlines() if ":" in l)
            if int(fields["Uid"].split()[0]) != CANDIDATE_UID or fields["State"].split()[0] == "Z":
                continue
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            procs.append((int(pid), int(fields["PPid"]), cmdline[:300]))
        except (FileNotFoundError, ProcessLookupError, KeyError, ValueError):
            continue
    return procs


def sweep_candidate_processes():
    """Kill anything still running as the candidate user and report it.

    A process that outlives its entry point tried to stay resident.
    """
    seen = []
    for _ in range(5):
        found = False
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/status") as fh:
                    status = fh.read().splitlines()
                uid_line = next(l for l in status if l.startswith("Uid:"))
                state_line = next((l for l in status if l.startswith("State:")), "State: ?")
                if int(uid_line.split()[1]) != CANDIDATE_UID or state_line.split()[1] == "Z":
                    continue
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmdline = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
                os.kill(int(pid), signal.SIGKILL)
                seen.append(cmdline[:300])
                found = True
            except (FileNotFoundError, ProcessLookupError, StopIteration, PermissionError):
                continue
        if not found:
            break
        time.sleep(0.2)
    return seen


def collect_traces(prefix):
    directory, base = os.path.split(prefix)
    traces = {}
    budget = TRACE_LIMIT
    truncated = False
    for name in sorted(os.listdir(directory)):
        if not name.startswith(base + "."):
            continue
        with open(os.path.join(directory, name), "rb") as fh:
            data = fh.read(budget + 1)
        if len(data) > budget:
            data = data[:budget]
            truncated = True
        budget -= len(data)
        traces[name[len(base) + 1:]] = data.decode("utf-8", "replace")
        if budget <= 0:
            truncated = True
            break
    return traces, truncated


# Network log


def count_lines(path):
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def read_net(path, skip):
    records = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i < skip:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records, skip + len(records)


# Filesystem snapshots


def snapshot():
    state = {}
    for root in SNAPSHOT_ROOTS:
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath == RUN_DIR or dirpath.startswith(RUN_DIR + "/"):
                dirnames[:] = []
                continue
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                if path == RUN_DIR:
                    continue
                try:
                    st = os.lstat(path)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    state[path] = ("link", os.readlink(path))
                elif stat.S_ISDIR(st.st_mode):
                    state[path] = ("dir", stat.S_IMODE(st.st_mode))
                elif stat.S_ISREG(st.st_mode):
                    state[path] = ("file", st.st_size, stat.S_IMODE(st.st_mode), file_digest(path, st.st_size))
                else:
                    state[path] = ("other",)
    return state


def file_digest(path, size):
    if size > HASH_LIMIT:
        return "large"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def diff_snapshots(before, after):
    changes = []
    for path in sorted(set(before) | set(after)):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        kind = "added" if old is None else "removed" if new is None else "modified"
        change = {"path": path, "change": kind}
        if new and new[0] == "link":
            change["link_target"] = new[1]
        if new and new[0] == "file" and kind != "removed" and new[1] <= 64 * 1024:
            try:
                with open(path, "rb") as fh:
                    change["content_head"] = fh.read(512).decode("latin-1")
            except OSError:
                pass
        changes.append(change)
    return changes


if __name__ == "__main__":
    pwd.getpwnam("candidate")
    main()
