"""Static inventory of a candidate skill, plugin or marketplace.

Nothing here executes candidate code, and nothing follows a symlink: every
file is examined through lstat, and a symlink is reported with its target
instead of being read.
"""

import json
import os
import re
import stat

TEXT_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 1024 * 1024
LARGE_FILE = 5 * 1024 * 1024
MAX_ENTRY_POINTS = 40

PLUGIN_ROOT = "/work/plugin"
SUBSTITUTIONS = {
    "${CLAUDE_PLUGIN_ROOT}": PLUGIN_ROOT,
    "${CLAUDE_PLUGIN_DATA}": "/work/data",
    "${CLAUDE_PROJECT_DIR}": "/work/project",
}

SCRIPT_INTERPRETERS = {
    ".sh": ["bash"], ".bash": ["bash"], ".zsh": ["bash"],
    ".py": ["python3"],
    ".js": ["node"], ".mjs": ["node"], ".cjs": ["node"],
}

COMMON_COMMANDS = {
    "git", "ls", "cat", "cp", "mv", "rm", "curl", "wget", "python", "python3", "pip", "pip3",
    "node", "npm", "npx", "yarn", "pnpm", "bun", "sh", "bash", "zsh", "ssh", "scp", "sudo",
    "docker", "kubectl", "make", "go", "cargo", "claude", "gh", "grep", "find", "sed", "awk",
    "env", "open", "brew", "apt", "apt-get", "chmod", "chown", "tar", "unzip", "code",
}

HOOK_SAMPLE_TOOL = {"tool_name": "Bash", "tool_input": {"command": "ls"}}

MCP_INIT = "\n".join([
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "preinstall-review", "version": "0.1.0"}}}),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
]) + "\n"

HIDDEN_CHARS = {
    "zero_width": set(range(0x200B, 0x2010)) | set(range(0x2060, 0x2065)) | {0xFEFF, 0x00AD},
    "bidi_control": set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)),
    "unicode_tags": set(range(0xE0000, 0xE0080)),
    "variation_selector_supplement": set(range(0xE0100, 0xE01F0)),
}

PATTERNS = [
    ("pipe_to_shell", "medium", re.compile(r"\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b")),
    ("decode_and_run", "medium", re.compile(r"base64\s+(-d|--decode|-D)\b|b64decode\(|\batob\(|Buffer\.from\([^)]{0,80}['\"]base64")),
    ("dynamic_code", "info", re.compile(r"\beval\s*\(|new Function\(|\bexec\s*\(|os\.system\(|child_process|subprocess\.")),
    ("sensitive_path", "medium", re.compile(
        r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.git-credentials|\.config/gh|"
        r"find-(generic|internet)-password|login\.keychain|\.npmrc|\.docker/config\.json|"
        r"\.claude\.json|\.claude/settings|settings\.local\.json|\.bashrc|\.zshrc|\.bash_profile|"
        r"authorized_keys|crontab|LaunchAgents|LaunchDaemons|\.git/hooks")),
    ("agent_config_write", "medium", re.compile(r"(>>?|tee\s+(-a\s+)?|writeFile\w*\(|open\([^)]*['\"][wa])[^\n]{0,80}(CLAUDE\.md|settings\.json|\.mcp\.json)")),
    ("permission_bypass", "medium", re.compile(r"dangerously-skip-permissions|bypassPermissions|\"defaultMode\"\s*:\s*\"(bypassPermissions|acceptEdits)\"")),
    ("url", "info", re.compile(r"\bhttps?://[^\s'\"<>)\]}`]+")),
    ("raw_ip", "info", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

BINARY_MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
    (b"MZ", "Windows PE executable"),
    (b"\x00asm", "WebAssembly module"),
    (b"PK\x03\x04", "zip archive"),
    (b"\x1f\x8b", "gzip archive"),
]

SKILL_INJECTION = re.compile(r"!`([^`\n]+)`")


def finding(severity, category, title, detail="", **evidence):
    return {"severity": severity, "category": category, "title": title,
            "detail": detail, "evidence": evidence, "source": "static"}


# Walking


def walk(root):
    """List every entry under root without following symlinks."""
    entries = []
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            st = os.lstat(path)
            entry = {"path": rel, "size": st.st_size, "mode": stat.S_IMODE(st.st_mode)}
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(path)
                resolved = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(path)), target))
                entry.update(kind="symlink", target=target,
                             escapes=not _inside(os.path.realpath(resolved), real_root)
                             if not os.path.isabs(target) else True)
            elif stat.S_ISDIR(st.st_mode):
                entry["kind"] = "dir"
            elif stat.S_ISREG(st.st_mode):
                entry["kind"] = "file"
            else:
                entry["kind"] = "other"
            entries.append(entry)
    return entries


def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def read_regular(path, limit):
    """Read a regular file through lstat; return None for anything else."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    with open(path, "rb") as fh:
        return fh.read(limit)


def load_json(path):
    data = read_regular(path, JSON_LIMIT)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"__invalid_json__": True}


# Layout


def detect_targets(root):
    """Return (layout, plugin_roots, findings) for a candidate directory."""
    findings = []
    market = load_json(os.path.join(root, ".claude-plugin", "marketplace.json"))
    if isinstance(market, dict) and "plugins" in market:
        roots = []
        for entry in market.get("plugins") or []:
            if not isinstance(entry, dict):
                continue
            source = entry.get("source")
            name = entry.get("name", "?")
            if isinstance(source, str):
                path = os.path.normpath(os.path.join(root, source))
                if not _inside(os.path.realpath(path), os.path.realpath(root)):
                    findings.append(finding("high", "path_escape",
                                            f"Marketplace entry '{name}' points outside the repository",
                                            source=source))
                elif os.path.isdir(path):
                    roots.append((name, path))
                else:
                    findings.append(finding("medium", "missing_source",
                                            f"Marketplace entry '{name}' points to a directory that is not in the repository",
                                            "Nothing was reviewed for this entry.", source=source))
            else:
                findings.append(finding("medium", "remote_source",
                                        f"Marketplace entry '{name}' is fetched from elsewhere and was not reviewed",
                                        "Review that source on its own before installing it.",
                                        source=source))
        return "marketplace", roots, findings
    if os.path.isfile(os.path.join(root, "SKILL.md")) and not os.path.isdir(os.path.join(root, "skills")):
        return "skill", [(os.path.basename(os.path.abspath(root)), root)], findings
    return "plugin", [(os.path.basename(os.path.abspath(root)), root)], findings


# Components


def plugin_components(root):
    manifest = load_json(os.path.join(root, ".claude-plugin", "plugin.json")) or {}
    comps = {"manifest": manifest, "hooks": [], "mcp": [], "lsp": [], "monitors": [],
             "bin": [], "skills": [], "settings": None, "package_scripts": {}}

    hook_sources = []
    default_hooks = load_json(os.path.join(root, "hooks", "hooks.json"))
    if isinstance(default_hooks, dict):
        hook_sources.append(("hooks/hooks.json", default_hooks.get("hooks", {})))
    for item in _as_list(manifest.get("hooks")):
        if isinstance(item, str):
            data = load_json(_resolve(root, item))
            if isinstance(data, dict):
                hook_sources.append((item, data.get("hooks", {})))
        elif isinstance(item, dict):
            hook_sources.append(("plugin.json (inline)", item))
    for origin, event_map in hook_sources:
        if not isinstance(event_map, dict):
            continue
        for event, groups in event_map.items():
            for group in _as_list(groups):
                if not isinstance(group, dict):
                    continue
                for hook in _as_list(group.get("hooks")):
                    if isinstance(hook, dict):
                        comps["hooks"].append({"origin": origin, "event": event,
                                               "matcher": group.get("matcher"), **hook})

    mcp_sources = []
    default_mcp = load_json(os.path.join(root, ".mcp.json"))
    if isinstance(default_mcp, dict):
        mcp_sources.append((".mcp.json", default_mcp.get("mcpServers", default_mcp)))
    for item in _as_list(manifest.get("mcpServers")):
        if isinstance(item, str):
            if item.startswith("https://") or item.startswith("http://"):
                comps["mcp"].append({"origin": "plugin.json", "name": item, "bundle_url": item})
            elif item.endswith((".mcpb", ".dxt")):
                comps["mcp"].append({"origin": "plugin.json", "name": item, "bundle_path": item})
            else:
                data = load_json(_resolve(root, item))
                if isinstance(data, dict):
                    mcp_sources.append((item, data.get("mcpServers", data)))
        elif isinstance(item, dict):
            mcp_sources.append(("plugin.json (inline)", item))
    for origin, servers in mcp_sources:
        if isinstance(servers, dict):
            for name, conf in servers.items():
                if isinstance(conf, dict):
                    comps["mcp"].append({"origin": origin, "name": name, **conf})

    lsp_sources = []
    default_lsp = load_json(os.path.join(root, ".lsp.json"))
    if isinstance(default_lsp, dict):
        lsp_sources.append((".lsp.json", default_lsp))
    for item in _as_list(manifest.get("lspServers")):
        if isinstance(item, str):
            data = load_json(_resolve(root, item))
            if isinstance(data, dict):
                lsp_sources.append((item, data))
        elif isinstance(item, dict):
            lsp_sources.append(("plugin.json (inline)", item))
    for origin, servers in lsp_sources:
        for name, conf in servers.items():
            if isinstance(conf, dict):
                comps["lsp"].append({"origin": origin, "name": name, **conf})

    monitors = (manifest.get("experimental") or {}).get("monitors") if isinstance(manifest.get("experimental"), dict) else None
    monitors = monitors if monitors is not None else manifest.get("monitors")
    origin = "plugin.json"
    if isinstance(monitors, str):
        origin, monitors = monitors, load_json(_resolve(root, monitors))
    if monitors is None:
        origin, monitors = "monitors/monitors.json", load_json(os.path.join(root, "monitors", "monitors.json"))
    if isinstance(monitors, dict):
        monitors = monitors.get("monitors", [])
    for mon in _as_list(monitors):
        if isinstance(mon, dict):
            comps["monitors"].append({"origin": origin, **mon})

    bin_dir = os.path.join(root, "bin")
    if os.path.isdir(bin_dir) and not os.path.islink(bin_dir):
        for name in sorted(os.listdir(bin_dir)):
            comps["bin"].append(name)

    skill_dirs = []
    if os.path.isfile(os.path.join(root, "SKILL.md")):
        skill_dirs.append(root)
    for base in [os.path.join(root, "skills")] + [_resolve(root, s) for s in _as_list(manifest.get("skills")) if isinstance(s, str)]:
        if os.path.isfile(os.path.join(base, "SKILL.md")) and base not in skill_dirs:
            skill_dirs.append(base)
        elif os.path.isdir(base) and not os.path.islink(base):
            for name in sorted(os.listdir(base)):
                d = os.path.join(base, name)
                if os.path.isfile(os.path.join(d, "SKILL.md")) and d not in skill_dirs:
                    skill_dirs.append(d)
    for d in skill_dirs:
        comps["skills"].append({"dir": os.path.relpath(d, root), **skill_frontmatter(os.path.join(d, "SKILL.md"))})

    settings = load_json(os.path.join(root, "settings.json"))
    if settings is not None:
        comps["settings"] = settings
    package = load_json(os.path.join(root, "package.json"))
    if isinstance(package, dict) and isinstance(package.get("scripts"), dict):
        comps["package_scripts"] = {k: v for k, v in package["scripts"].items()
                                    if k in ("preinstall", "install", "postinstall", "prepare")}
    return comps


def skill_frontmatter(path):
    data = read_regular(path, TEXT_LIMIT)
    if data is None:
        return {}
    text = data.decode("utf-8", "replace")
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    meta = {}
    key = None
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            meta[key] = m.group(2).strip().strip("\"'")
        elif key and line.startswith((" ", "\t")):
            meta[key] = (meta[key] + " " + line.strip()).strip()
    return {k: meta[k] for k in ("name", "description", "allowed-tools", "license") if k in meta}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _resolve(root, rel):
    path = os.path.normpath(os.path.join(root, rel))
    return path if _inside(os.path.realpath(path), os.path.realpath(root)) else os.path.join(root, ".__escaped__")


# Static scanning


def scan_files(root, entries):
    findings = []
    for e in entries:
        if e["kind"] == "symlink":
            sev = "high" if e["escapes"] else "info"
            findings.append(finding(sev, "symlink",
                                    f"Symlink {e['path']} -> {e['target']}",
                                    "Points outside the package." if e["escapes"] else "",
                                    path=e["path"], target=e["target"]))
            continue
        if e["kind"] == "other":
            findings.append(finding("medium", "special_file", f"Special file {e['path']}", path=e["path"]))
            continue
        if e["kind"] != "file":
            continue
        path = os.path.join(root, e["path"])
        if e["size"] > LARGE_FILE:
            findings.append(finding("medium", "large_file",
                                    f"Large file {e['path']} ({e['size'] // 1024 // 1024} MB)",
                                    "Padding a package past scanner size limits is a known evasion.",
                                    path=e["path"], size=e["size"]))
        head = read_regular(path, 8192) or b""
        kind = next((label for magic, label in BINARY_MAGIC if head.startswith(magic)), None)
        if kind:
            findings.append(finding("medium", "binary", f"{kind}: {e['path']}",
                                    "Compiled code cannot be read here; its behavior is only what the sandbox observed.",
                                    path=e["path"]))
            continue
        if b"\0" in head:
            continue
        data = read_regular(path, TEXT_LIMIT)
        if data is None:
            continue
        text = data.decode("utf-8", "replace")
        findings.extend(scan_hidden(e["path"], text))
        findings.extend(scan_patterns(e["path"], text))
    return findings


def scan_hidden(rel, text):
    counts = {}
    tag_text = []
    for ch in text:
        cp = ord(ch)
        for label, chars in HIDDEN_CHARS.items():
            if cp in chars:
                counts[label] = counts.get(label, 0) + 1
                if label == "unicode_tags" and 0xE0020 <= cp <= 0xE007E:
                    tag_text.append(chr(cp - 0xE0000))
    if not counts:
        return []
    severity = "high" if any(k in counts for k in ("unicode_tags", "bidi_control", "variation_selector_supplement")) else "medium"
    evidence = {"path": rel, "counts": counts}
    if tag_text:
        evidence["decoded_tag_text_untrusted"] = "".join(tag_text)[:500]
    return [finding(severity, "hidden_unicode", f"Invisible characters in {rel}",
                    "Text a human reviewer cannot see but a model reads. Decoded text is untrusted data.",
                    **evidence)]


def scan_patterns(rel, text):
    hits = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for category, severity, rx in PATTERNS:
            for m in rx.finditer(line):
                bucket = hits.setdefault((category, severity), [])
                if len(bucket) < 10:
                    bucket.append({"line": lineno, "match": _printable(m.group(0))[:160],
                                   "context": _printable(line.strip())[:200]})
    return [finding(sev, cat, f"{cat.replace('_', ' ')} in {rel}", path=rel, hits=items)
            for (cat, sev), items in hits.items()]


def _printable(s):
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)


# Entry points


def substitute(value):
    if not isinstance(value, str):
        return value
    for key, repl in SUBSTITUTIONS.items():
        value = value.replace(key, repl)
    return re.sub(r"\$\{user_config\.[A-Za-z0-9_]+\}", "REVIEW_PLACEHOLDER", value)


def hook_stdin(event):
    payload = {"session_id": "preinstall-review", "transcript_path": "/work/data/transcript.jsonl",
               "cwd": "/work/project", "hook_event_name": event, "prompt": "list the files",
               "permission_mode": "default", **HOOK_SAMPLE_TOOL}
    return json.dumps(payload)


def entry_points(root, comps, entries):
    """Build the run plan plus static findings about what runs automatically."""
    plan, notes = [], []

    for i, hook in enumerate(comps["hooks"]):
        htype = hook.get("type", "command")
        label = f"hook {hook['event']}" + (f" [{hook['matcher']}]" if hook.get("matcher") else "")
        if htype == "command" and hook.get("command"):
            if isinstance(hook.get("args"), list):
                argv = [substitute(hook["command"])] + [substitute(a) for a in hook["args"]]
            else:
                argv = ["bash", "-c", substitute(hook["command"])]
            plan.append({"id": f"hook-{i}", "label": label, "kind": "hook", "autorun": True,
                         "argv": argv, "stdin": hook_stdin(hook["event"])})
        elif htype == "http":
            notes.append(finding("high", "remote_hook", f"{label} sends hook data to {hook.get('url')}",
                                 "Every matching event is posted to this URL, including tool inputs.",
                                 origin=hook["origin"], url=hook.get("url")))
        else:
            notes.append(finding("info", "hook", f"{label} of type '{htype}'", origin=hook["origin"]))

    for server in comps["mcp"]:
        name = server.get("name")
        if server.get("bundle_url"):
            notes.append(finding("high", "remote_bundle", f"MCP bundle downloaded at load time: {server['bundle_url']}",
                                 "Its content is not in the package and was not reviewed.", url=server["bundle_url"]))
            continue
        if server.get("bundle_path"):
            notes.append(finding("medium", "mcp_bundle", f"MCP bundle {server['bundle_path']} is extracted at load time",
                                 "Bundles are archives; their server code runs when Claude Code starts.", path=server["bundle_path"]))
            continue
        if server.get("url"):
            notes.append(finding("medium", "remote_mcp", f"Remote MCP server '{name}' at {server['url']}",
                                 "Tool calls and their arguments go to this host.", url=server["url"]))
            continue
        if server.get("command"):
            argv = [substitute(server["command"])] + [substitute(a) for a in _as_list(server.get("args"))]
            env = {k: substitute(v) for k, v in (server.get("env") or {}).items()} if isinstance(server.get("env"), dict) else {}
            plan.append({"id": f"mcp-{name}", "label": f"MCP server {name}", "kind": "mcp", "autorun": True,
                         "argv": argv, "env": env, "stdin": MCP_INIT, "long_running": True})

    for server in comps["lsp"]:
        if server.get("command"):
            argv = [substitute(server["command"])] + [substitute(a) for a in _as_list(server.get("args"))]
            plan.append({"id": f"lsp-{server['name']}", "label": f"LSP server {server['name']}", "kind": "lsp",
                         "autorun": True, "argv": argv, "stdin": "", "long_running": True})

    for i, mon in enumerate(comps["monitors"]):
        if mon.get("command"):
            plan.append({"id": f"monitor-{i}", "label": f"monitor {mon.get('name', i)}", "kind": "monitor",
                         "autorun": mon.get("when", "always") == "always",
                         "argv": ["bash", "-c", substitute(mon["command"])], "stdin": "", "long_running": True})

    for name in comps["bin"]:
        if name in COMMON_COMMANDS:
            notes.append(finding("high", "path_shadowing", f"bin/{name} shadows a common command",
                                 "Files in bin/ are on the Bash tool's PATH while the plugin is enabled, "
                                 f"so every '{name}' Claude runs would run this file instead.", path=f"bin/{name}"))
        plan.append({"id": f"bin-{name}", "label": f"bin/{name}", "kind": "bin", "autorun": False,
                     "argv": [f"{PLUGIN_ROOT}/bin/{name}"], "stdin": ""})

    for script, body in comps["package_scripts"].items():
        notes.append(finding("medium", "install_script", f"package.json '{script}' script",
                             "Runs when dependencies are installed.", command=body))
        plan.append({"id": f"npm-{script}", "label": f"package.json {script}", "kind": "package_script",
                     "autorun": False, "argv": ["bash", "-c", body], "stdin": "", "cwd": PLUGIN_ROOT})

    seen_scripts = {f"bin/{n}" for n in comps["bin"]}
    already_run = " ".join(" ".join(p["argv"]) for p in plan).replace('"', "").replace("'", "")
    for e in entries:
        if e["kind"] != "file" or e["path"] in seen_scripts or e["path"].startswith(("tests/", "test/", "node_modules/")):
            continue
        if f"{PLUGIN_ROOT}/{e['path']}" in already_run:
            continue
        ext = os.path.splitext(e["path"])[1].lower()
        executable = bool(e["mode"] & 0o111)
        if ext in SCRIPT_INTERPRETERS:
            argv = SCRIPT_INTERPRETERS[ext] + [f"{PLUGIN_ROOT}/{e['path']}"]
        elif executable:
            argv = [f"{PLUGIN_ROOT}/{e['path']}"]
        else:
            continue
        plan.append({"id": f"script-{e['path']}", "label": e["path"], "kind": "script", "autorun": False,
                     "argv": argv, "stdin": ""})

    for skill in comps["skills"]:
        data = read_regular(os.path.join(root, skill["dir"], "SKILL.md"), TEXT_LIMIT) or b""
        for i, m in enumerate(SKILL_INJECTION.finditer(data.decode("utf-8", "replace"))):
            command = m.group(1)
            notes.append(finding("medium", "skill_shell_injection",
                                 f"SKILL.md in {skill['dir']} runs a shell command when the skill loads",
                                 "The !`command` syntax runs before Claude sees the skill.", command=command))
            plan.append({"id": f"skillcmd-{skill['dir']}-{i}", "label": f"!`{command}` in {skill['dir']}/SKILL.md",
                         "kind": "skill_command", "autorun": True,
                         "argv": ["bash", "-c", substitute(command)], "stdin": ""})

    # Code that runs on its own goes first, so filler scripts cannot push it past the cap.
    plan = [p for p in plan if p["autorun"]] + [p for p in plan if not p["autorun"]]
    if len(plan) > MAX_ENTRY_POINTS:
        dropped = plan[MAX_ENTRY_POINTS:]
        severity = "high" if any(p["autorun"] for p in dropped) else "medium"
        notes.append(finding(severity, "plan_truncated",
                             f"{len(plan)} entry points found; only {MAX_ENTRY_POINTS} were run",
                             "Entry points that run on their own were run first.",
                             not_run=[p["label"] for p in dropped]))
        plan = plan[:MAX_ENTRY_POINTS]
    for kind in ("hook", "mcp", "lsp", "monitor", "skill_command"):
        auto = [p["label"] for p in plan if p["kind"] == kind and p["autorun"]]
        if auto:
            notes.append(finding("info", "autorun", f"Runs without being asked: {kind} ({len(auto)})",
                                 "These start on their own once the plugin is enabled.", items=auto))
    return plan, notes
