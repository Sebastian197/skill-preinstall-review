"""End-to-end: runs review.py against the fixtures in a real Docker sandbox.

Skipped when Docker is not available. Evidence level: separate OS
processes (host CLI + container), real syscall tracing.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from helpers import FIXTURES, SCRIPTS
import review

REVIEW = os.path.join(SCRIPTS, "review.py")


def run(fixture):
    out = tempfile.mkdtemp(prefix="spr-test-")
    proc = subprocess.run([sys.executable, REVIEW, os.path.join(FIXTURES, fixture), "--out", out, "--timeout", "8"],
                          capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        raise AssertionError(proc.stderr[-2000:])
    with open(os.path.join(out, "report.json")) as fh:
        return json.load(fh)


@unittest.skipUnless(review.docker_available(), "Docker is not running")
class SandboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exfil = run("exfil-plugin")
        cls.benign = run("benign-skill")

    def by(self, report, category):
        return [f for f in report["findings"] if f["category"] == category]

    def test_hook_exfiltrates_ssh_canary(self):
        hits = [f for f in self.by(self.exfil, "exfiltration") if f["entry"] == "hook-0"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"]["canaries"], ["ssh_ed25519"])

    def test_mcp_server_leaks_env_key_through_dns(self):
        hits = [f for f in self.by(self.exfil, "exfiltration") if f["entry"] == "mcp-formatter"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"]["canaries"], ["env_ANTHROPIC_API_KEY"])

    def test_hook_reads_decoy_credentials(self):
        hits = [f for f in self.by(self.exfil, "credential_access") if f["entry"] == "hook-0"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["evidence"]["paths"],
                         ["/home/candidate/.aws/credentials", "/home/candidate/.ssh/id_ed25519"])

    def test_hook_tampers_with_claude_config(self):
        hits = [f for f in self.by(self.exfil, "config_tampering") if f["entry"] == "hook-0"]
        self.assertEqual(len(hits), 1)
        paths = sorted(c["path"] for c in hits[0]["evidence"]["changes"])
        self.assertEqual(paths, ["/home/candidate/.claude/settings.json", "/work/project/CLAUDE.md"])

    def test_hook_leaves_background_process(self):
        hits = [f for f in self.by(self.exfil, "persistence") if f["entry"] == "hook-0"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(any("sleep 300" in p for p in hits[0]["evidence"]["processes"]))

    def test_only_the_hook_is_flagged_for_persistence(self):
        self.assertEqual([f["entry"] for f in self.by(self.exfil, "persistence")], ["hook-0"])

    def test_benign_skill_is_quiet(self):
        self.assertEqual(self.benign["findings"], [])
        self.assertEqual(self.benign["not_reviewed"], [])
        self.assertEqual(len(self.benign["entries"]), 1)
        self.assertEqual(self.benign["entries"][0]["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
