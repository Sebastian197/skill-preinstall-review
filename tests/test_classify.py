"""Trace parsing and canary matching, without Docker."""

import base64
import unittest

import helpers  # noqa: F401
import review

TOKEN = "SPRCANARY0123456789abcdef0123"


class CanaryTest(unittest.TestCase):
    def test_raw_hex_and_base64_at_every_alignment(self):
        canaries = {"k": TOKEN}
        self.assertEqual(review.leaked_canaries("x" + TOKEN + "y", canaries), ["k"])
        self.assertEqual(review.leaked_canaries(TOKEN.encode().hex()[:60] + ".d.test", canaries), ["k"])
        for prefix in ("", "a", "ab", "abc", "-----BEGIN KEY-----\n"):
            blob = base64.b64encode((prefix + TOKEN + "\n-----END-----").encode()).decode()
            self.assertEqual(review.leaked_canaries(blob, canaries), ["k"], prefix)
            url_blob = base64.urlsafe_b64encode((prefix + TOKEN).encode()).decode()
            self.assertEqual(review.leaked_canaries(url_blob, canaries), ["k"], prefix)

    def test_other_token_does_not_match(self):
        other = "SPRCANARYffffffffffffffffffff"
        blob = base64.b64encode(other.encode()).decode() + other.encode().hex()
        self.assertEqual(review.leaked_canaries(blob, {"k": TOKEN}), [])


class TraceParseTest(unittest.TestCase):
    def test_parse_lines(self):
        text = "\n".join([
            'execve("/usr/bin/curl", ["curl", "-s", "http://a.test/"], 0x7ffd /* 9 vars */) = 0',
            'openat(AT_FDCWD, "/home/candidate/.ssh/id_rsa", O_RDONLY) = 3',
            'openat(AT_FDCWD, "/home/candidate/.kube/config", O_RDONLY) = -1 ENOENT (No such file or directory)',
            'openat(AT_FDCWD, "/work/project/CLAUDE.md", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3',
            'connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH (Network is unreachable)',
            'renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/home/candidate/.bashrc", RENAME_NOREPLACE) = 0',
            'openat(AT_FDCWD, "/tmp/we\\"ird", O_RDONLY) = 3',
        ])
        evs = review.parse_trace(text)
        self.assertEqual(evs[0]["argv"], ["curl", "-s", "http://a.test/"])
        self.assertTrue(evs[1]["ok"])
        self.assertFalse(evs[1]["write"])
        self.assertFalse(evs[2]["ok"])
        self.assertEqual(evs[2]["errno"], "ENOENT")
        self.assertTrue(evs[3]["write"])
        self.assertEqual((evs[4]["addr"], evs[4]["port"], evs[4]["ok"]), ("203.0.113.9", 443, False))
        self.assertEqual(evs[5]["path2"], "/home/candidate/.bashrc")
        self.assertEqual(evs[6]["path"], '/tmp/we"ird')


class ClassifyTest(unittest.TestCase):
    def result(self, **kw):
        base = {"traces": {}, "net": [], "fs_changes": [], "leftover_processes": [], "background_processes": [],
                "timed_out": False, "main_still_running": False, "exit_code": 0, "duration_s": 0.1,
                "stdout_head": "", "stderr_head": "", "traces_truncated": False}
        base.update(kw)
        return base

    def cats(self, entry, res):
        findings, _ = review.classify_entry(entry, res, {"k": TOKEN})
        return {f["category"] for f in findings}

    def test_quiet_entry_has_no_findings(self):
        entry = {"id": "s", "label": "s", "kind": "script", "argv": ["x"]}
        self.assertEqual(self.cats(entry, self.result()), set())

    def test_long_running_server_is_not_persistence(self):
        entry = {"id": "m", "label": "m", "kind": "mcp", "argv": ["x"], "long_running": True}
        res = self.result(timed_out=True, main_still_running=True, leftover_processes=["python3 server.py"])
        self.assertEqual(self.cats(entry, res), set())

    def test_background_child_is_persistence(self):
        entry = {"id": "h", "label": "h", "kind": "hook", "argv": ["x"]}
        res = self.result(timed_out=True, main_still_running=False, background_processes=["sleep 300"])
        self.assertEqual(self.cats(entry, res), {"persistence"})

    def test_config_change_and_staging(self):
        entry = {"id": "h", "label": "h", "kind": "hook", "argv": ["x"]}
        res = self.result(fs_changes=[
            {"path": "/work/project/CLAUDE.md", "change": "modified", "content_head": "run me"},
            {"path": "/tmp/.cache", "change": "added", "content_head": TOKEN},
        ])
        self.assertEqual(self.cats(entry, res), {"config_tampering", "secret_staging"})


if __name__ == "__main__":
    unittest.main()
