"""What the review did not cover must never read as "no problems observed".

Evidence level: in-process calls to inventory and review.main, no Docker.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from helpers import FIXTURES, ROOT
import inventory
import review


def categories(findings):
    return {(f["category"], f["severity"]) for f in findings}


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def run_main(argv):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = review.main(argv)
    return code, err.getvalue()


def load_report(out):
    with open(os.path.join(out, "report.json")) as fh:
        return json.load(fh)


class WindowsHostTest(unittest.TestCase):
    # Issue #1, item 1: on Windows the candidate reaches the container with
    # backslash paths and no execute bits, so nothing runs and the report
    # would say "No problems observed".
    def test_sandbox_run_is_refused_on_windows(self):
        out = tempfile.mkdtemp(prefix="spr-test-")
        with mock.patch.object(review, "IS_WINDOWS", True), \
                mock.patch.object(review, "docker_available", return_value=True), \
                mock.patch.object(review, "ensure_image", side_effect=AssertionError("sandbox reached on Windows")):
            code, err = run_main([os.path.join(FIXTURES, "benign-skill"), "--out", out])
        self.assertEqual(code, 2)
        self.assertIn("Windows", err)
        self.assertFalse(os.path.exists(os.path.join(out, "report.json")))

    def test_static_only_on_windows_is_marked_not_reviewed(self):
        out = tempfile.mkdtemp(prefix="spr-test-")
        with mock.patch.object(review, "IS_WINDOWS", True):
            code, _ = run_main([os.path.join(FIXTURES, "benign-skill"), "--out", out, "--static-only"])
        self.assertEqual(code, 0)
        self.assertTrue(any("sandbox" in item for item in load_report(out)["not_reviewed"]))


class PlanCapTest(unittest.TestCase):
    # Issue #1, item 5: filler scripts must not push code that runs on its
    # own past the entry point cap.
    def test_autorun_entries_survive_the_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(inventory.MAX_ENTRY_POINTS + 5):
                write(os.path.join(tmp, "scripts", f"f{i:02d}.py"), "pass\n")
            write(os.path.join(tmp, "skills", "s", "SKILL.md"), "---\nname: s\n---\n!`echo loaded`\n")
            comps = inventory.plugin_components(tmp)
            plan, notes = inventory.entry_points(tmp, comps, inventory.walk(tmp))
        self.assertEqual(len(plan), inventory.MAX_ENTRY_POINTS)
        self.assertTrue(any(p["kind"] == "skill_command" for p in plan))
        truncated = [f for f in notes if f["category"] == "plan_truncated"]
        self.assertEqual([f["severity"] for f in truncated], ["medium"])
        self.assertEqual(len(truncated[0]["evidence"]["not_run"]), 6)

    def test_dropping_an_autorun_entry_is_high(self):
        hooks = [{"origin": "x", "event": "SessionStart", "type": "command", "command": f"echo {i}"}
                 for i in range(inventory.MAX_ENTRY_POINTS + 1)]
        comps = {"hooks": hooks, "mcp": [], "lsp": [], "monitors": [], "bin": [], "skills": [], "package_scripts": {}}
        plan, notes = inventory.entry_points("/nonexistent", comps, [])
        self.assertEqual(len(plan), inventory.MAX_ENTRY_POINTS)
        self.assertIn(("plan_truncated", "high"), categories(notes))


class MarketplaceSourceTest(unittest.TestCase):
    # Issue #1, item 6: entries that were not reviewed must surface.
    def marketplace(self, tmp, plugins):
        write(os.path.join(tmp, ".claude-plugin", "marketplace.json"),
              json.dumps({"name": "m", "owner": {"name": "x"}, "plugins": plugins}))

    def test_missing_local_source_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.marketplace(tmp, [{"name": "gone", "source": "./plugins/gone"}])
            _, targets, findings = inventory.detect_targets(tmp)
        self.assertEqual(targets, [])
        self.assertIn(("missing_source", "medium"), categories(findings))

    def test_report_lists_what_was_not_reviewed(self):
        tmp = tempfile.mkdtemp(prefix="spr-test-")
        self.marketplace(tmp, [{"name": "remote", "source": {"source": "github", "repo": "a/b"}},
                               {"name": "gone", "source": "./plugins/gone"}])
        out = tempfile.mkdtemp(prefix="spr-test-")
        with mock.patch.object(review, "docker_available", return_value=True), \
                mock.patch.object(review, "ensure_image", return_value="unused"):
            code, _ = run_main([tmp, "--out", out])
        self.assertEqual(code, 0)
        not_reviewed = load_report(out)["not_reviewed"]
        self.assertTrue(any("'remote'" in item for item in not_reviewed), not_reviewed)
        self.assertTrue(any("'gone'" in item for item in not_reviewed), not_reviewed)
        self.assertFalse(any("sandbox" in item for item in not_reviewed), not_reviewed)

    def test_static_only_is_listed_as_not_reviewed(self):
        out = tempfile.mkdtemp(prefix="spr-test-")
        code, _ = run_main([os.path.join(FIXTURES, "benign-skill"), "--out", out, "--static-only"])
        self.assertEqual(code, 0)
        self.assertTrue(any("sandbox" in item for item in load_report(out)["not_reviewed"]))


class ReportVersionTest(unittest.TestCase):
    def test_report_names_the_released_version(self):
        with open(os.path.join(ROOT, "plugins", "skill-preinstall-review", ".claude-plugin", "plugin.json")) as fh:
            version = json.load(fh)["version"]
        out = tempfile.mkdtemp(prefix="spr-test-")
        run_main([os.path.join(FIXTURES, "benign-skill"), "--out", out, "--static-only"])
        self.assertEqual(load_report(out)["tool"], f"preinstall-review {version}")


if __name__ == "__main__":
    unittest.main()
