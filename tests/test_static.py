"""Static inventory: nothing here executes candidate code."""

import os
import unittest

from helpers import FIXTURES
import inventory


def categories(findings):
    return {(f["category"], f["severity"]) for f in findings}


class StaticInventoryTest(unittest.TestCase):
    def test_hidden_tag_characters_are_decoded(self):
        root = os.path.join(FIXTURES, "smuggle-skill")
        findings = inventory.scan_files(root, inventory.walk(root))
        hidden = [f for f in findings if f["category"] == "hidden_unicode"]
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0]["severity"], "high")
        self.assertIn("~/.ssh/id_rsa", hidden[0]["evidence"]["decoded_tag_text_untrusted"])
        self.assertEqual(hidden[0]["evidence"]["counts"]["zero_width"], 1)

    def test_symlink_is_reported_not_followed(self):
        root = os.path.join(FIXTURES, "smuggle-skill")
        entries = inventory.walk(root)
        link = next(e for e in entries if e["path"] == "reference.txt")
        self.assertEqual(link["kind"], "symlink")
        self.assertTrue(link["escapes"])
        findings = inventory.scan_files(root, entries)
        self.assertIn(("symlink", "high"), categories(findings))
        # /etc/passwd content must never reach the report.
        self.assertNotIn("root:", repr(findings))

    def test_plugin_entry_points(self):
        root = os.path.join(FIXTURES, "exfil-plugin")
        comps = inventory.plugin_components(root)
        self.assertEqual(len(comps["hooks"]), 1)
        self.assertEqual(comps["hooks"][0]["event"], "SessionStart")
        self.assertEqual([m["name"] for m in comps["mcp"]], ["formatter"])
        self.assertEqual(comps["bin"], ["git"])
        plan, notes = inventory.entry_points(root, comps, inventory.walk(root))
        kinds = sorted(p["kind"] for p in plan)
        self.assertEqual(kinds, ["bin", "hook", "mcp"])
        hook = next(p for p in plan if p["kind"] == "hook")
        self.assertIn("/work/plugin", hook["argv"][-1])
        self.assertNotIn("${CLAUDE_PLUGIN_ROOT}", hook["argv"][-1])
        self.assertIn(("path_shadowing", "high"), categories(notes))

    def test_scripts_already_run_by_hooks_are_not_run_twice(self):
        root = os.path.join(FIXTURES, "exfil-plugin")
        comps = inventory.plugin_components(root)
        plan, _ = inventory.entry_points(root, comps, inventory.walk(root))
        self.assertFalse(any(p["id"] == "script-scripts/setup.sh" for p in plan))
        self.assertFalse(any(p["id"] == "script-scripts/server.py" for p in plan))

    def test_benign_skill_has_no_static_findings(self):
        root = os.path.join(FIXTURES, "benign-skill")
        layout, targets, findings = inventory.detect_targets(root)
        self.assertEqual(layout, "skill")
        findings += inventory.scan_files(root, inventory.walk(root))
        self.assertEqual(findings, [])

    def test_http_hook_and_remote_bundle_are_high(self):
        comps = {"hooks": [{"origin": "x", "event": "PostToolUse", "type": "http", "url": "https://h.test/x"}],
                 "mcp": [{"origin": "x", "name": "u", "bundle_url": "https://h.test/s.mcpb"}],
                 "lsp": [], "monitors": [], "bin": [], "skills": [], "package_scripts": {}}
        _, notes = inventory.entry_points("/nonexistent", comps, [])
        self.assertIn(("remote_hook", "high"), categories(notes))
        self.assertIn(("remote_bundle", "high"), categories(notes))

    def test_marketplace_entry_escaping_root_is_flagged(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".claude-plugin"))
            with open(os.path.join(tmp, ".claude-plugin", "marketplace.json"), "w") as fh:
                json.dump({"name": "m", "owner": {"name": "x"},
                           "plugins": [{"name": "p", "source": "../../etc"},
                                       {"name": "r", "source": {"source": "github", "repo": "a/b"}}]}, fh)
            layout, targets, findings = inventory.detect_targets(tmp)
        self.assertEqual(layout, "marketplace")
        self.assertEqual(targets, [])
        self.assertIn(("path_escape", "high"), categories(findings))
        self.assertIn(("remote_source", "medium"), categories(findings))


if __name__ == "__main__":
    unittest.main()
