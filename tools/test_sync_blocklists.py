"""Unit tests for examples/blocklist-sync/scripts/sync_blocklists.py."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "examples" / "blocklist-sync" / "scripts" / "sync_blocklists.py"
_spec = importlib.util.spec_from_file_location("sync_blocklists", SCRIPT)
sb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sb)

GROUPS = [
    {"group_number": 32, "group_name": "NFVMBL_HS", "entries": [
        {"url": "weather.com/", "note": "", "is_regex": False, "global": False, "apply_keyword_and_safe_search": False,
         "direction": 0, "priority": 0, "weight": 502, "start_port": 0, "end_port": 0, "is_timed_url": False},
        {"url": ".*\\.games\\.example$", "note": 'says "no"', "is_regex": True, "direction": 2, "is_timed_url": False},
        {"url": "Apple.example", "is_timed_url": False},
        {"url": "temp.example", "is_timed_url": True},
    ]},
    {"group_number": 20, "group_name": "NFVMBL_Staff", "entries": []},
]


class RenderTest(unittest.TestCase):
    def test_render_sorts_omits_zero_values_and_lists_timed(self):
        text = sb.render(GROUPS[0])
        self.assertEqual(text, "\n".join([
            "# iboss block list for security group 32 (NFVMBL_HS).",
            "# Synced from iboss by scripts/sync_blocklists.py. Terraform applies edits to this file.",
            "# Fields left out keep their current value in iboss.",
            "group_number: 32",
            'group_name: "NFVMBL_HS"',
            "entries:",
            '  - url: ".*\\\\.games\\\\.example$"',
            '    note: "says \\"no\\""',
            "    is_regex: true",
            "    direction: 2",
            '  - url: "Apple.example"',
            '  - url: "weather.com/"',
            "    weight: 502",
            "# Timed (expiring) entries cannot be managed by Terraform; listed for reference only.",
            "timed_entries_not_managed:",
            '  - "temp.example"',
        ]) + "\n")

    def test_empty_group(self):
        self.assertIn("entries: []\n", sb.render(GROUPS[1]))

    def test_strings_round_trip_as_json(self):
        # Every quoted scalar is a JSON string, which YAML parses identically.
        line = sb.render(GROUPS[0]).splitlines()[6]
        self.assertEqual(json.loads(line.split(": ", 1)[1]), ".*\\.games\\.example$")

    def test_newlines_in_names_cannot_break_comments(self):
        text = sb.render({"group_number": 1, "group_name": "a\nb: injected", "entries": []})
        self.assertNotIn("\nb: injected", text)
        self.assertIn('group_name: "a\\nb: injected"', text)

    def test_duplicate_urls_are_rejected(self):
        with self.assertRaises(sb.SyncError):
            sb.render({"group_number": 1, "group_name": "x", "entries": [{"url": "a"}, {"url": "a"}]})


class NamingTest(unittest.TestCase):
    def test_file_names_match_console_labels(self):
        self.assertEqual(sb.file_name(32, "NFVMBL_HS"), "32. NFVMBL_HS.yaml")
        self.assertEqual(sb.file_name(47, "NF/only:sites"), "47. NF_only_sites.yaml")
        self.assertEqual(sb.file_name(5, "  ..  "), "5. unnamed.yaml")
        self.assertEqual(sb.file_name(6, "../../etc"), "6. .._.._etc.yaml")

    def test_validate(self):
        sb.validate(GROUPS)
        for bad in ([{"group_number": "1", "group_name": "x"}],
                    [{"group_number": 1, "group_name": "x"}, {"group_number": 1, "group_name": "y"}],
                    [{"group_number": 1, "group_name": "x", "entries": [{"url": ""}]}],
                    {"not": "a list"}):
            with self.assertRaises(sb.SyncError):
                sb.validate(bad)


class ParseOutputTest(unittest.TestCase):
    def test_skips_warnings(self):
        out = '\nWarning: something\n\nDetails [here].\n[{"group_number": 1}]\n'
        self.assertEqual(sb.parse_output(out), [{"group_number": 1}])
        with self.assertRaises(sb.SyncError):
            sb.parse_output("Error: nope\n")


class WriteTest(unittest.TestCase):
    def test_writes_updates_and_prunes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / sb.BLOCKLIST_DIR
            target.mkdir(parents=True)
            (target / "99. Removed group.yaml").write_text("old", encoding="utf-8")
            (target / "notes.txt").write_text("keep", encoding="utf-8")
            files = sb.plan_files(GROUPS)
            r = sb.write_files(root, files)
            self.assertEqual(sorted(r["added"]), ["20. NFVMBL_Staff.yaml", "32. NFVMBL_HS.yaml"])
            self.assertEqual(r["removed"], ["99. Removed group.yaml"])
            self.assertTrue((target / "notes.txt").exists())
            r = sb.write_files(root, files)
            self.assertEqual(len(r["unchanged"]), 2)
            self.assertEqual(r["added"] + r["updated"] + r["removed"], [])

    def test_refuses_dirty_folder_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            data = root / "data.json"
            data.write_text(json.dumps(GROUPS), encoding="utf-8")
            target = root / sb.BLOCKLIST_DIR
            target.mkdir(parents=True)
            (target / "32. NFVMBL_HS.yaml").write_text("edited", encoding="utf-8")
            self.assertEqual(sb.main(["--root", str(root), "--from-json", str(data)]), 1)
            self.assertEqual((target / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"), "edited")
            self.assertEqual(sb.main(["--root", str(root), "--from-json", str(data), "--force"]), 0)
            self.assertIn("weight: 502", (target / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
