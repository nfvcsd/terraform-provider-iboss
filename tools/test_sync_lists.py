"""Unit tests for examples/url-list-sync/scripts/sync_lists.py."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "examples" / "url-list-sync" / "scripts" / "sync_lists.py"
_spec = importlib.util.spec_from_file_location("sync_lists", SCRIPT)
sl = importlib.util.module_from_spec(_spec)
sys.modules["sync_lists"] = sl  # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(sl)

BLOCK, ALLOW = sl.LISTS

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
ALLOW_GROUPS = [
    {"group_number": 32, "group_name": "NFVMBL_HS", "entries": [
        {"url": "learning.example.org", "note": "LMS", "do_dlp_scan": True, "do_malware_scan": True},
    ]},
    {"group_number": 20, "group_name": "NFVMBL_Staff", "entries": []},
]
OUTPUTS = {
    "blocklists": {"sensitive": False, "type": [], "value": GROUPS},
    "allowlists": {"sensitive": False, "type": [], "value": ALLOW_GROUPS},
}


class RenderTest(unittest.TestCase):
    def test_lists_cover_both_documented_folders(self):
        self.assertEqual([(s.output, str(s.folder)) for s in sl.LISTS],
                         [("blocklists", "Gateway/Block List"), ("allowlists", "Gateway/Allowlist")])

    def test_render_sorts_omits_zero_values_and_lists_timed(self):
        text = sl.render(GROUPS[0], BLOCK)
        self.assertEqual(text, "\n".join([
            "# iboss block list for security group 32 (NFVMBL_HS).",
            "# Synced from iboss by scripts/sync_lists.py. Terraform applies edits to this file.",
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

    def test_allowlist_ignores_read_only_scan_flags(self):
        text = sl.render(ALLOW_GROUPS[0], ALLOW)
        self.assertTrue(text.startswith("# iboss allowlist for security group 32 (NFVMBL_HS).\n"))
        self.assertIn('  - url: "learning.example.org"\n    note: "LMS"\n', text)
        self.assertNotIn("scan", text)

    def test_empty_group(self):
        self.assertIn("entries: []\n", sl.render(GROUPS[1], BLOCK))

    def test_strings_round_trip_as_json(self):
        line = sl.render(GROUPS[0], BLOCK).splitlines()[6]
        self.assertEqual(json.loads(line.split(": ", 1)[1]), ".*\\.games\\.example$")

    def test_newlines_in_names_cannot_break_comments(self):
        text = sl.render({"group_number": 1, "group_name": "a\nb: injected", "entries": []}, BLOCK)
        self.assertNotIn("\nb: injected", text)
        self.assertIn('group_name: "a\\nb: injected"', text)

    def test_duplicate_urls_are_rejected(self):
        with self.assertRaises(sl.SyncError):
            sl.render({"group_number": 1, "group_name": "x", "entries": [{"url": "a"}, {"url": "a"}]}, ALLOW)


class NamingTest(unittest.TestCase):
    def test_file_names_match_console_labels(self):
        self.assertEqual(sl.file_name(32, "NFVMBL_HS"), "32. NFVMBL_HS.yaml")
        self.assertEqual(sl.file_name(47, "NF/only:sites"), "47. NF_only_sites.yaml")
        self.assertEqual(sl.file_name(5, "  ..  "), "5. unnamed.yaml")
        self.assertEqual(sl.file_name(6, "../../etc"), "6. .._.._etc.yaml")

    def test_validate(self):
        sl.validate(GROUPS, BLOCK)
        for bad in ([{"group_number": "1", "group_name": "x"}],
                    [{"group_number": 1, "group_name": "x"}, {"group_number": 1, "group_name": "y"}],
                    [{"group_number": 1, "group_name": "x", "entries": [{"url": ""}]}],
                    {"not": "a list"}):
            with self.assertRaises(sl.SyncError):
                sl.validate(bad, BLOCK)


class ParseOutputTest(unittest.TestCase):
    def test_terraform_shape_and_warnings(self):
        out = "\nWarning: something\n\nDetails [here].\n" + json.dumps(OUTPUTS) + "\n"
        self.assertEqual(sl.parse_output(out), {"blocklists": GROUPS, "allowlists": ALLOW_GROUPS})

    def test_plain_mapping(self):
        self.assertEqual(sl.parse_output('{"blocklists": []}'), {"blocklists": []})

    def test_not_json(self):
        with self.assertRaises(sl.SyncError):
            sl.parse_output("Error: nope\n[1, 2]\n")


class WriteTest(unittest.TestCase):
    def test_writes_updates_and_prunes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / BLOCK.folder
            target.mkdir(parents=True)
            (target / "99. Removed group.yaml").write_text("old", encoding="utf-8")
            (target / "notes.txt").write_text("keep", encoding="utf-8")
            files = sl.plan_files(GROUPS, BLOCK)
            r = sl.write_files(root, BLOCK.folder, files)
            self.assertEqual(sorted(r["added"]), ["20. NFVMBL_Staff.yaml", "32. NFVMBL_HS.yaml"])
            self.assertEqual(r["removed"], ["99. Removed group.yaml"])
            self.assertTrue((target / "notes.txt").exists())
            r = sl.write_files(root, BLOCK.folder, files)
            self.assertEqual(len(r["unchanged"]), 2)
            self.assertEqual(r["added"] + r["updated"] + r["removed"], [])

    def test_main_writes_both_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "outputs.json"
            data.write_text(json.dumps(OUTPUTS), encoding="utf-8")
            self.assertEqual(sl.main(["--root", str(root), "--from-json", str(data)]), 0)
            self.assertIn("weight: 502", (root / BLOCK.folder / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"))
            self.assertIn("learning.example.org", (root / ALLOW.folder / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"))

    def test_missing_output_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "outputs.json"
            data.write_text(json.dumps({"blocklists": OUTPUTS["blocklists"]}), encoding="utf-8")
            self.assertEqual(sl.main(["--root", str(root), "--from-json", str(data)]), 1)
            self.assertFalse((root / BLOCK.folder).exists())

    def test_refuses_dirty_folder_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            data = root / "outputs.json"
            data.write_text(json.dumps(OUTPUTS), encoding="utf-8")
            target = root / ALLOW.folder
            target.mkdir(parents=True)
            (target / "32. NFVMBL_HS.yaml").write_text("edited", encoding="utf-8")
            self.assertEqual(sl.main(["--root", str(root), "--from-json", str(data)]), 1)
            self.assertEqual((target / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"), "edited")
            self.assertEqual(sl.main(["--root", str(root), "--from-json", str(data), "--force"]), 0)
            self.assertIn("learning.example.org", (target / "32. NFVMBL_HS.yaml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
