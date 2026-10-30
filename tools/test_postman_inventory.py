"""Tests for postman_inventory.py using a synthetic collection fixture."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import postman_inventory as pi  # noqa: E402

FIXTURE = Path(__file__).resolve().parent.parent / "testdata" / "postman" / "synthetic_collection.json"


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.collection = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_walk_flattens_nested_folders(self):
        ops = list(pi.walk(self.collection["item"]))
        self.assertEqual(
            [(o.folder, o.method, o.host, o.path) for o in ops],
            [
                ("Authentication", "GET", "core", "/ibcloud/web/users/mySettings"),
                ("Gateway / Allowlist / V3", "PUT", "gateway", "/json/v3/controls/allowList/replace"),
                ("Gateway / Allowlist", "GET", "gateway", "/json/controls/allowList"),
                ("(root)", "GET", "accounts", "/ibossauth/web/tokens"),
            ],
        )
        self.assertEqual(ops[2].query, ("currentPolicyBeingEdited",))
        self.assertEqual(ops[3].query, ("ignoreAuthModule", "totpCode"))
        self.assertTrue(ops[2].link.endswith("#00000000-0000-0000-0000-000000000002"))

    def test_render_escapes_and_counts(self):
        text = pi.render(self.collection, "abc123", "2026-10-30")
        self.assertIn("- Operations: 4", text)
        self.assertIn("`abc123`", text)
        self.assertIn("Get \\| Allow List", text)

    def test_digest_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inv.md"
            rc = pi.main(["inventory", str(FIXTURE), "--out", str(out), "--expect-sha256", "0" * 64])
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())
            rc = pi.main(["inventory", str(FIXTURE), "--out", str(out), "--retrieved", "2026-10-30",
                          "--expect-sha256", pi.sha256(FIXTURE.read_bytes())])
            self.assertEqual(rc, 0)
            self.assertIn("Retrieved: 2026-10-30", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
