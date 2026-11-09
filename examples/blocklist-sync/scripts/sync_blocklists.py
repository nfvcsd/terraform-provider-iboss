#!/usr/bin/env python3
"""Sync iboss block lists into "Gateway/Block List/<number>. <group>.yaml".

Reads every security group's block list through the Terraform configuration in
./export (read-only data sources), then writes one YAML file per group. Files
for groups that no longer exist are removed. Terraform in the repository root
manages the entries listed in these files.

Usage (from the repository root, with IBOSS_* credentials in the environment):
  python3 scripts/sync_blocklists.py            # refuse if the folder has uncommitted edits
  python3 scripts/sync_blocklists.py --force    # overwrite uncommitted edits
  python3 scripts/sync_blocklists.py --from-json blocklists.json   # skip Terraform

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

BLOCKLIST_DIR = Path("Gateway") / "Block List"

# Managed entry fields, in output order. A field is written only when it is
# set to something other than its zero value; omitted fields are left as they
# are in iboss.
ENTRY_FIELDS = (
    "url", "note", "is_regex", "global", "apply_keyword_and_safe_search",
    "direction", "priority", "weight", "start_port", "end_port",
)
_UNSAFE = re.compile(r'[\\/:*?"<>|\x00-\x1f\x7f]')


class SyncError(Exception):
    """Raised for invalid input or a failed Terraform command."""


def safe_name(name: str) -> str:
    """Make a group name usable as a file name on macOS, Windows and Linux."""
    cleaned = _UNSAFE.sub("_", name).strip().rstrip(".")
    return cleaned or "unnamed"


def file_name(group_number: int, group_name: str) -> str:
    return f"{group_number}. {safe_name(group_name)}.yaml"


def _quote(value: str) -> str:
    # A JSON string is a valid YAML double-quoted scalar.
    return json.dumps(value, ensure_ascii=False)


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _quote(value)
    raise SyncError(f"unsupported value {value!r}")


def _is_zero(value: Any) -> bool:
    return value is None or value is False or value == 0 or value == ""


def _comment(text: str) -> str:
    return re.sub(r"[\r\n]+", " ", text)


def render(group: dict[str, Any]) -> str:
    """Render one group's block list as YAML."""
    number = group["group_number"]
    name = group["group_name"]
    entries = group.get("entries") or []
    managed = sorted((e for e in entries if not e.get("is_timed_url")), key=lambda e: (e["url"].casefold(), e["url"]))
    timed = sorted(e["url"] for e in entries if e.get("is_timed_url"))

    seen: set[str] = set()
    for e in managed:
        if e["url"] in seen:
            raise SyncError(f"group {number} lists {e['url']!r} more than once; remove the duplicate in iboss first")
        seen.add(e["url"])

    lines = [
        f"# iboss block list for security group {number} ({_comment(name)}).",
        "# Synced from iboss by scripts/sync_blocklists.py. Terraform applies edits to this file.",
        "# Fields left out keep their current value in iboss.",
        f"group_number: {number}",
        f"group_name: {_quote(name)}",
    ]
    if not managed:
        lines.append("entries: []")
    else:
        lines.append("entries:")
        for e in managed:
            first = True
            for field in ENTRY_FIELDS:
                value = e.get(field)
                if field != "url" and _is_zero(value):
                    continue
                prefix = "  - " if first else "    "
                lines.append(f"{prefix}{field}: {_scalar(value)}")
                first = False
    if timed:
        lines.append("# Timed (expiring) entries cannot be managed by Terraform; listed for reference only.")
        lines.append("timed_entries_not_managed:")
        lines.extend(f"  - {_quote(u)}" for u in timed)
    return "\n".join(lines) + "\n"


def validate(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise SyncError("expected a list of groups")
    numbers: set[int] = set()
    for g in data:
        if not isinstance(g, dict) or not isinstance(g.get("group_number"), int) or not isinstance(g.get("group_name"), str):
            raise SyncError(f"malformed group: {g!r}")
        if g["group_number"] in numbers:
            raise SyncError(f"group number {g['group_number']} appears more than once")
        numbers.add(g["group_number"])
        for e in g.get("entries") or []:
            if not isinstance(e, dict) or not isinstance(e.get("url"), str) or not e["url"]:
                raise SyncError(f"malformed entry in group {g['group_number']}: {e!r}")
    return data


def plan_files(groups: list[dict[str, Any]]) -> dict[str, str]:
    files: dict[str, str] = {}
    for g in groups:
        name = file_name(g["group_number"], g["group_name"])
        files[name] = render(g)
    return files


def write_files(root: Path, files: dict[str, str]) -> dict[str, list[str]]:
    """Write files into root/Gateway/Block List and remove stale *.yaml files."""
    target = (root / BLOCKLIST_DIR).resolve()
    target.mkdir(parents=True, exist_ok=True)
    result: dict[str, list[str]] = {"added": [], "updated": [], "unchanged": [], "removed": []}
    for name, content in sorted(files.items()):
        path = (target / name).resolve()
        if path.parent != target:
            raise SyncError(f"refusing to write outside {target}: {name!r}")
        if path.exists():
            if path.read_text(encoding="utf-8") == content:
                result["unchanged"].append(name)
                continue
            result["updated"].append(name)
        else:
            result["added"].append(name)
        path.write_text(content, encoding="utf-8")
    for path in sorted(target.glob("*.yaml")):
        if path.name not in files:
            path.unlink()
            result["removed"].append(path.name)
    return result


def uncommitted_changes(root: Path) -> list[str]:
    """Return uncommitted paths under the block list folder (empty outside git)."""
    if shutil.which("git") is None:
        return []
    proc = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--", str(BLOCKLIST_DIR)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:  # not a git repository
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def terraform_export(root: Path, terraform: str) -> Any:
    export = root / "export"
    env = {**os.environ, "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"}

    def run(*args: str) -> str:
        proc = subprocess.run([terraform, f"-chdir={export}", *args], capture_output=True, text=True, env=env, check=False)
        if proc.returncode != 0:
            raise SyncError(f"terraform {' '.join(args)} failed:\n{proc.stdout}{proc.stderr}")
        return proc.stdout

    run("init", "-input=false", "-no-color")
    # The export configuration only has data sources and outputs, so apply
    # reads from iboss and changes nothing there.
    run("apply", "-auto-approve", "-input=false", "-no-color")
    out = run("output", "-json", "blocklists")
    return parse_output(out)


def parse_output(out: str) -> Any:
    """Parse `terraform output -json`, skipping any warnings printed before it."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(("[", "{")):
            try:
                return json.loads("\n".join(lines[i:]))
            except json.JSONDecodeError:
                continue
    raise SyncError(f"terraform output -json blocklists did not return JSON:\n{out}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="repository root (default: current directory)")
    ap.add_argument("--terraform", default=os.environ.get("TERRAFORM", "terraform"), help="Terraform or OpenTofu binary")
    ap.add_argument("--from-json", help="read `terraform output -json blocklists` from this file instead of running Terraform")
    ap.add_argument("--force", action="store_true", help="overwrite uncommitted changes in the block list folder")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        dirty = uncommitted_changes(root)
        if dirty and not args.force:
            raise SyncError("the block list folder has uncommitted changes; commit or discard them, or pass --force:\n  "
                            + "\n  ".join(dirty))
        if args.from_json:
            data = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        else:
            data = terraform_export(root, args.terraform)
        result = write_files(root, plan_files(validate(data)))
    except SyncError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    for kind in ("added", "updated", "removed"):
        for name in result[kind]:
            print(f"{kind:8} {BLOCKLIST_DIR / name}")
    print(f"{len(result['unchanged'])} unchanged, {len(result['added'])} added, "
          f"{len(result['updated'])} updated, {len(result['removed'])} removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
