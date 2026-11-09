#!/usr/bin/env python3
"""Sync iboss URL lists into YAML, one file per security group and list.

  Gateway/Block List/<number>. <group>.yaml
  Gateway/Allowlist/<number>. <group>.yaml

Folders follow the iboss API documentation (Gateway → Block List, Allowlist);
file names follow the group menu in the iboss console. The script runs the
read-only Terraform configuration in ./export, writes the files, removes files
for groups that no longer exist, and renames files of renamed groups. Terraform
in the repository root manages the entries listed in these files.

Usage (from the repository root, with IBOSS_* credentials in the environment):
  python3 scripts/sync_lists.py            # refuse if the list folders have uncommitted edits
  python3 scripts/sync_lists.py --force    # overwrite uncommitted edits
  python3 scripts/sync_lists.py --from-json outputs.json   # `terraform output -json`; skip Terraform

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
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ListSpec:
    output: str  # Terraform output name in export/
    folder: Path  # folder relative to the repository root
    title: str  # used in file headers


LISTS = (
    ListSpec("blocklists", Path("Gateway") / "Block List", "block list"),
    ListSpec("allowlists", Path("Gateway") / "Allowlist", "allowlist"),
)

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


def render(group: dict[str, Any], spec: ListSpec) -> str:
    """Render one group's list as YAML."""
    number = group["group_number"]
    name = group["group_name"]
    entries = group.get("entries") or []
    managed = sorted((e for e in entries if not e.get("is_timed_url")), key=lambda e: (e["url"].casefold(), e["url"]))
    timed = sorted(e["url"] for e in entries if e.get("is_timed_url"))

    seen: set[str] = set()
    for e in managed:
        if e["url"] in seen:
            raise SyncError(f"group {number}'s {spec.title} lists {e['url']!r} more than once; remove the duplicate in iboss first")
        seen.add(e["url"])

    lines = [
        f"# iboss {spec.title} for security group {number} ({_comment(name)}).",
        "# Synced from iboss by scripts/sync_lists.py. Terraform applies edits to this file.",
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


def validate(data: Any, spec: ListSpec) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise SyncError(f"{spec.output}: expected a list of groups")
    numbers: set[int] = set()
    for g in data:
        if not isinstance(g, dict) or not isinstance(g.get("group_number"), int) or not isinstance(g.get("group_name"), str):
            raise SyncError(f"{spec.output}: malformed group: {g!r}")
        if g["group_number"] in numbers:
            raise SyncError(f"{spec.output}: group number {g['group_number']} appears more than once")
        numbers.add(g["group_number"])
        for e in g.get("entries") or []:
            if not isinstance(e, dict) or not isinstance(e.get("url"), str) or not e["url"]:
                raise SyncError(f"{spec.output}: malformed entry in group {g['group_number']}: {e!r}")
    return data


def plan_files(groups: list[dict[str, Any]], spec: ListSpec) -> dict[str, str]:
    return {file_name(g["group_number"], g["group_name"]): render(g, spec) for g in groups}


def write_files(root: Path, folder: Path, files: dict[str, str]) -> dict[str, list[str]]:
    """Write files into root/folder and remove stale *.yaml files there."""
    target = (root / folder).resolve()
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


def uncommitted_changes(root: Path, folders: list[Path]) -> list[str]:
    """Return uncommitted paths under the list folders (empty outside git)."""
    if shutil.which("git") is None:
        return []
    proc = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--", *map(str, folders)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:  # not a git repository
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def parse_output(out: str) -> dict[str, Any]:
    """Parse `terraform output -json`, skipping any warnings printed before it.

    Returns {output name: value}. Accepts Terraform's {"name": {"value": …}}
    form or a plain {"name": value} mapping.
    """
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("{"):
            continue
        try:
            data = json.loads("\n".join(lines[i:]))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return {k: v["value"] if isinstance(v, dict) and "value" in v else v for k, v in data.items()}
    raise SyncError(f"terraform output -json did not return a JSON object:\n{out}")


def terraform_export(root: Path, terraform: str) -> dict[str, Any]:
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
    return parse_output(run("output", "-json"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="repository root (default: current directory)")
    ap.add_argument("--terraform", default=os.environ.get("TERRAFORM", "terraform"), help="Terraform or OpenTofu binary")
    ap.add_argument("--from-json", help="read `terraform output -json` from this file instead of running Terraform")
    ap.add_argument("--force", action="store_true", help="overwrite uncommitted changes in the list folders")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        dirty = uncommitted_changes(root, [spec.folder for spec in LISTS])
        if dirty and not args.force:
            raise SyncError("the list folders have uncommitted changes; commit or discard them, or pass --force:\n  "
                            + "\n  ".join(dirty))
        if args.from_json:
            outputs = parse_output(Path(args.from_json).read_text(encoding="utf-8"))
        else:
            outputs = terraform_export(root, args.terraform)
        # Validate and render everything before writing anything.
        planned = []
        for spec in LISTS:
            if spec.output not in outputs:
                raise SyncError(f"export/ has no {spec.output!r} output; update export/main.tf")
            planned.append((spec, plan_files(validate(outputs[spec.output], spec), spec)))
        results = [(spec, write_files(root, spec.folder, files)) for spec, files in planned]
    except SyncError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    for spec, result in results:
        for kind in ("added", "updated", "removed"):
            for name in result[kind]:
                print(f"{kind:8} {spec.folder / name}")
        print(f"{spec.folder}: {len(result['unchanged'])} unchanged, {len(result['added'])} added, "
              f"{len(result['updated'])} updated, {len(result['removed'])} removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
