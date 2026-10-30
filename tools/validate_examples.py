#!/usr/bin/env python3
"""Validate every example configuration against a locally built provider.

Each example directory is copied to a temporary directory together with a
provider-source override, and `terraform validate` runs with a CLI config
whose dev_overrides point at the local build. Validation is offline: it
never configures the provider, so no request is sent to iboss.

Usage:
  python3 tools/validate_examples.py --provider-dir ./bin [--terraform terraform]
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "nfvcsd/iboss"
REQUIRED = f"""terraform {{
  required_providers {{
    iboss = {{
      source = "{SOURCE}"
    }}
  }}
}}
"""


def example_dirs(root: Path) -> list[Path]:
    return sorted({p.parent for p in (root / "examples").rglob("*.tf")})


def has_required_providers(d: Path) -> bool:
    return any("required_providers" in p.read_text(encoding="utf-8") for p in d.glob("*.tf"))


def validate(d: Path, terraform: str, env: dict[str, str]) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for p in d.glob("*.tf"):
            shutil.copy(p, work / p.name)
        if not has_required_providers(d):
            (work / "zz_required_providers.tf").write_text(REQUIRED, encoding="utf-8")
        proc = subprocess.run([terraform, "validate", "-no-color"], cwd=work, env=env,
                              capture_output=True, text=True, check=False)
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider-dir", required=True, help="directory containing the built provider binary")
    ap.add_argument("--terraform", default=os.environ.get("TERRAFORM", "terraform"))
    ap.add_argument("--registry-host", default="registry.terraform.io",
                    help="registry host used in the override address (registry.opentofu.org for OpenTofu)")
    args = ap.parse_args(argv)

    provider_dir = Path(args.provider_dir).resolve()
    with tempfile.TemporaryDirectory() as cfgdir:
        rc = Path(cfgdir) / "dev.tfrc"
        rc.write_text(
            'provider_installation {\n'
            f'  dev_overrides {{\n    "{args.registry_host}/{SOURCE}" = "{provider_dir}"\n  }}\n'
            '  direct {}\n}\n',
            encoding="utf-8",
        )
        env = {k: v for k, v in os.environ.items() if not k.startswith("IBOSS_")}
        env.update({"TF_CLI_CONFIG_FILE": str(rc), "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1"})
        failed = 0
        for d in example_dirs(ROOT):
            ok, out = validate(d, args.terraform, env)
            print(f"{'ok  ' if ok else 'FAIL'} {d.relative_to(ROOT)}")
            if not ok:
                failed += 1
                print("    " + out.replace("\n", "\n    "))
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
