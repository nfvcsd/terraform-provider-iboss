# iboss block lists as code

Each security group's iboss block list lives in its own file:

```
Gateway/Block List/
  10. NFVMBL_ValElem.yaml
  20. NFVMBL_Staff.yaml
  32. NFVMBL_HS.yaml
  ...
```

The folder mirrors the iboss API documentation (Gateway → Block List). File names match the group menu in
the iboss console: `<group number>. <group name>.yaml`. Terraform in this folder adds and removes block
list entries so iboss matches the files.

Requires Terraform 1.7+ (or OpenTofu 1.7+), Python 3.10+, and the `nfvcsd/iboss` provider.

## Credentials

Both steps read the same environment variables as the provider:

```sh
export IBOSS_API_KEY="…"   # or IBOSS_USERNAME / IBOSS_PASSWORD (/ IBOSS_TOTP_CODE)
```

## 1. Sync from iboss

```sh
python3 scripts/sync_blocklists.py
```

This runs the read-only Terraform configuration in `export/` (data sources only, nothing in iboss changes)
and rewrites `Gateway/Block List/`:

- one file per security group, including groups with an empty block list;
- entries sorted by URL; fields at their zero value (`false`, `0`, empty note) are left out;
- files for groups that no longer exist are removed, and a renamed group's file is renamed;
- timed (expiring) entries are listed under `timed_entries_not_managed` but are not managed.

The script refuses to run if the folder has uncommitted changes, so a sync never silently overwrites an
unapplied edit. Review the result with `git diff` and commit it.

## 2. Adopt and manage with Terraform

```sh
terraform init
terraform plan    # first time: every entry shows as "will be imported", no changes
terraform apply
```

Entries that already exist in iboss are imported, not recreated. After that:

- **add** a URL to a file → Terraform adds it to that group's block list;
- **remove** a URL → Terraform deletes it from iboss;
- **change** a field (for example `note`) → Terraform replaces the entry (iboss has no update operation);
- **leave a field out** → Terraform leaves its value in iboss alone.

Entry fields: `url` (required), `note`, `is_regex`, `global`, `apply_keyword_and_safe_search`, `direction`,
`priority`, `weight`, `start_port`, `end_port`. See the provider's `iboss_blocklist_entry` docs.

Deleting a whole file removes every managed entry in that group, so read the plan before applying. A
`check` warns when a file's group was renamed or removed in iboss; run the sync to fix the file name.

## State

Terraform's state for this folder must persist between runs and be shared by everyone who applies. Before
the first `apply`, add a `backend` block (for example HCP Terraform or an S3-compatible bucket) to
`main.tf`. Do not commit `terraform.tfstate`; `.gitignore` already excludes it. `export/` uses throwaway
local state.

## Suggested workflow

1. Run the sync on `main` and commit (captures changes made in the iboss console).
2. Edit YAML on a branch and open a pull request; attach `terraform plan` output for review.
3. Merge, then `terraform apply` from `main`.
