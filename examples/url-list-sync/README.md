# iboss URL lists as code

Each security group's block list and allowlist live in their own files:

```
Gateway/
  Block List/
    10. NFVMBL_ValElem.yaml
    32. NFVMBL_HS.yaml
    ...
  Allowlist/
    10. NFVMBL_ValElem.yaml
    32. NFVMBL_HS.yaml
    ...
```

The folders mirror the iboss API documentation (Gateway → Block List, Gateway → Allowlist). File names match
the group menu in the iboss console: `<group number>. <group name>.yaml`. Terraform in this folder adds and
removes list entries so iboss matches the files: `blocklist.tf` handles block lists, `allowlist.tf` handles
allowlists.

Requires Terraform 1.7+ (or OpenTofu 1.7+), Python 3.10+, and the `nfvcsd/iboss` provider.

## Credentials

Both steps read the same environment variables as the provider:

```sh
export IBOSS_API_KEY="…"   # or IBOSS_USERNAME / IBOSS_PASSWORD (/ IBOSS_TOTP_CODE)
```

## 1. Sync from iboss

```sh
python3 scripts/sync_lists.py
```

This runs the read-only Terraform configuration in `export/` (data sources only, nothing in iboss changes)
and rewrites both list folders:

- one file per security group in each folder, including groups with an empty list;
- entries sorted by URL; fields at their zero value (`false`, `0`, empty note) are left out;
- files for groups that no longer exist are removed, and a renamed group's files are renamed;
- timed (expiring) entries are listed under `timed_entries_not_managed` but are not managed.

The script refuses to run if either folder has uncommitted changes, so a sync never silently overwrites an
unapplied edit. Review the result with `git diff` and commit it.

## 2. Adopt and manage with Terraform

```sh
terraform init
terraform plan    # first time: every entry shows as "will be imported", no changes
terraform apply
```

Entries that already exist in iboss are imported, not recreated. After that:

- **add** a URL to a file → Terraform adds it to that group's list;
- **remove** a URL → Terraform deletes it from iboss;
- **change** a field (for example `note`) → Terraform replaces the entry (iboss has no update operation);
- **leave a field out** → Terraform leaves its value in iboss alone.

Entry fields: `url` (required), `note`, `is_regex`, `global`, `apply_keyword_and_safe_search`, `direction`,
`priority`, `weight`, `start_port`, `end_port`. See the provider's `iboss_blocklist_entry` and
`iboss_allowlist_entry` docs. Allowlist settings such as "only allow sites on the allowlist" are not part of
these files; the API documents no way to change them.

Deleting a whole file removes every managed entry in that group's list, so read the plan before applying. A
`check` warns when a file's group was renamed or removed in iboss; run the sync to fix the file name.

## State

Terraform's state for this folder must persist between runs and be shared by everyone who applies. Before
the first `apply`, add a `backend` block (for example an S3 bucket with `use_lockfile = true`) to
`main.tf`. Do not commit `terraform.tfstate`. `export/` uses throwaway local state.

## Suggested workflow

1. Run the sync on `main` and commit (captures changes made in the iboss console).
2. Edit YAML on a branch and open a pull request; attach `terraform plan` output for review.
3. Merge, then `terraform apply` from `main`.
