# Changelog

## Unreleased

### Fixed

- Legacy login used `accounts.ibosscloud.com`, which the iboss documentation names but which does not exist in
  DNS. The default is now `accounts.iboss.com`.

### Added

- `accounts_host` provider argument (`IBOSS_ACCOUNTS_HOST`) to override the legacy login host.

- `iboss_security_groups` data source listing every security group.
- `examples/blocklist-sync`: sync every group's block list to
  `Gateway/Block List/<number>. <name>.yaml` and manage the entries from those files, adopting existing
  entries with import blocks. Covered by an end-to-end test that runs the CLI and sync script against the
  simulator.
- Provider configuration with API-key or legacy username/password (optional TOTP) authentication,
  `IBOSS_*` environment fallbacks, account discovery, and validated gateway-node discovery.
- `iboss_allowlist_entry` and `iboss_blocklist_entry` resources (create, read, delete, import).
- `iboss_allowlist`, `iboss_blocklist`, `iboss_allowlist_settings` and `iboss_security_group` data sources.
- Local iboss simulator, fail-closed test harness, and simulated acceptance tests.
- API coverage tracking (`docs/api-coverage.md`) and Postman inventory tooling.

### Compatibility

- Requires Terraform 1.0 or later (protocol 6). CI tests with Terraform 1.16.6.
