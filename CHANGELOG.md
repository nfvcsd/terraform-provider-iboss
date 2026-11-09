# Changelog

## 0.1.0 (2026-11-09)

First release.

### Added

- Provider configuration with API-key or legacy username/password (optional TOTP) authentication, `IBOSS_*`
  environment fallbacks, account discovery, and validated gateway-node discovery that uses the account's
  default web gateway cluster.
- `accounts_host` provider argument (`IBOSS_ACCOUNTS_HOST`). Legacy login defaults to `accounts.iboss.com`;
  the `accounts.ibosscloud.com` host named in the iboss documentation does not exist in DNS.
- `iboss_allowlist_entry` and `iboss_blocklist_entry` resources (create, read, delete, import).
- `iboss_allowlist`, `iboss_blocklist`, `iboss_allowlist_settings`, `iboss_security_group` and
  `iboss_security_groups` data sources.
- `examples/url-list-sync`: sync every group's block list and allowlist to
  `Gateway/Block List/<number>. <name>.yaml` and `Gateway/Allowlist/<number>. <name>.yaml`, and manage the
  entries from those files, adopting existing entries with import blocks.
- Local iboss simulator, fail-closed test harness, simulated acceptance tests, and an end-to-end test that
  runs the Terraform CLI and the sync script against the simulator.
- API coverage tracking (`docs/api-coverage.md`) and Postman inventory tooling.

### Verified live

- Against NFV's tenant with legacy login: account and gateway discovery, security groups, block list and
  allowlist reads, and block list add and delete. API-key authentication has not been exercised live. See
  "Live verification" in `docs/api-coverage.md`.

### Compatibility

- Requires Terraform 1.0 or later (protocol 6). CI tests with Terraform 1.16.6.
