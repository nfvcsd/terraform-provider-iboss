# Terraform Provider for iboss

Manage [iboss](https://www.iboss.com/) Zero Trust SSE configuration with Terraform. The provider currently
covers gateway **URL allowlists and block lists** for each security (filtering) group, plus the lookups
needed to target them.

- Registry: [`nfvcsd/iboss`](https://registry.terraform.io/providers/nfvcsd/iboss/latest)
- Documentation: [registry docs](https://registry.terraform.io/providers/nfvcsd/iboss/latest/docs)
- Maintained by North Fayette Valley Community School District. Not affiliated with or endorsed by iboss or
  HashiCorp.

> [!WARNING]
> **Provided as is.** This software is provided "as is", without warranty of any kind, express or
> implied. North Fayette Valley Community School District, its board, employees and contributors are not
> responsible for any damage, data loss, service disruption or other liability arising from its use. You
> use it entirely at your own risk. Test changes on a non-production security group first. See sections 6
> and 7 of the [license](LICENSE).

## What it manages

| Object | Type | Purpose |
|---|---|---|
| `iboss_blocklist_entry` | resource | One URL on a security group's block list |
| `iboss_allowlist_entry` | resource | One URL on a security group's allowlist |
| `iboss_blocklist`, `iboss_allowlist` | data sources | Every entry on a group's list |
| `iboss_allowlist_settings` | data source | A group's allowlist settings (read-only) |
| `iboss_security_group` | data source | Find a group by name or number |
| `iboss_security_groups` | data source | List every security group |

Resources manage individual entries and leave entries Terraform doesn't know about alone.

## Getting started

### 1. Requirements

- Terraform 1.0 or later (1.5 or later to adopt existing entries with `import` blocks)
- An iboss administrator account, or an iboss API key

### 2. Add the provider

```hcl
terraform {
  required_providers {
    iboss = {
      source  = "nfvcsd/iboss"
      version = "~> 0.1"
    }
  }
}

provider "iboss" {}
```

### 3. Supply credentials

Keep credentials out of `.tf` files and pass them through environment variables. Use one method:

```sh
# API key
export IBOSS_API_KEY="..."

# or a legacy administrator login
export IBOSS_USERNAME="admin@example.org"
export IBOSS_PASSWORD="..."
export IBOSS_TOTP_CODE="123456"   # only if MFA is enabled
```

Legacy login has been verified against a live tenant; API-key authentication has not yet. The provider
finds your account and primary gateway automatically. Set `account_settings_id` or `gateway_host` only
if discovery picks the wrong one. Credentials and session tokens are never written to Terraform state.

### 4. Block a site

```hcl
data "iboss_security_group" "students" {
  name = "Students"
}

resource "iboss_blocklist_entry" "games" {
  group_number = data.iboss_security_group.students.group_number
  url          = "games.example.com"
  note         = "Managed by Terraform"
}
```

```sh
terraform init
terraform plan
terraform apply
```

`terraform destroy` (or removing the resource block) deletes the entry from the list.

### 5. Adopt entries that already exist

Entries are imported by `<group_number>/<url>`:

```hcl
import {
  to = iboss_blocklist_entry.games
  id = "2/games.example.com"
}
```

To bring every group's lists under management at once, start from
[`examples/url-list-sync`](examples/url-list-sync/README.md). It exports each group's block list and
allowlist to `Gateway/Block List/<number>. <name>.yaml` and `Gateway/Allowlist/<number>. <name>.yaml`,
manages entries from those files, and adopts existing entries with `import` blocks. Changes then go
through pull requests like any other code.

## Things to know

- Entries have no update operation in the iboss API, so changing any argument replaces the entry.
- Timed (expiring) entries aren't supported.
- The provider covers a small part of the iboss API. [`docs/api-coverage.md`](docs/api-coverage.md) maps
  what is implemented, what is planned and the open questions about the API.

## Development

Requirements: Go (version in `go.mod`), Python 3.10+, `make`, and Terraform for acceptance tests.

```sh
make build      # bin/terraform-provider-iboss
make test       # unit tests
make testacc    # acceptance tests against the local simulator
make docs       # regenerate docs/ from templates/ and examples/
make check      # everything CI runs except the dependency scan (make vuln)
```

**Tests never contact an iboss tenant.** `internal/testutil` runs an HTTPS simulator built from the
published API documentation, and every test client uses a fail-closed transport that can only reach it.
`TF_ACC=1` enables these simulated acceptance tests only; there is no live test mode. A passing suite
shows the provider matches the documentation as we understood it, not that the real API behaves the same.

To try a local build, point Terraform at it with a
[`dev_overrides`](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
block. Releases are described in [RELEASING.md](RELEASING.md).

## License

[Mozilla Public License 2.0](LICENSE).
