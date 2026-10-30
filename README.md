# terraform-provider-iboss

A Terraform provider for the [iboss](https://www.iboss.com/) Zero Trust SSE API, built with the
[Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework) (protocol 6).

Maintained privately by North Fayette Valley CSD. Not affiliated with or endorsed by iboss or HashiCorp.

## Status

| Object | Type | Purpose |
|---|---|---|
| `iboss_allowlist_entry` | resource | One URL on a security group's allowlist |
| `iboss_blocklist_entry` | resource | One URL on a security group's block list |
| `iboss_allowlist`, `iboss_blocklist` | data sources | All entries on a group's list |
| `iboss_allowlist_settings` | data source | A group's allowlist settings (read-only) |
| `iboss_security_group` | data source | Find a group number by name |

The provider covers a small slice of the API. [`docs/api-coverage.md`](docs/api-coverage.md) maps every
in-scope operation, records what is planned or not mapped, and lists open questions about the API.

## Usage

```hcl
terraform {
  required_providers {
    iboss = {
      source = "nfvcsd/iboss"
    }
  }
}

provider "iboss" {} # reads IBOSS_API_KEY

data "iboss_security_group" "students" {
  name = "Students"
}

resource "iboss_blocklist_entry" "games" {
  group_number = data.iboss_security_group.students.group_number
  url          = "games.example.com"
  note         = "Managed by Terraform"
}
```

Authentication, discovery and limitations are described in [`docs/index.md`](docs/index.md). Per-object
reference pages are in `docs/resources` and `docs/data-sources`.

Because the repository is private and the provider is not on a public registry, install a build locally
(see [RELEASING.md](RELEASING.md)) or use a `dev_overrides` block while developing.

## Development

Requirements: Go (version in `go.mod`), Terraform 1.16.6 (pinned in CI), Python 3.10+ and `make`.

```sh
make test       # unit tests with -race
make testacc    # simulated acceptance tests: real Terraform CLI, local simulator
make build      # bin/terraform-provider-iboss
make docs       # regenerate docs/ from templates/ and examples/
make check      # everything CI runs (except the vulnerability scan: make vuln)
```

### Testing boundary

**Tests never contact an iboss tenant.** `internal/testutil` runs an HTTPS simulator for the core,
accounts and gateway hosts, built from the published API documentation. Every test client uses a
fail-closed transport that can only reach that simulator; production hosts, discovered hosts outside the
allowlist, plain HTTP and redirects all fail before a connection is attempted. `TF_ACC=1` only enables
these simulated acceptance tests. There is no live test mode, and none should be added.

A passing suite means the provider matches the documentation as we understood it. It does not prove the
real API behaves the same way. Treat the open questions in `docs/api-coverage.md` as risks, and try
changes on a non-production group first.

### Layout

```
internal/client     HTTP transport, authentication, discovery, typed API models
internal/provider   Terraform resources, data sources, provider configuration
internal/testutil   simulator and fail-closed test harness
examples/           example configurations (also rendered into docs/)
templates/          tfplugindocs templates
tools/              Python helpers: Postman inventory, example validation
```

### API documentation inventory

`make api-inventory` downloads the public Postman collection and writes `docs/api-inventory.md`, a full
per-operation table with source links. Compare its SHA-256 with the value recorded in
`docs/api-coverage.md` to spot documentation changes.
