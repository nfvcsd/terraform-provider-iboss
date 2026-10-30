# Releasing

Releases are built by `.github/workflows/release.yml` when a maintainer pushes a `v*` tag. The workflow
creates a **draft** GitHub release in this private repository with signed archives, `SHA256SUMS` and the
registry manifest. Nothing is pushed to a Terraform registry.

## One-time setup (not done yet)

1. In **Settings → Environments**, create an environment named `release` with required reviewers.
2. Generate a dedicated GPG signing key for the provider. Add `GPG_PRIVATE_KEY` (ASCII-armored) and
   `GPG_PASSPHRASE` as secrets **on the `release` environment**, not as repository secrets, so PR jobs
   can never read them.
3. Decide where teams will install the provider from:
   - **Local filesystem or network mirror** (simplest for a private provider). Unzip a release archive into
     `~/.terraform.d/plugins/registry.terraform.io/nfvcsd/iboss/<version>/<os>_<arch>/`, or host the files as
     a [provider network mirror](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol).
   - **HCP Terraform private registry** for the organization.
   - The **public Terraform Registry** requires a public repository named `terraform-provider-iboss`. That
     conflicts with keeping this code private, so it is out of scope unless that decision changes.

The provider address compiled into `main.go` is `registry.terraform.io/nfvcsd/iboss`. Change it if you
choose a different registry host before the first release.

## Cutting a release

1. Update `CHANGELOG.md` and merge to `main` with CI green.
2. `git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`
3. Approve the `release` environment deployment, review the draft release, then publish it.

Fix a bad release with a new version. Never replace published artifacts.
