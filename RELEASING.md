# Releasing

Releases are built by `.github/workflows/release.yml` when a version tag (`v*`) is pushed. The workflow
uses GoReleaser to create a **draft** GitHub release in this private repository with a zip archive per
platform, `SHA256SUMS`, a detached GPG signature of the checksums, and the registry manifest. Nothing is
pushed to a Terraform registry.

## Signing key

| | |
|---|---|
| Identity | NFVCSD Terraform provider signing |
| Type | RSA 4096 (sign and certify) |
| Fingerprint | `6F5F 70CB 3636 A17E 952C  D467 B97A D4D6 6CCC E722` |
| Created / expires | 2026-11-09 / 2028-11-08 |
| Public key | [`keys/iboss-provider-signing.asc`](keys/iboss-provider-signing.asc) |

The private key and its passphrase are stored as the repository secrets `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE`, with a backup in the maintainer's password manager. Rotate the key before it expires:
generate a new one, replace both secrets and the public key file, and note the change in `CHANGELOG.md`.

### GitHub Free limitations

The organization is on GitHub Free, so this private repository cannot use environment secrets, required
reviewers, or tag rulesets. The workflow still declares `environment: release`; on Free it has no effect,
and the protections can be configured there if the plan changes. Until then:

- anyone with write access can push a `v*` tag and run a release, so keep write access limited;
- a workflow changed in a pull request from a branch of this repository can read repository secrets, so
  review changes under `.github/workflows/` before running them;
- `ci.yml` never references the signing secrets.

## Cutting a release

1. Move the `Unreleased` notes in `CHANGELOG.md` under a new version heading and merge to `main` with CI
   green.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git checkout main && git pull
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

3. Watch **Actions → Release**. When it finishes, open **Releases**, check the draft has an archive for each
   platform plus `_SHA256SUMS`, `_SHA256SUMS.sig` and `_manifest.json`, then publish it.

Fix a bad release with a new version. Never replace published artifacts.

## Verifying and installing a release

```sh
gpg --import keys/iboss-provider-signing.asc
gpg --verify terraform-provider-iboss_0.1.0_SHA256SUMS.sig terraform-provider-iboss_0.1.0_SHA256SUMS
shasum -a 256 -c terraform-provider-iboss_0.1.0_SHA256SUMS --ignore-missing
```

Terraform finds the provider in a local mirror. On an Apple Silicon Mac:

```sh
dest=~/.terraform.d/plugins/registry.terraform.io/nfvcsd/iboss/0.1.0/darwin_arm64
mkdir -p "$dest"
unzip terraform-provider-iboss_0.1.0_darwin_arm64.zip -d "$dest"
```

Use the matching `<os>_<arch>` folder on other systems (for example `linux_amd64` in CI). Remove older
development builds from the same folder tree, then run `terraform init -upgrade`.

The provider address compiled into `main.go` is `registry.terraform.io/nfvcsd/iboss`. Hosting the files as a
[provider network mirror](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol)
or in an HCP Terraform private registry are later options; the public Terraform Registry would require a
public repository named `terraform-provider-iboss`.
