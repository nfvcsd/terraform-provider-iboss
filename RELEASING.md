# Releasing

Releases are built by `.github/workflows/release.yml` when a version tag (`v*`) is pushed. The workflow
uses GoReleaser to create a **draft** GitHub release with a zip archive per platform, `SHA256SUMS`, a
detached GPG signature of the checksums, and the registry manifest.

The provider is published on the public Terraform Registry as
[`nfvcsd/iboss`](https://registry.terraform.io/providers/nfvcsd/iboss/latest). The registry ingests a
release when it is **published** on GitHub (drafts are ignored), checks the signature against the public
key registered for the `nfvcsd` namespace, and renders the documentation from `docs/` at the tagged
commit. Publishing a draft therefore releases it to everyone; treat that click as the release.

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

### Release protections

The repository is public, so GitHub Free now supports environment secrets, required reviewers and tag
rulesets. The workflow already declares `environment: release`. Recommended next steps, in the
repository settings:

- move `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` from repository secrets to the `release` environment and
  require a reviewer for it;
- add a tag ruleset so only maintainers can create or delete `v*` tags;
- keep reviewing changes under `.github/workflows/` before running them. `ci.yml` never references the
  signing secrets.

## Cutting a release

1. Move the `Unreleased` notes in `CHANGELOG.md` under a new version heading and merge to `main` with CI
   green.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git checkout main && git pull
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

3. Watch **Actions → Release**. When it finishes, open **Releases**, check the draft has an archive for each
   platform plus `_SHA256SUMS`, `_SHA256SUMS.sig` and `_manifest.json`, then publish it.
4. Within a few minutes the new version appears on the registry. If it doesn't, confirm the release is
   published (not a draft) and signed with the key registered for the namespace, then use **Resync** on
   the provider's page in the registry.

Fix a bad release with a new version. Never replace published artifacts.

## Verifying a release

`terraform init` verifies registry downloads against the signing key automatically. To check an archive
by hand:

```sh
gpg --import keys/iboss-provider-signing.asc
gpg --verify terraform-provider-iboss_0.1.0_SHA256SUMS.sig terraform-provider-iboss_0.1.0_SHA256SUMS
shasum -a 256 -c terraform-provider-iboss_0.1.0_SHA256SUMS --ignore-missing
```

## Moving off a local mirror

Before the registry listing, builds were installed into a filesystem mirror under
`~/.terraform.d/plugins/registry.terraform.io/nfvcsd/iboss/`. Terraform prefers that folder over the
registry, so remove it and run `terraform init -upgrade` to install from the registry instead. The
provider address (`registry.terraform.io/nfvcsd/iboss`) is unchanged, so state and lock files need no
edits; the lock file gains registry hashes on the next `init`.
