# conda-sigstore

A conda plugin that verifies [Sigstore](https://www.sigstore.dev/) attestations for packages
installed from user-configured trusted channels. This is a proof of concept aimed at showing how
this plugin could work in the future. It is not intended to be used in production.

When you install a package from a trusted channel, the plugin fetches its Sigstore attestation,
verifies the cryptographic signature against the downloaded archive, cross-checks the in-toto
statement inside the attestation bundle against the package metadata (filename, SHA-256 digest,
and target channel per [CEP-0027](https://conda.org/learn/ceps/cep-0027)), and aborts the
installation if any check fails — before any files are written to your environment.

## Requirements

- conda >= 26.5.0
- Python >= 3.11
- osx-arm64/linux-aarch64 platform (the `py-sigstore` dependency is currently only published for that
  architecture)

## Installation

The package is published to the
[`https://prefix.dev/thath`](https://prefix.dev/channels/thath) channel.

**With conda:**

```bash
conda install --name base --channel https://prefix.dev/thath conda-sigstore
```

Once installed, conda will automatically discover the plugin via its entry point and activate
it for all subsequent install, update, and create operations.

## How it works

The plugin uses the `conda_pre_transaction_actions` hook, which runs **after** packages are
downloaded to the local cache but **before** any files are linked into the target environment.

For every package being installed whose channel appears in `sigstore_trusted_channels`,
the plugin:

1. **Fetches the attestation** by appending `.v0.sigs` to the package download URL, e.g.:
   ```
   https://prefix.dev/github-releases/osx-arm64/7zip-25.00-hb0f4dca_0.conda.v0.sigs
   ```
   The response is a JSON array of [Sigstore bundle](https://github.com/sigstore/protobuf-specs)
   objects, each containing a DSSE envelope with an in-toto statement.

2. **Reads the local archive** from the conda package cache.

3. **Verifies the bundle** using the embedded GitHub Actions trusted root (no additional
   network call required).

4. **Cross-checks the in-toto statement** inside the bundle against the actual package
   per [CEP-0027](https://conda.org/learn/ceps/cep-0027):
   - The predicate type must be `https://schemas.conda.org/attestations-publish-1.schema.json`
   - The subject filename must match the package being installed
   - The subject SHA-256 digest must match the downloaded archive
   - The `targetChannel` must match the channel the package was retrieved from

5. **Blocks the install** and reports a `CondaVerificationError` if all bundles for a package
   fail verification, or if no attestation is available and the plugin is configured in strict
   mode (the default).

Packages from channels not listed in `sigstore_trusted_channels` are silently skipped because
we assume the user does not want this feature enabled for it. Additionally, support for this
feature is currently very limited, so most channels will not be able to support it.

## Configuration

All settings live under the `plugins` key in `.condarc` and can also be set via environment
variables prefixed with `CONDA_PLUGINS_`.

### `sigstore_identity`

The expected signer identity. For packages signed by GitHub Actions this is a workflow URI.

| | |
|---|---|
| **Type** | `str` or unset |
| **Default** | unset (accepts any identity matching the issuer) |
| **Env var** | `CONDA_PLUGINS_SIGSTORE_IDENTITY` |

**Example** — pin to a specific workflow:

```yaml
# .condarc
plugins:
  sigstore_identity: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
```

When left unset, any signer identity is accepted as long as it was issued by the configured
`sigstore_issuer`. Pinning to a specific workflow URI is the strictest and most secure option.

---

### `sigstore_issuer`

The expected [OIDC](https://openid.net/connect/) issuer URL. The issuer identifies the
certificate authority that issued the signing certificate.

| | |
|---|---|
| **Type** | `str` or `null` |
| **Default** | `https://token.actions.githubusercontent.com` |
| **Env var** | `CONDA_PLUGINS_SIGSTORE_ISSUER` |

**Example** — accept any issuer (not recommended):

```yaml
# .condarc
plugins:
  sigstore_issuer: null
```

The default accepts only GitHub Actions-issued certificates. Setting this to `null` disables
issuer checking and is not recommended in production.

---

### `sigstore_trusted_channels`

The list of channel base URLs for which Sigstore attestations are required. Only packages
downloaded from one of these channels will be verified; all other packages are silently skipped.
An empty list (the default) disables verification entirely.

| | |
|---|---|
| **Type** | list of `str` |
| **Default** | `[]` (verification disabled) |
| **Env var** | `CONDA_PLUGINS_SIGSTORE_TRUSTED_CHANNELS` |

**Example** — enable verification for `github-releases` on prefix.dev:

```yaml
# .condarc
plugins:
  sigstore_trusted_channels:
    - https://prefix.dev/github-releases
```

The plugin uses conda's own `Channel` model to parse and compare URLs, so trailing slashes and
minor URL variations are normalised automatically.

---

### `sigstore_on_missing`

Controls what happens when a package from a trusted channel has no attestation (the `.v0.sigs`
endpoint returns a 404 or an empty array).

| | |
|---|---|
| **Type** | `"block"` or `"warn"` |
| **Default** | `"block"` |
| **Env var** | `CONDA_PLUGINS_SIGSTORE_ON_MISSING` |

| Value | Behaviour |
|---|---|
| `"block"` | Abort the installation with an error (default, most secure). |
| `"warn"` | Log a warning and allow the install to proceed. |

**Example** — allow packages without attestations (e.g. during a rollout):

```yaml
# .condarc
plugins:
  sigstore_on_missing: warn
```

Or as a one-off override via environment variable:

```bash
CONDA_PLUGINS_SIGSTORE_ON_MISSING=warn conda install -c https://prefix.dev/github-releases 7zip
```

---

### Full example `.condarc`

```yaml
channels:
  - https://prefix.dev/github-releases
  - conda-forge

plugins:
  sigstore_trusted_channels:
    - https://prefix.dev/github-releases
  sigstore_identity: "https://github.com/hunger/octoconda/.github/workflows/octoconda.yaml@refs/heads/main"
  sigstore_issuer: "https://token.actions.githubusercontent.com"
  sigstore_on_missing: block
```

## Development

This project uses [pixi](https://pixi.sh) to manage the environment.

```bash
# Install dependencies
pixi install -e dev

# Run tests (osx-arm64 only)
pixi run -e dev pytest tests/ -v

# Run pre-commit checks
pixi run -e dev pre-commit run --all-files
```
