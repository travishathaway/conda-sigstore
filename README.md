# conda-sigstore

A conda plugin that verifies [Sigstore](https://www.sigstore.dev/) attestations for packages
installed from the [`github-releases`](https://prefix.dev/channels/github-releases) channel on
prefix.dev. This is a proof of concept aimed at showing how this plugin could work in the
future. It is not intended to be used in production.

When you install a package from that channel, the plugin fetches its Sigstore attestation,
verifies the cryptographic signature against the downloaded archive, and aborts the installation
if verification fails — before any files are written to your environment.

## Requirements

- conda >= 26.5.0
- Python >= 3.11
- osx-arm64 platform (the `py-sigstore` dependency is currently only published for that
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

For every package being installed whose URL belongs to `https://prefix.dev/github-releases`,
the plugin:

1. **Fetches the attestation** by appending `.v0.sigs` to the package download URL, e.g.:
   ```
   https://prefix.dev/github-releases/osx-arm64/7zip-25.00-hb0f4dca_0.conda.v0.sigs
   ```
   The response is a JSON array of [Sigstore bundle](https://github.com/sigstore/protobuf-specs)
   objects, each containing a DSSE envelope with an in-toto statement.

2. **Reads the local archive** from the conda package cache.

3. **Verifies the bundle** using the embedded GitHub Actions trusted root (no additional
   network call required). The in-toto statement inside the DSSE envelope must name the
   package file and its SHA-256 digest as a subject, binding the attestation to the exact
   archive being installed.

4. **Blocks the install** and reports a `CondaVerificationError` if all bundles for a package
   fail verification, or if no attestation is available and the plugin is configured in strict
   mode (the default).

Packages from other channels (e.g. `conda-forge`) are silently skipped.

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

The default accepts only GitHub Actions-issued certificates, which is correct for the
`github-releases` channel. Setting this to `null` disables issuer checking and is not
recommended in production.

---

### `sigstore_on_missing`

Controls what happens when a package from the `github-releases` channel has no attestation
(the `.v0.sigs` endpoint returns a 404 or an empty array).

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
