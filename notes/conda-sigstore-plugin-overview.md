# Sigstore Artifact Verification Plugin for conda — High-Level Overview

## 1. Motivation

conda installs packages (`.conda` / `.tar.bz2` archives) from channels indexed by
`repodata.json`. Today, integrity relies almost entirely on:

- TLS to the channel/CDN (protects transport, not the artifact's provenance)
- SHA-256 hashes embedded in `repodata.json` (protects against corruption, not
  against a compromised index or build system that signs off on a malicious hash)
- Optional TUF-based trust via `conda-content-trust` (root/targets keys, but this
  requires conda maintainers or channel owners to manage long-lived signing keys)

A sigstore-backed plugin adds a complementary layer: cryptographic proof of *who
or what* produced a given artifact, anchored in a public, append-only
transparency log, without requiring long-lived private keys to be generated,
distributed, or rotated by package maintainers.

## 2. Where it fits in conda's plugin system

conda's plugin architecture (`conda.plugins`, using `pluggy` hookspecs) exposes
several hook points that are candidates for this work:

- **`conda_pre_solve` / `conda_post_solve`** — could gate or annotate which
  package specs are eligible before the solver runs, or inspect the resolved
  set of `PackageRecord`s after solving.
- **`conda_pre_transaction_actions` / `conda_post_transaction_actions`** — the
  most natural hook: verification happens *after* the solver has decided what
  to link/unlink, but *before* packages are actually extracted and linked into
  the environment. This is the last safe checkpoint before bytes hit disk.
- **`conda_settings`** — to expose user-facing config (enforcement mode, trusted
  identity list, cache location) via `.condarc` / CLI flags.
- **`conda_subcommands`** — for a standalone `conda verify` command useful for
  auditing an existing environment or a local package cache outside of an
  install flow.

Given that package downloads and extraction happen inside the transaction
execution step, the most robust design intercepts each package *before
extraction*, verifying it against a fetched signature bundle, and raises to
abort the transaction on failure (or warns, depending on configured
enforcement level).

## 3. Verification flow (conceptual)

1. **Fetch the artifact** as normal (channel URL, CDN, etc.) — no change to
   existing download logic.
2. **Fetch its signature bundle.** Sigstore's `cosign`/`sigstore-python`
   tooling produces a bundle containing: the artifact digest, a short-lived
   X.509 certificate issued by Fulcio (binding a public key to an OIDC
   identity — e.g. a GitHub Actions workflow identity for conda-forge's
   feedstock CI), the signature itself, and an inclusion proof/entry from the
   Rekor transparency log. This bundle could be published alongside the
   artifact in the channel (e.g. `package.conda.sigstore.json` or embedded as
   package metadata in `repodata.json`).
3. **Verify offline-checkable material:** recompute the artifact digest and
   compare to the signed digest; validate the certificate chain against
   Fulcio's root; check certificate validity window against the Rekor
   entry's logged timestamp (since the cert itself is short-lived, typically
   minutes).
4. **Verify the transparency log inclusion proof** against a trusted Rekor
   log checkpoint (can be done offline against a cached/pinned checkpoint,
   or online against the live log — a design tradeoff).
5. **Check the signing identity against a policy.** This is the crux of the
   trust decision: was the certificate issued to an identity conda is
   configured to trust for this package/channel (e.g. "any workflow in
   `conda-forge/*-feedstock` repos" or "a specific maintainer's OIDC
   identity")? This is where sigstore differs most from classic PGP/TUF:
   trust is expressed as *identity + issuer* policy, not key possession.
6. **Enforce.** Depending on config: block install, warn and proceed, or
   silently log — likely staged rollout (log-only → warn → enforce) similar
   to how `conda-content-trust` and other ecosystems (npm, PyPI's forthcoming
   work) have approached rollout.

## 4. Threat model — what this helps protect against

- **Build/CI compromise producing a tampered artifact**, where the attacker
  can alter file contents post-build but cannot forge a Fulcio certificate
  bound to the legitimate CI identity (since Fulcio issuance requires a valid
  OIDC token from the real workflow).
- **Channel/mirror/CDN compromise or malicious substitution**, where an
  attacker swaps a package on the index or a mirror. Signature + digest
  verification detects any artifact that doesn't match what the legitimate
  identity actually signed.
- **Malicious insider or stolen static credentials**, to the extent the
  signing identity is an ephemeral, workload-bound OIDC identity (e.g. tied
  to a specific CI job) rather than a long-lived, exportable key — there's no
  persistent private key an attacker can exfiltrate and reuse indefinitely.
- **Silent retroactive tampering**, because Rekor's log is append-only and
  publicly auditable; a forged or backdated entry would be detectable by
  anyone monitoring the log (monitoring/log-consistency checking is itself
  a separate operational piece).
- **Typosquatting / impersonation at the channel level**, if policy binds
  trust to a specific verified identity (e.g. the real conda-forge CI) rather
  than "any signature exists" — a copycat package signed by an unrelated
  identity would fail the identity-policy check even if cryptographically
  valid.

## 5. What it does *not* protect against (be explicit about limits)

- **A legitimately signed but intentionally malicious package.** Sigstore
  proves provenance, not benign intent — if the real maintainer's CI signs
  malware, verification passes.
- **Compromise of the OIDC identity provider itself** (e.g. GitHub Actions
  OIDC issuer), which would let an attacker mint valid Fulcio certs for that
  identity. This shifts trust up a level rather than eliminating it.
- **Compromise at solve time** unrelated to artifact authenticity (dependency
  confusion via channel priority misconfiguration, etc.) — this is a
  different problem from artifact integrity and needs separate mitigations.
- **Users who disable/bypass enforcement**, or a rollout period where
  verification is warn-only and most packages are unsigned (adoption gap is
  a real bootstrapping problem — see below).

## 6. Open design questions worth scoping early

- **Bundle distribution.** Sidecar file per artifact vs. embedding in
  `repodata.json` vs. a separate signed manifest — affects both index size
  and how incremental adoption works.
- **Identity policy format and management.** Who defines "trusted identity
  for this channel" — conda itself, channel owners via a policy file, or
  end users via `.condarc`? This is analogous to TUF's root-of-trust problem.
- **Online vs. offline Rekor checking.** Offline (cached checkpoints) avoids
  a network dependency and log-availability outage blocking installs, but
  needs a secure checkpoint-update mechanism to avoid trusting a stale/rolled-back
  log.
- **Interaction with `conda-content-trust`/TUF.** Are these complementary
  (TUF for index/metadata integrity + rollback protection, sigstore for
  per-artifact provenance) or does one supersede the other for conda's needs?
- **Adoption/bootstrapping.** Verification is only meaningful once major
  channels (conda-forge, defaults) actually sign artifacts in CI — the
  plugin's value curve tracks upstream signing adoption, not just the
  plugin's existence.
- **Revocation.** Sigstore's short-lived certs sidestep classical key
  revocation, but what's the story for "this specific artifact/version was
  signed correctly but is now known-bad" (recall/yank scenarios)?

## 7. Suggested prior art to review

- `conda-content-trust` (existing TUF-based effort in the conda ecosystem)
- `conda-protect` (referenced by conda.org as an example plugin using the
  pre/post-command hooks — useful as a template for hook wiring even though
  its purpose differs)
- npm's and PyPI's (Trusted Publishing / sigstore-python) work, as the
  closest analogues of applying sigstore to a language-level package
  ecosystem
