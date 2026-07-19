"""
Core Sigstore verification logic for conda-sigstore.

This module provides:

- :func:`fetch_attestation_bundles` — download ``.v0.sigs`` attestation data
- :func:`verify_in_toto_statement` — cross-check the in-toto payload against
  the actual package metadata (CEP-0027)
- :func:`verify_package` — verify a package file against one or more bundles
- :class:`SigstoreVerificationAction` — conda pre-transaction action that ties
  the above together and is registered via the ``conda_pre_transaction_actions``
  hook in :mod:`conda_sigstore.hooks`.

Verification flow
-----------------
1.  conda resolves the package set and downloads all archives (via
    ``ProgressiveFetchExtract``).
2.  ``SigstoreVerificationAction.verify()`` is called before any file is linked
    into the target prefix.
3.  For every package whose channel URL appears in ``sigstore_trusted_channels``
    the action:

    a. Fetches ``<package-url>.v0.sigs`` — a JSON array of Sigstore bundles.
    b. Reads the local archive bytes from the package cache.
    c. Calls ``Verifier.verify_dsse()`` (the bundles are GitHub Actions DSSE
       bundles containing an in-toto statement).
    d. Cross-checks the in-toto statement against the package record per
       CEP-0027 (filename, SHA-256, targetChannel).
    e. Returns a :class:`CondaVerificationError` to conda if *all* bundles fail
       to verify, which aborts the transaction before anything is installed.

Bundle format
-------------
A ``.v0.sigs`` URL returns::

    [
      {
        "dsseEnvelope": { ... },
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { ... }
      },
      ...
    ]

Each element is a complete Sigstore bundle JSON object, suitable for
``Bundle.from_json()``.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import hashlib

import requests.exceptions
from conda.base.context import context
from conda.core.path_actions import Action
from conda.exceptions import CondaVerificationError
from conda.gateways.connection.session import get_session
from conda.models.channel import Channel
from py_sigstore import Bundle, Identity, VerificationError, Verifier

from .cache import fetch_and_cache_attestation_bundles
from .constants import ATTESTATION_FILE_SUFFIX

if TYPE_CHECKING:
    from conda.models.records import PackageCacheRecord, PackageRecord

log = logging.getLogger(__name__)

#: Predicate type required in in-toto statements per CEP-0027.
CONDA_PREDICATE_TYPE = "https://schemas.conda.org/attestations-publish-1.schema.json"


class AttestationFetchError(Exception):
    """Raised when the ``.v0.sigs`` endpoint cannot be reached or returns an
    unexpected HTTP status code."""


def fetch_attestation_bundles(package_url: str) -> list[str]:
    """Fetch Sigstore attestation bundles for a conda package.

    Appends ``.v0.sigs`` to *package_url* and downloads the JSON array of
    Sigstore bundle objects.

    Args:
        package_url: The full HTTPS download URL of the package archive, e.g.
            ``https://prefix.dev/github-releases/linux-64/foo-1.0-h0.conda``.

    Returns:
        A list of raw JSON strings, one per bundle.  The list may be empty if
        the server responds with ``[]``.

    Raises:
        :class:`AttestationFetchError`: If the HTTP request fails (e.g. 404,
            connection error, or the response body is not valid JSON).
    """
    sigs_url = f"{package_url}{ATTESTATION_FILE_SUFFIX}"
    log.debug("Fetching attestation from %s", sigs_url)

    session = get_session(sigs_url)
    try:
        response = session.get(sigs_url, timeout=30)
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise AttestationFetchError(
            f"HTTP {exc.response.status_code} fetching attestation from {sigs_url}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise AttestationFetchError(
            f"Network error fetching attestation from {sigs_url}: {exc}"
        ) from exc

    try:
        bundles = response.json()
    except ValueError as exc:
        raise AttestationFetchError(
            f"Invalid JSON in attestation response from {sigs_url}: {exc}"
        ) from exc

    if not isinstance(bundles, list):
        raise AttestationFetchError(
            f"Expected a JSON array from {sigs_url}, got {type(bundles).__name__}"
        )

    # Serialise each bundle object back to a JSON string so callers can pass
    # them to Bundle.from_json() without having to re-serialise themselves.
    return [json.dumps(bundle) for bundle in bundles]


def verify_in_toto_statement(
    payload: bytes,
    expected_filename: str,
    expected_channel: str,
    artifact_bytes: bytes,
) -> None:
    """Validate an in-toto statement payload against the actual package metadata.

    Performs the cross-checks required by CEP-0027 after Sigstore cryptographic
    verification:

    - ``predicateType`` must be :data:`CONDA_PREDICATE_TYPE`.
    - ``subject`` must contain exactly one entry whose ``name`` matches
      *expected_filename*.
    - The subject ``digest.sha256`` must match the SHA-256 of *artifact_bytes*.
    - ``predicate.targetChannel`` must match *expected_channel* (channel from
      which the package was downloaded).

    Args:
        payload: Raw bytes of the decoded in-toto statement JSON (as returned
            by :meth:`~py_sigstore.Verifier.verify_dsse`).
        expected_filename: The package filename (e.g. ``foo-1.0-h0.conda``).
        expected_channel: The channel base URL the package was retrieved from
            (e.g. ``https://prefix.dev/github-releases``), without trailing
            slash.
        artifact_bytes: Raw bytes of the package archive for digest comparison.

    Raises:
        :class:`~py_sigstore.VerificationError`: If any check fails.
    """
    stmt = json.loads(payload)

    predicate_type = stmt.get("predicateType")
    if predicate_type != CONDA_PREDICATE_TYPE:
        raise VerificationError(
            f"Unexpected predicateType {predicate_type!r}; "
            f"expected {CONDA_PREDICATE_TYPE!r}"
        )

    subjects = stmt.get("subject", [])
    if len(subjects) != 1:
        raise VerificationError(
            f"Expected exactly 1 subject in in-toto statement, got {len(subjects)}"
        )

    subject = subjects[0]
    bundle_name = subject.get("name")
    if bundle_name != expected_filename:
        raise VerificationError(
            f"Bundle subject name {bundle_name!r} != package filename {expected_filename!r}"
        )

    actual_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    bundle_sha256 = subject.get("digest", {}).get("sha256", "")
    if actual_sha256 != bundle_sha256:
        raise VerificationError(
            f"SHA-256 mismatch: bundle has {bundle_sha256!r}, "
            f"local file computes {actual_sha256!r}"
        )

    target_channel = stmt.get("predicate", {}).get("targetChannel", "").rstrip("/")
    if target_channel != expected_channel.rstrip("/"):
        raise VerificationError(
            f"Bundle targetChannel {target_channel!r} != "
            f"download channel {expected_channel!r}"
        )


def verify_package(
    verifier: Verifier,
    artifact_bytes: bytes,
    bundle_jsons: list[str],
    policy: Identity,
    expected_filename: str,
    expected_channel: str,
) -> None:
    """Verify *artifact_bytes* against at least one of the provided bundles.

    Iterates over *bundle_jsons* and calls
    :meth:`~py_sigstore.Verifier.verify_dsse` for each.  For each bundle that
    passes Sigstore verification, also cross-checks the in-toto statement
    against the package metadata per CEP-0027 via
    :func:`verify_in_toto_statement`.  Succeeds (returns ``None``) as soon as
    *any* bundle passes both checks.  Raises
    :class:`~py_sigstore.VerificationError` only if *every* bundle fails.

    Args:
        verifier: A pre-constructed :class:`~py_sigstore.Verifier` instance.
        artifact_bytes: Raw bytes of the package archive.
        bundle_jsons: Non-empty list of Sigstore bundle JSON strings.
        policy: The :class:`~py_sigstore.Identity` the signer must match.
        expected_filename: Package filename for in-toto subject name check.
        expected_channel: Channel base URL for in-toto targetChannel check.

    Raises:
        :class:`~py_sigstore.VerificationError`: If all bundles fail
            verification.
        :class:`~py_sigstore.BundleError`: If a bundle JSON string cannot be
            parsed.
        ValueError: If *bundle_jsons* is empty (caller bug).
    """
    if not bundle_jsons:
        raise ValueError("bundle_jsons must not be empty")

    last_error: VerificationError | None = None
    for bundle_json in bundle_jsons:
        bundle = Bundle.from_json(bundle_json)
        try:
            _, payload = verifier.verify_dsse(artifact_bytes, bundle, policy)
            verify_in_toto_statement(
                payload, expected_filename, expected_channel, artifact_bytes
            )
            log.debug("Sigstore verification succeeded")
            return  # success — no need to check remaining bundles
        except VerificationError as exc:
            log.debug("Bundle verification failed: %s", exc)
            last_error = exc

    # All bundles failed — surface the last error.
    assert last_error is not None  # guaranteed: bundle_jsons is non-empty
    raise last_error


def _get_cache_record(rec: PackageRecord) -> PackageCacheRecord:
    """Look up the local :class:`~conda.models.records.PackageCacheRecord` for
    *rec*.

    By the time a pre-transaction action runs, ``ProgressiveFetchExtract`` has
    already downloaded and extracted every package, so this lookup is always
    expected to succeed.

    Args:
        rec: A package record from the transaction's ``link_precs``.

    Returns:
        The corresponding :class:`~conda.models.records.PackageCacheRecord`
        with a valid ``package_tarball_full_path``.

    Raises:
        :class:`~conda.exceptions.CondaVerificationError`: If the package
            cannot be found in the local cache (should not happen in normal
            usage).
    """
    from conda.core.package_cache_data import PackageCacheData

    cache_rec = PackageCacheData.get_entry_to_link(rec)
    if cache_rec is None:
        raise CondaVerificationError(
            f"Package {rec.fn!r} not found in local cache; "
            "cannot perform Sigstore verification."
        )
    return cache_rec


# ---------------------------------------------------------------------------
# conda pre-transaction Action
# ---------------------------------------------------------------------------


class SigstoreVerificationAction(Action):
    """conda pre-transaction action that verifies Sigstore attestations.

    Registered via :func:`conda_sigstore.hooks.conda_pre_transaction_actions`.
    conda instantiates this class with the full transaction context and calls
    :meth:`verify` before linking any packages into the target prefix.

    Settings are read from ``context.plugins`` at verification time:

    ``sigstore_identity``
        Expected signer identity string.  ``None`` accepts any identity
        matching the issuer.

    ``sigstore_issuer``
        Expected OIDC issuer URL.  Defaults to the GitHub Actions issuer.

    ``sigstore_on_missing``
        ``"block"`` (default) or ``"warn"``.  Controls behaviour when a
        package has no attestation.

    ``sigstore_trusted_channels``
        List of channel base URLs to verify.  Only packages from these
        channels are checked.  Empty list disables verification.
    """

    def verify(self) -> Exception | None:
        """Run Sigstore verification for all packages from trusted channels.

        Attestation bundles are fetched in parallel using a
        :class:`~concurrent.futures.ThreadPoolExecutor` sized by
        ``context.fetch_threads`` (the same setting conda uses for package
        downloads, defaulting to 5).  Disk reads and cryptographic
        verification are performed sequentially after all fetches complete.

        Returns:
            ``None`` on success (sets ``self._verified = True``).
            An :class:`~conda.exceptions.CondaVerificationError` if
            verification fails for any package.
        """
        # Read plugin settings (accessed via context.plugins.<name>).
        plugins = context.plugins
        identity_str: str | None = plugins.sigstore_identity
        issuer_str: str | None = plugins.sigstore_issuer
        on_missing: str = plugins.sigstore_on_missing

        trusted: set[str | None] = {
            Channel.from_url(ch).base_url for ch in plugins.sigstore_trusted_channels
        }

        # Build the verifier once — the embedded GHA root requires no network
        # call and is correct for all packages on trusted channels.
        verifier = Verifier.github()

        # Build the Identity policy.  When identity_str is None we pass an
        # empty string as a sentinel; py_sigstore treats this as "any identity"
        # when only issuer matching matters.
        policy = Identity(
            identity=identity_str or "",
            issuer=issuer_str,
        )

        trusted_recs: list[PackageRecord] = [
            rec
            for rec in (self.link_precs or [])
            if rec.url and Channel.from_url(rec.url).base_url in trusted
        ]

        if not trusted_recs:
            self._verified = True
            return None

        # --- Parallel fetch phase --------------------------------------------
        # Submit all attestation bundle fetches concurrently.  The pool size
        # is driven by context.fetch_threads so it respects the user's
        # configured parallelism (default: 5).  CondaSession is per-thread
        # (CondaSessionType metaclass), so each worker gets its own session
        # instance automatically — no locking required.
        fetch_futures: dict = {}
        with ThreadPoolExecutor(max_workers=context.fetch_threads) as executor:
            for rec in trusted_recs:
                log.info("Fetching Sigstore attestation for %s", rec.fn)
                fetch_futures[executor.submit(fetch_and_cache_attestation_bundles, rec.url)] = rec

        # --- Sequential verify phase -----------------------------------------
        # All fetches are complete; process results in submission order so that
        # error reporting is deterministic.  Return on the first error found
        # (preserves existing early-exit semantics).
        for future, rec in fetch_futures.items():
            # --- Fetch result ------------------------------------------------
            try:
                bundle_jsons = future.result()
            except AttestationFetchError as exc:
                msg = f"Could not fetch Sigstore attestation for {rec.fn!r}: {exc}"
                if on_missing == "block":
                    return CondaVerificationError(msg)
                log.warning("%s — continuing (sigstore_on_missing=warn)", msg)
                continue

            # --- Handle empty attestation list --------------------------------
            if not bundle_jsons:
                msg = f"No Sigstore attestation available for {rec.fn!r}"
                if on_missing == "block":
                    return CondaVerificationError(msg)
                log.warning("%s — continuing (sigstore_on_missing=warn)", msg)
                continue

            # --- Read the locally cached archive ------------------------------
            try:
                cache_rec = _get_cache_record(rec)
            except CondaVerificationError as exc:
                return exc

            try:
                with open(cache_rec.package_tarball_full_path, "rb") as fh:
                    artifact_bytes = fh.read()
            except OSError as exc:
                return CondaVerificationError(
                    f"Could not read cached package {cache_rec.package_tarball_full_path!r}: {exc}"
                )

            # --- Verify -------------------------------------------------------
            try:
                verify_package(
                    verifier,
                    artifact_bytes,
                    bundle_jsons,
                    policy,
                    expected_filename=rec.fn,
                    expected_channel=Channel.from_url(rec.url).base_url or "",
                )
            except VerificationError as exc:
                return CondaVerificationError(
                    f"Sigstore verification failed for {rec.fn!r}: {exc}"
                )

            log.info("Sigstore verification passed for %s", rec.fn)

        self._verified = True
        return None

    def execute(self) -> None:
        """No-op: all work is done in :meth:`verify`."""

    def reverse(self) -> None:
        """No-op: nothing to reverse."""

    def cleanup(self) -> None:
        """No-op: nothing to clean up."""
