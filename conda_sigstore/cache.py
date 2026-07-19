"""
Attestation bundle cache backed by the user's platformdirs cache directory.

Cache keys are the full ``.v0.sigs`` URL.  Bundle data is stored as a
JSON file per URL, named by a SHA-256 digest of the URL.  Bundles are
immutable once published, so no TTL or invalidation logic is required.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from platformdirs import user_cache_dir

from .constants import ATTESTATION_FILE_SUFFIX

log = logging.getLogger(__name__)

_APP_NAME = "conda-sigstore"


def get_cache_dir() -> Path:
    """Return the platformdirs user cache directory for conda-sigstore."""
    return Path(user_cache_dir(_APP_NAME))


def _url_to_cache_path(url: str) -> Path:
    digest = hashlib.sha256(url.encode()).hexdigest()
    return get_cache_dir() / digest


def get_cached_bundles(url: str) -> list[str] | None:
    """Return cached bundle JSON strings for *url*, or ``None`` if not cached.

    Args:
        url: The full ``.v0.sigs`` URL used as the cache key.

    Returns:
        A list of bundle JSON strings on a cache hit, or ``None`` on a miss.
        A corrupt or unreadable cache entry is treated as a miss.
    """
    cache_path = _url_to_cache_path(url)
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            log.debug("Cache hit for %s", url)
            return data
    except (OSError, ValueError) as exc:
        log.debug("Ignoring corrupt cache entry %s: %s", cache_path, exc)
    return None


def cache_bundles(url: str, bundles: list[str]) -> None:
    """Write *bundles* to the cache under the key *url*.

    Failures are logged at DEBUG level and silently ignored so that a
    read-only or missing cache directory never breaks verification.

    Args:
        url: The full ``.v0.sigs`` URL used as the cache key.
        bundles: List of bundle JSON strings to persist.
    """
    cache_path = _url_to_cache_path(url)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(bundles), encoding="utf-8")
        log.debug("Cached %d bundle(s) for %s", len(bundles), url)
    except OSError as exc:
        log.debug("Could not write cache entry %s: %s", cache_path, exc)


def fetch_and_cache_attestation_bundles(package_url: str) -> list[str]:
    """Return attestation bundles for *package_url*, using the cache when possible.

    On a cache miss the bundles are fetched from the network via
    :func:`~conda_sigstore.verifier.fetch_attestation_bundles` and then
    written to the cache before being returned.  The cache key is the
    ``.v0.sigs`` URL derived from *package_url*.

    Args:
        package_url: The full HTTPS download URL of the package archive.

    Returns:
        A list of raw bundle JSON strings (may be empty).

    Raises:
        :class:`~conda_sigstore.verifier.AttestationFetchError`: Propagated
            from the underlying fetch on network or parsing failures.
    """
    from .verifier import fetch_attestation_bundles

    sigs_url = f"{package_url}{ATTESTATION_FILE_SUFFIX}"
    cached = get_cached_bundles(sigs_url)
    if cached is not None:
        return cached
    log.debug("Cache miss for %s — fetching", sigs_url)
    bundles = fetch_attestation_bundles(package_url)
    cache_bundles(sigs_url, bundles)
    return bundles
