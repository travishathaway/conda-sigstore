"""
Tests for conda_sigstore.cache.

All tests run fully offline; filesystem access is isolated to a tmp_path
fixture directory so the real user cache is never touched.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from conda_sigstore.cache import (
    _url_to_cache_path,
    cache_bundles,
    fetch_and_cache_attestation_bundles,
    get_cache_dir,
    get_cached_bundles,
)
from conda_sigstore.constants import ATTESTATION_FILE_SUFFIX

SAMPLE_URL = "https://prefix.dev/github-releases/linux-64/foo-1.0-h0.conda.v0.sigs"
PACKAGE_URL = "https://prefix.dev/github-releases/linux-64/foo-1.0-h0.conda"
SAMPLE_BUNDLES = ['{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}']


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_cache_dir(tmp_path: Path):
    """Context manager that redirects the cache dir to *tmp_path*."""
    return patch("conda_sigstore.cache.get_cache_dir", return_value=tmp_path)


# ---------------------------------------------------------------------------
# Tests: get_cache_dir
# ---------------------------------------------------------------------------


class TestGetCacheDir:
    def test_returns_path(self):
        result = get_cache_dir()
        assert isinstance(result, Path)

    def test_contains_app_name(self):
        result = get_cache_dir()
        assert "conda-sigstore" in str(result)


# ---------------------------------------------------------------------------
# Tests: _url_to_cache_path
# ---------------------------------------------------------------------------


class TestUrlToCachePath:
    def test_returns_path_under_cache_dir(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            p = _url_to_cache_path(SAMPLE_URL)
        assert p.parent == tmp_path

    def test_different_urls_produce_different_paths(self, tmp_path):
        other_url = SAMPLE_URL + "?extra"
        with _patch_cache_dir(tmp_path):
            p1 = _url_to_cache_path(SAMPLE_URL)
            p2 = _url_to_cache_path(other_url)
        assert p1 != p2

    def test_same_url_produces_same_path(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            p1 = _url_to_cache_path(SAMPLE_URL)
            p2 = _url_to_cache_path(SAMPLE_URL)
        assert p1 == p2


# ---------------------------------------------------------------------------
# Tests: get_cached_bundles
# ---------------------------------------------------------------------------


class TestGetCachedBundles:
    def test_returns_none_on_miss(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            result = get_cached_bundles(SAMPLE_URL)
        assert result is None

    def test_returns_bundles_on_hit(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_path = _url_to_cache_path(SAMPLE_URL)
            cache_path.write_text(json.dumps(SAMPLE_BUNDLES), encoding="utf-8")
            result = get_cached_bundles(SAMPLE_URL)
        assert result == SAMPLE_BUNDLES

    def test_empty_list_is_cached(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_path = _url_to_cache_path(SAMPLE_URL)
            cache_path.write_text(json.dumps([]), encoding="utf-8")
            result = get_cached_bundles(SAMPLE_URL)
        assert result == []

    def test_corrupt_json_returns_none(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_path = _url_to_cache_path(SAMPLE_URL)
            cache_path.write_text("not-json", encoding="utf-8")
            result = get_cached_bundles(SAMPLE_URL)
        assert result is None

    def test_non_list_json_returns_none(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_path = _url_to_cache_path(SAMPLE_URL)
            cache_path.write_text(json.dumps({"key": "value"}), encoding="utf-8")
            result = get_cached_bundles(SAMPLE_URL)
        assert result is None


# ---------------------------------------------------------------------------
# Tests: cache_bundles
# ---------------------------------------------------------------------------


class TestCacheBundles:
    def test_writes_file(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_bundles(SAMPLE_URL, SAMPLE_BUNDLES)
            result = get_cached_bundles(SAMPLE_URL)
        assert result == SAMPLE_BUNDLES

    def test_creates_cache_dir(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        with patch("conda_sigstore.cache.get_cache_dir", return_value=nested):
            cache_bundles(SAMPLE_URL, SAMPLE_BUNDLES)
        assert nested.exists()

    def test_os_error_is_silently_ignored(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            with patch("conda_sigstore.cache.Path.write_text", side_effect=OSError("no space")):
                cache_bundles(SAMPLE_URL, SAMPLE_BUNDLES)  # must not raise


# ---------------------------------------------------------------------------
# Tests: fetch_and_cache_attestation_bundles
# ---------------------------------------------------------------------------


class TestFetchAndCacheAttestationBundles:
    # fetch_attestation_bundles is lazily imported inside the function body, so
    # patch the name in its source module (conda_sigstore.verifier) rather than
    # the non-existent conda_sigstore.cache attribute.
    _FETCH_TARGET = "conda_sigstore.verifier.fetch_attestation_bundles"

    def test_returns_cached_bundles_without_fetching(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            cache_bundles(
                f"{PACKAGE_URL}{ATTESTATION_FILE_SUFFIX}", SAMPLE_BUNDLES
            )
            with patch(self._FETCH_TARGET) as mock_fetch:
                result = fetch_and_cache_attestation_bundles(PACKAGE_URL)

        assert result == SAMPLE_BUNDLES
        mock_fetch.assert_not_called()

    def test_fetches_and_caches_on_miss(self, tmp_path):
        with _patch_cache_dir(tmp_path):
            with patch(self._FETCH_TARGET, return_value=SAMPLE_BUNDLES) as mock_fetch:
                result = fetch_and_cache_attestation_bundles(PACKAGE_URL)

            assert result == SAMPLE_BUNDLES
            mock_fetch.assert_called_once_with(PACKAGE_URL)
            # Verify the result was written to cache.
            cached = get_cached_bundles(f"{PACKAGE_URL}{ATTESTATION_FILE_SUFFIX}")
        assert cached == SAMPLE_BUNDLES

    def test_uses_sigs_url_as_cache_key(self, tmp_path):
        expected_key = f"{PACKAGE_URL}{ATTESTATION_FILE_SUFFIX}"
        with _patch_cache_dir(tmp_path):
            with patch(self._FETCH_TARGET, return_value=SAMPLE_BUNDLES):
                fetch_and_cache_attestation_bundles(PACKAGE_URL)
            result = get_cached_bundles(expected_key)
        assert result == SAMPLE_BUNDLES

    def test_propagates_fetch_error(self, tmp_path):
        from conda_sigstore.verifier import AttestationFetchError

        with _patch_cache_dir(tmp_path):
            with patch(self._FETCH_TARGET, side_effect=AttestationFetchError("HTTP 404")):
                with pytest.raises(AttestationFetchError, match="HTTP 404"):
                    fetch_and_cache_attestation_bundles(PACKAGE_URL)
