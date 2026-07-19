"""
Integration tests for conda-sigstore against the prefix.dev/github-releases channel.

These tests make real network requests and create real conda environments.
Run with::

    pytest tests/integration/ -v -m integration
"""

from __future__ import annotations

import pytest
from conda.base.context import reset_context
from conda.exceptions import CondaError

TRUSTED_CHANNEL = "https://prefix.dev/github-releases"
CONDA_FORGE_CHANNEL = "https://conda.anaconda.org/conda-forge"
TEST_PACKAGE = "asciinema"

pytestmark = pytest.mark.integration


class TestIntegrationInstall:
    def test_create_env_with_signed_package(self, conda_cli, tmp_path, monkeypatch):
        """Installing 7zip from github-releases with the plugin enabled succeeds."""
        monkeypatch.setenv("CONDA_PLUGINS_SIGSTORE_TRUSTED_CHANNELS", TRUSTED_CHANNEL)
        monkeypatch.setenv("CONDA_PLUGINS_SIGSTORE_ON_MISSING", "block")
        reset_context()

        prefix = tmp_path / "env1"
        stdout, stderr, code = conda_cli(
            "create",
            "--prefix",
            str(prefix),
            "--channel",
            TRUSTED_CHANNEL,
            "--override-channels",
            "--yes",
            "--quiet",
            TEST_PACKAGE,
        )
        assert code == 0
        assert prefix.exists()

    def test_create_env_with_tmp_env_fixture(self, tmp_env, monkeypatch):
        """Same install via the tmp_env context-manager fixture."""
        monkeypatch.setenv("CONDA_PLUGINS_SIGSTORE_TRUSTED_CHANNELS", TRUSTED_CHANNEL)
        monkeypatch.setenv("CONDA_PLUGINS_SIGSTORE_ON_MISSING", "block")
        reset_context()

        with tmp_env(
            "--channel",
            TRUSTED_CHANNEL,
            "--override-channels",
            TEST_PACKAGE,
        ) as prefix:
            assert prefix.exists()

    def test_install_blocks_when_attestation_missing(
        self, conda_cli, tmp_path, monkeypatch
    ):
        """Installing from a trusted channel without .v0.sigs endpoints is blocked."""
        # conda-forge has no Sigstore attestation files, so fetching them returns
        # a 404, which raises AttestationFetchError → CondaVerificationError.
        monkeypatch.setenv(
            "CONDA_PLUGINS_SIGSTORE_TRUSTED_CHANNELS", CONDA_FORGE_CHANNEL
        )
        monkeypatch.setenv("CONDA_PLUGINS_SIGSTORE_ON_MISSING", "block")
        reset_context()

        prefix = tmp_path / "blocked-env"
        stdout, stderr, exc_info = conda_cli(
            "create",
            "--prefix",
            str(prefix),
            "--channel",
            "conda-forge",
            "--override-channels",
            "--yes",
            "--quiet",
            "zstd",
            raises=CondaError,
        )
        error_text = str(exc_info.value).lower()
        assert "attestation" in error_text or "sigstore" in error_text
