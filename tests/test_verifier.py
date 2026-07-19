"""
Tests for conda_sigstore.verifier and conda_sigstore.hooks.

Run with::

    pytest tests/test_verifier.py -v

All tests mock external dependencies (network, filesystem, py_sigstore,
and the conda context) so they run fully offline without conda being
initialised.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests.exceptions

from conda_sigstore.verifier import (
    CONDA_PREDICATE_TYPE,
    AttestationFetchError,
    SigstoreVerificationAction,
    fetch_attestation_bundles,
    verify_in_toto_statement,
    verify_package,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

SAMPLE_BUNDLE_OBJ: dict[str, Any] = {
    "dsseEnvelope": {
        "payload": "eyJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YxIn0=",
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"sig": "MEYCIQDexample"}],
    },
    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
    "verificationMaterial": {
        "certificate": {"rawBytes": "MIIBexample"},
        "tlogEntries": [],
    },
}

SAMPLE_BUNDLE_JSON = json.dumps(SAMPLE_BUNDLE_OBJ)

GITHUB_RELEASES_CHANNEL = "https://prefix.dev/github-releases"
GITHUB_RELEASES_URL = f"{GITHUB_RELEASES_CHANNEL}/linux-64/7zip-25.00-hb0f4dca_0.conda"
CONDA_FORGE_URL = (
    "https://conda.anaconda.org/conda-forge/linux-64/numpy-1.25.0-py311h.conda"
)


def _make_record(url: str, fn: str = "pkg-1.0-h0.conda") -> Mock:
    """Create a minimal mock PackageRecord."""
    rec = Mock()
    rec.url = url
    rec.fn = fn
    return rec


def _make_cache_record(tarball_path: str) -> Mock:
    """Create a minimal mock PackageCacheRecord."""
    crec = Mock()
    crec.package_tarball_full_path = tarball_path
    return crec


def _make_context_plugins(
    identity: str | None = None,
    issuer: str | None = "https://token.actions.githubusercontent.com",
    on_missing: str = "block",
    trusted_channels: list[str] | None = None,
) -> SimpleNamespace:
    """Return a mock ``context.plugins`` namespace."""
    return SimpleNamespace(
        sigstore_identity=identity,
        sigstore_issuer=issuer,
        sigstore_on_missing=on_missing,
        sigstore_trusted_channels=trusted_channels
        if trusted_channels is not None
        else [GITHUB_RELEASES_CHANNEL],
    )


# ---------------------------------------------------------------------------
# Tests: fetch_attestation_bundles
# ---------------------------------------------------------------------------


class TestFetchAttestationBundles:
    def _mock_session(self, body=None, json_data=None, status_code=200):
        """Return a mock CondaSession whose .get() returns a mock response."""
        response = Mock()
        response.status_code = status_code
        response.raise_for_status = Mock()  # no-op by default (2xx)
        if json_data is not None:
            response.json = Mock(return_value=json_data)
        elif body is not None:
            response.json = Mock(return_value=json.loads(body))
        else:
            response.json = Mock(return_value=[])
        session = Mock()
        session.get = Mock(return_value=response)
        return session, response

    def test_returns_list_of_json_strings(self):
        session, _ = self._mock_session(json_data=[SAMPLE_BUNDLE_OBJ])
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            result = fetch_attestation_bundles(GITHUB_RELEASES_URL)

        assert isinstance(result, list)
        assert len(result) == 1
        parsed = json.loads(result[0])
        assert parsed["mediaType"] == SAMPLE_BUNDLE_OBJ["mediaType"]

    def test_empty_array_returns_empty_list(self):
        session, _ = self._mock_session(json_data=[])
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            result = fetch_attestation_bundles(GITHUB_RELEASES_URL)

        assert result == []

    def test_multiple_bundles(self):
        session, _ = self._mock_session(
            json_data=[SAMPLE_BUNDLE_OBJ, SAMPLE_BUNDLE_OBJ]
        )
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            result = fetch_attestation_bundles(GITHUB_RELEASES_URL)

        assert len(result) == 2

    def test_404_raises_attestation_fetch_error(self):
        http_err = requests.exceptions.HTTPError(response=Mock(status_code=404))
        session = Mock()
        session.get.return_value = Mock(
            raise_for_status=Mock(side_effect=http_err),
            status_code=404,
        )
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            with pytest.raises(AttestationFetchError, match="HTTP 404"):
                fetch_attestation_bundles(GITHUB_RELEASES_URL)

    def test_network_error_raises_attestation_fetch_error(self):
        net_err = requests.exceptions.ConnectionError("Name or service not known")
        session = Mock()
        session.get.side_effect = net_err
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            with pytest.raises(AttestationFetchError, match="Network error"):
                fetch_attestation_bundles(GITHUB_RELEASES_URL)

    def test_invalid_json_raises_attestation_fetch_error(self):
        session = Mock()
        response = Mock()
        response.raise_for_status = Mock()
        response.json = Mock(side_effect=ValueError("No JSON object could be decoded"))
        session.get.return_value = response
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            with pytest.raises(AttestationFetchError, match="Invalid JSON"):
                fetch_attestation_bundles(GITHUB_RELEASES_URL)

    def test_non_array_json_raises_attestation_fetch_error(self):
        session, _ = self._mock_session(json_data={"key": "value"})
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            with pytest.raises(AttestationFetchError, match="Expected a JSON array"):
                fetch_attestation_bundles(GITHUB_RELEASES_URL)

    def test_sigs_url_has_correct_suffix(self):
        """Ensure the URL passed to session.get() ends with .v0.sigs."""
        session, _ = self._mock_session(json_data=[])
        with patch("conda_sigstore.verifier.get_session", return_value=session):
            fetch_attestation_bundles(GITHUB_RELEASES_URL)

        called_url = session.get.call_args[0][0]
        assert called_url == GITHUB_RELEASES_URL + ".v0.sigs"


# ---------------------------------------------------------------------------
# Tests: verify_package
# ---------------------------------------------------------------------------


def _good_in_toto_payload(
    filename: str = "pkg-1.0-h0.conda",
    channel: str = GITHUB_RELEASES_CHANNEL,
    artifact_bytes: bytes = b"bytes",
) -> bytes:
    """Build a minimal valid in-toto statement payload for the given args."""
    import hashlib

    sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    stmt = {
        "predicateType": CONDA_PREDICATE_TYPE,
        "subject": [{"name": filename, "digest": {"sha256": sha256}}],
        "predicate": {"targetChannel": channel},
    }
    return json.dumps(stmt).encode()


class TestVerifyInTotoStatement:
    def _make_payload(self, **kwargs) -> bytes:
        return _good_in_toto_payload(**kwargs)

    def test_passes_for_valid_statement(self):
        payload = self._make_payload()
        verify_in_toto_statement(
            payload,
            expected_filename="pkg-1.0-h0.conda",
            expected_channel=GITHUB_RELEASES_CHANNEL,
            artifact_bytes=b"bytes",
        )

    def test_fails_wrong_predicate_type(self):
        from py_sigstore import VerificationError

        stmt = json.loads(self._make_payload())
        stmt["predicateType"] = "https://example.com/wrong"
        with pytest.raises(VerificationError, match="predicateType"):
            verify_in_toto_statement(
                json.dumps(stmt).encode(),
                "pkg-1.0-h0.conda",
                GITHUB_RELEASES_CHANNEL,
                b"bytes",
            )

    def test_fails_wrong_subject_count(self):
        from py_sigstore import VerificationError

        stmt = json.loads(self._make_payload())
        stmt["subject"] = []
        with pytest.raises(VerificationError, match="exactly 1 subject"):
            verify_in_toto_statement(
                json.dumps(stmt).encode(),
                "pkg-1.0-h0.conda",
                GITHUB_RELEASES_CHANNEL,
                b"bytes",
            )

    def test_fails_wrong_subject_name(self):
        from py_sigstore import VerificationError

        payload = self._make_payload(filename="different-1.0-h0.conda")
        with pytest.raises(VerificationError, match="subject name"):
            verify_in_toto_statement(
                payload,
                "pkg-1.0-h0.conda",
                GITHUB_RELEASES_CHANNEL,
                b"bytes",
            )

    def test_fails_sha256_mismatch(self):
        from py_sigstore import VerificationError

        payload = self._make_payload(artifact_bytes=b"other bytes")
        with pytest.raises(VerificationError, match="SHA-256"):
            verify_in_toto_statement(
                payload,
                "pkg-1.0-h0.conda",
                GITHUB_RELEASES_CHANNEL,
                b"bytes",  # different from what payload was built with
            )

    def test_fails_wrong_target_channel(self):
        from py_sigstore import VerificationError

        payload = self._make_payload(channel="https://prefix.dev/other-channel")
        with pytest.raises(VerificationError, match="targetChannel"):
            verify_in_toto_statement(
                payload,
                "pkg-1.0-h0.conda",
                GITHUB_RELEASES_CHANNEL,
                b"bytes",
            )

    def test_channel_trailing_slash_ignored(self):
        payload = self._make_payload(channel=GITHUB_RELEASES_CHANNEL + "/")
        verify_in_toto_statement(
            payload,
            "pkg-1.0-h0.conda",
            GITHUB_RELEASES_CHANNEL,
            b"bytes",
        )


class TestVerifyPackage:
    def _make_verify_package_args(
        self,
        filename: str = "pkg-1.0-h0.conda",
        channel: str = GITHUB_RELEASES_CHANNEL,
    ):
        return dict(
            expected_filename=filename,
            expected_channel=channel,
        )

    def test_succeeds_when_first_bundle_passes(self):
        verifier = Mock()
        payload = _good_in_toto_payload()
        verifier.verify_dsse.return_value = ("application/vnd.in-toto+json", payload)
        bundle_mock = Mock()
        policy = Mock()

        with patch("conda_sigstore.verifier.Bundle") as BundleCls:
            BundleCls.from_json.return_value = bundle_mock
            verify_package(
                verifier,
                b"bytes",
                [SAMPLE_BUNDLE_JSON],
                policy,
                **self._make_verify_package_args(),
            )

        verifier.verify_dsse.assert_called_once_with(b"bytes", bundle_mock, policy)

    def test_tries_second_bundle_if_first_fails(self):
        from py_sigstore import VerificationError

        payload = _good_in_toto_payload()
        verifier = Mock()
        verifier.verify_dsse.side_effect = [
            VerificationError("bad sig"),
            ("application/vnd.in-toto+json", payload),
        ]

        with patch("conda_sigstore.verifier.Bundle") as BundleCls:
            BundleCls.from_json.return_value = Mock()
            verify_package(
                verifier,
                b"bytes",
                [SAMPLE_BUNDLE_JSON, SAMPLE_BUNDLE_JSON],
                policy=Mock(),
                **self._make_verify_package_args(),
            )

        assert verifier.verify_dsse.call_count == 2

    def test_raises_verification_error_when_all_fail(self):
        from py_sigstore import VerificationError

        verifier = Mock()
        verifier.verify_dsse.side_effect = VerificationError("failed")

        with patch("conda_sigstore.verifier.Bundle") as BundleCls:
            BundleCls.from_json.return_value = Mock()
            with pytest.raises(VerificationError):
                verify_package(
                    verifier,
                    b"bytes",
                    [SAMPLE_BUNDLE_JSON],
                    policy=Mock(),
                    **self._make_verify_package_args(),
                )

    def test_raises_value_error_for_empty_bundle_list(self):
        verifier = Mock()
        with pytest.raises(ValueError, match="must not be empty"):
            verify_package(
                verifier,
                b"bytes",
                [],
                policy=Mock(),
                **self._make_verify_package_args(),
            )


# ---------------------------------------------------------------------------
# Tests: SigstoreVerificationAction
# ---------------------------------------------------------------------------


class TestSigstoreVerificationAction:
    """Tests for the main conda action class."""

    def _make_action(
        self,
        link_precs=None,
        identity: str | None = None,
        issuer: str | None = "https://token.actions.githubusercontent.com",
        on_missing: str = "block",
        trusted_channels: list[str] | None = None,
    ) -> SigstoreVerificationAction:
        action = SigstoreVerificationAction(
            transaction_context={},
            target_prefix="/some/prefix",
            unlink_precs=[],
            link_precs=link_precs or [],
        )
        plugins_ns = _make_context_plugins(
            identity, issuer, on_missing, trusted_channels
        )
        self._plugins_ns = plugins_ns
        return action

    def _patch_context(self):
        """Context manager that patches ``conda.base.context.context.plugins``."""
        mock_ctx = MagicMock()
        mock_ctx.plugins = self._plugins_ns
        mock_ctx.fetch_threads = 5
        return patch("conda_sigstore.verifier.context", mock_ctx)

    # --- Packages from other channels are skipped ---------------------------

    def test_skips_packages_not_in_trusted_channels(self):
        rec = _make_record(CONDA_FORGE_URL, fn="numpy-1.25.0-py311h.conda")
        action = self._make_action(link_precs=[rec])

        with self._patch_context():
            with patch("conda_sigstore.verifier.Verifier") as MockVerifier:
                result = action.verify()

        assert result is None
        assert action._verified is True
        MockVerifier.github.return_value.verify_dsse.assert_not_called()

    def test_skips_when_trusted_channels_empty(self):
        rec = _make_record(GITHUB_RELEASES_URL)
        action = self._make_action(link_precs=[rec], trusted_channels=[])

        with self._patch_context():
            with patch("conda_sigstore.verifier.Verifier") as MockVerifier:
                result = action.verify()

        assert result is None
        assert action._verified is True
        MockVerifier.github.return_value.verify_dsse.assert_not_called()

    def test_skips_when_no_link_precs(self):
        action = self._make_action(link_precs=[])
        with self._patch_context():
            result = action.verify()
        assert result is None
        assert action._verified is True

    # --- Successful verification -------------------------------------------

    def test_returns_none_on_successful_verification(self):
        rec = _make_record(GITHUB_RELEASES_URL, fn="7zip-25.00-hb0f4dca_0.conda")
        action = self._make_action(link_precs=[rec])

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles"
            ) as mock_fetch:
                mock_fetch.return_value = [SAMPLE_BUNDLE_JSON]
                with patch("conda_sigstore.verifier._get_cache_record") as mock_cache:
                    mock_cache.return_value = _make_cache_record(
                        "/pkg/cache/7zip.conda"
                    )
                    with patch(
                        "builtins.open",
                        MagicMock(
                            return_value=MagicMock(
                                __enter__=lambda s: MagicMock(read=lambda: b"bytes"),
                                __exit__=MagicMock(return_value=False),
                            )
                        ),
                    ):
                        with patch(
                            "conda_sigstore.verifier.verify_package"
                        ) as mock_verify:
                            mock_verify.return_value = None
                            result = action.verify()

        assert result is None
        assert action._verified is True
        mock_verify.assert_called_once()

    # --- Missing attestation (block mode) ----------------------------------

    def test_blocks_when_attestation_fetch_fails_strict(self):
        rec = _make_record(GITHUB_RELEASES_URL)
        action = self._make_action(link_precs=[rec], on_missing="block")

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                side_effect=AttestationFetchError("HTTP 404"),
            ):
                result = action.verify()

        from conda.exceptions import CondaVerificationError

        assert isinstance(result, CondaVerificationError)
        assert action._verified is False

    def test_blocks_when_bundle_list_empty_strict(self):
        rec = _make_record(GITHUB_RELEASES_URL)
        action = self._make_action(link_precs=[rec], on_missing="block")

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                return_value=[],
            ):
                result = action.verify()

        from conda.exceptions import CondaVerificationError

        assert isinstance(result, CondaVerificationError)

    # --- Missing attestation (warn mode) -----------------------------------

    def test_continues_when_attestation_fetch_fails_lenient(self):
        rec = _make_record(GITHUB_RELEASES_URL)
        action = self._make_action(link_precs=[rec], on_missing="warn")

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                side_effect=AttestationFetchError("HTTP 404"),
            ):
                result = action.verify()

        assert result is None
        assert action._verified is True

    def test_continues_when_bundle_list_empty_lenient(self):
        rec = _make_record(GITHUB_RELEASES_URL)
        action = self._make_action(link_precs=[rec], on_missing="warn")

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                return_value=[],
            ):
                result = action.verify()

        assert result is None
        assert action._verified is True

    # --- Verification failure ----------------------------------------------

    def test_returns_error_on_verification_failure(self):
        from py_sigstore import VerificationError

        rec = _make_record(GITHUB_RELEASES_URL, fn="7zip-25.00-hb0f4dca_0.conda")
        action = self._make_action(link_precs=[rec])

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                return_value=[SAMPLE_BUNDLE_JSON],
            ):
                with patch(
                    "conda_sigstore.verifier._get_cache_record",
                    return_value=_make_cache_record("/pkg/cache/7zip.conda"),
                ):
                    with patch(
                        "builtins.open",
                        MagicMock(
                            return_value=MagicMock(
                                __enter__=lambda s: MagicMock(read=lambda: b"bytes"),
                                __exit__=MagicMock(return_value=False),
                            )
                        ),
                    ):
                        with patch(
                            "conda_sigstore.verifier.verify_package",
                            side_effect=VerificationError("signature mismatch"),
                        ):
                            result = action.verify()

        from conda.exceptions import CondaVerificationError

        assert isinstance(result, CondaVerificationError)
        assert "signature mismatch" in str(result)
        assert action._verified is False

    # --- Parallel fetch -------------------------------------------------------

    def test_all_packages_fetched_in_parallel(self):
        """All packages from trusted channels have their attestations fetched."""
        recs = [
            _make_record(GITHUB_RELEASES_URL, fn=f"pkg-{i}-1.0-h0.conda")
            for i in range(3)
        ]
        action = self._make_action(link_precs=recs)

        with self._patch_context():
            with patch(
                "conda_sigstore.verifier.fetch_and_cache_attestation_bundles",
                return_value=[SAMPLE_BUNDLE_JSON],
            ) as mock_fetch:
                with patch(
                    "conda_sigstore.verifier._get_cache_record",
                    return_value=_make_cache_record("/pkg/cache/pkg.conda"),
                ):
                    with patch(
                        "builtins.open",
                        MagicMock(
                            return_value=MagicMock(
                                __enter__=lambda s: MagicMock(read=lambda: b"bytes"),
                                __exit__=MagicMock(return_value=False),
                            )
                        ),
                    ):
                        with patch(
                            "conda_sigstore.verifier.verify_package",
                            return_value=None,
                        ):
                            result = action.verify()

        assert result is None
        assert action._verified is True
        # All three packages must have had their attestations fetched.
        assert mock_fetch.call_count == 3

    # --- No-op methods -----------------------------------------------------

    def test_execute_is_noop(self):
        action = self._make_action()
        action.execute()  # should not raise

    def test_reverse_is_noop(self):
        action = self._make_action()
        action.reverse()  # should not raise

    def test_cleanup_is_noop(self):
        action = self._make_action()
        action.cleanup()  # should not raise


# ---------------------------------------------------------------------------
# Tests: hooks registration
# ---------------------------------------------------------------------------


class TestHooksRegistration:
    def test_conda_settings_yields_four_settings(self):
        from conda_sigstore.hooks import conda_settings

        results = list(conda_settings())
        assert len(results) == 4
        names = {s.name for s in results}
        assert names == {
            "sigstore_identity",
            "sigstore_issuer",
            "sigstore_on_missing",
            "sigstore_trusted_channels",
        }

    def test_conda_pre_transaction_actions_yields_action(self):
        from conda_sigstore.hooks import conda_pre_transaction_actions
        from conda.plugins.types import CondaPreTransactionAction

        results = list(conda_pre_transaction_actions())
        assert len(results) == 1
        action_reg = results[0]
        assert isinstance(action_reg, CondaPreTransactionAction)
        assert action_reg.name == "sigstore-verify"
        assert action_reg.action is SigstoreVerificationAction
