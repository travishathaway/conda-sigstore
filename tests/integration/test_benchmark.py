"""
Benchmarks comparing conda install time with and without conda-sigstore verification.

Run with::

    pytest tests/integration/ -v -m bench
"""

from __future__ import annotations

import os

import pytest
from conda.base.context import reset_context

TRUSTED_CHANNEL = "https://prefix.dev/github-releases"
TEST_PACKAGE = "asciinema"

pytestmark = pytest.mark.bench

# Rounds are kept low because conda environment creation is slow (~5-20s each).
BENCHMARK_ROUNDS = 3
BENCHMARK_WARMUP_ROUNDS = 1


def _install(conda_cli, tmp_path_factory, *, sigstore_enabled: bool) -> None:
    prefix = tmp_path_factory.mktemp("env")
    extra_env = {
        "CONDA_PLUGINS_SIGSTORE_TRUSTED_CHANNELS": TRUSTED_CHANNEL
        if sigstore_enabled
        else "",
        "CONDA_PLUGINS_SIGSTORE_ON_MISSING": "warn",
    }
    orig = {k: os.environ.get(k) for k in extra_env}
    try:
        os.environ.update(extra_env)
        reset_context()
        conda_cli(
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
    finally:
        for k, v in orig.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        reset_context()


class TestBenchmarkInstall:
    def test_install_with_sigstore(self, benchmark, conda_cli, tmp_path_factory):
        """Measure conda install time with sigstore verification enabled."""
        benchmark.pedantic(
            _install,
            kwargs={
                "conda_cli": conda_cli,
                "tmp_path_factory": tmp_path_factory,
                "sigstore_enabled": True,
            },
            rounds=BENCHMARK_ROUNDS,
            warmup_rounds=BENCHMARK_WARMUP_ROUNDS,
        )

    def test_install_without_sigstore(self, benchmark, conda_cli, tmp_path_factory):
        """Measure conda install time with sigstore verification disabled."""
        benchmark.pedantic(
            _install,
            kwargs={
                "conda_cli": conda_cli,
                "tmp_path_factory": tmp_path_factory,
                "sigstore_enabled": False,
            },
            rounds=BENCHMARK_ROUNDS,
            warmup_rounds=BENCHMARK_WARMUP_ROUNDS,
        )
