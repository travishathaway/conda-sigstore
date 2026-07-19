import pytest  # noqa: F401
from conda.testing.fixtures import (  # noqa: F401 — pytest fixture discovery
    conda_cli,
    path_factory,
    tmp_env,
)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: end-to-end tests requiring network access"
    )
    config.addinivalue_line(
        "markers",
        "bench: benchmarks measuring install time with and without conda-sigstore",
    )
