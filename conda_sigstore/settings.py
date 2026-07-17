"""
Plugin settings for conda-sigstore.

These are exposed as .condarc options under the ``plugins`` key, e.g.::

    plugins:
      sigstore_identity: "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
      sigstore_issuer: "https://token.actions.githubusercontent.com"
      sigstore_on_missing: "block"

They can also be set via environment variables with the ``CONDA_PLUGINS_`` prefix, e.g.::

    CONDA_PLUGINS_SIGSTORE_ON_MISSING=warn conda install ...
"""

from __future__ import annotations

from conda.common.configuration import PrimitiveParameter
from conda.plugins import hookimpl
from conda.plugins.types import CondaSetting

#: Default OIDC issuer for GitHub Actions-signed packages.
DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"

#: Allowed values for the ``sigstore_on_missing`` setting.
VALID_ON_MISSING = ("block", "warn")


def _validate_on_missing(value: str) -> str | None:
    if value not in VALID_ON_MISSING:
        return f"sigstore_on_missing must be one of {VALID_ON_MISSING!r}, got {value!r}"
    return None


SIGSTORE_SETTINGS = [
    CondaSetting(
        name="sigstore_identity",
        description=(
            "Expected signer identity for Sigstore-verified packages. "
            "For GitHub Actions this is a workflow URI, e.g. "
            "'https://github.com/org/repo/.github/workflows/release.yml"
            "@refs/heads/main'. "
            "Leave unset (None) to accept any identity that matches the issuer."
        ),
        parameter=PrimitiveParameter(None, element_type=(str, type(None))),
    ),
    CondaSetting(
        name="sigstore_issuer",
        description=(
            "Expected OIDC issuer URL for Sigstore-verified packages. "
            f"Defaults to '{DEFAULT_ISSUER}'. "
            "Set to None to accept any issuer (not recommended)."
        ),
        parameter=PrimitiveParameter(DEFAULT_ISSUER, element_type=(str, type(None))),
    ),
    CondaSetting(
        name="sigstore_on_missing",
        description=(
            "What to do when a package from the github-releases channel has no "
            "Sigstore attestation. "
            "'block' (default): abort the installation. "
            "'warn': log a warning and continue."
        ),
        parameter=PrimitiveParameter(
            "block",
            element_type=str,
            validation=_validate_on_missing,
        ),
    ),
]


@hookimpl
def conda_settings():
    """Register conda-sigstore plugin settings."""
    yield from SIGSTORE_SETTINGS
