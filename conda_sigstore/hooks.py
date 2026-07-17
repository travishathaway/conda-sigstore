"""
conda-sigstore plugin hook registrations.

This module is the entry point declared in ``pyproject.toml``::

    [project.entry-points.conda]
    conda-sigstore = "conda_sigstore.hooks"

It registers two hooks:

``conda_settings``
    Exposes three ``.condarc`` / environment-variable settings:
    ``sigstore_identity``, ``sigstore_issuer``, and ``sigstore_on_missing``.
    See :mod:`conda_sigstore.settings` for details.

``conda_pre_transaction_actions``
    Injects :class:`~conda_sigstore.verifier.SigstoreVerificationAction`
    into every install/update transaction.  The action verifies Sigstore
    attestations for packages from the ``github-releases`` channel on
    prefix.dev before any files are linked into the target prefix.
"""

from conda.plugins import hookimpl
from conda.plugins.types import CondaPreTransactionAction

from conda_sigstore.settings import SIGSTORE_SETTINGS
from conda_sigstore.verifier import SigstoreVerificationAction


@hookimpl
def conda_settings():
    """Register conda-sigstore plugin settings."""
    yield from SIGSTORE_SETTINGS


@hookimpl
def conda_pre_transaction_actions():
    """Register the Sigstore verification pre-transaction action."""
    yield CondaPreTransactionAction(
        name="sigstore-verify",
        action=SigstoreVerificationAction,
    )
