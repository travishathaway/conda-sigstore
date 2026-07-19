"""
Stub out conda and py_sigstore at import time so tests run without those
packages installed (the full suite requires the pixi dev environment).

When the packages are actually installed (e.g. inside `pixi run -e dev`),
the stubs are skipped so that real types are used and real exceptions can
be raised and caught correctly.
"""

import importlib.util
import sys
from unittest.mock import MagicMock

_CONDA_MODS = [
    "conda",
    "conda.base",
    "conda.base.context",
    "conda.common",
    "conda.common.configuration",
    "conda.core",
    "conda.core.package_cache_data",
    "conda.core.path_actions",
    "conda.exceptions",
    "conda.gateways",
    "conda.gateways.connection",
    "conda.gateways.connection.session",
    "conda.models",
    "conda.models.records",
    "conda.plugins",
    "conda.plugins.types",
]

_PY_SIGSTORE_MODS = [
    "py_sigstore",
]

_conda_available = importlib.util.find_spec("conda") is not None
_py_sigstore_available = importlib.util.find_spec("py_sigstore") is not None

if not _conda_available:
    for _mod in _CONDA_MODS:
        if _mod not in sys.modules:
            sys.modules[_mod] = MagicMock()

    # hookimpl must be an identity decorator — the real one just marks the
    # function with a special attribute and returns it unchanged.
    sys.modules["conda.plugins"].hookimpl = lambda f: f

    # CondaSetting and CondaPreTransactionAction must be real classes so that
    # isinstance() checks in tests work and .name/.action kwargs are preserved.
    class _CondaSetting:
        def __init__(self, name, description, parameter):
            self.name = name
            self.description = description
            self.parameter = parameter

    class _CondaPreTransactionAction:
        def __init__(self, name, action):
            self.name = name
            self.action = action

    sys.modules["conda.plugins.types"].CondaSetting = _CondaSetting
    sys.modules["conda.plugins.types"].CondaPreTransactionAction = _CondaPreTransactionAction

if not _py_sigstore_available:
    for _mod in _PY_SIGSTORE_MODS:
        if _mod not in sys.modules:
            sys.modules[_mod] = MagicMock()
