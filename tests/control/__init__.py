"""The control extra is optional, so the zero-dependency suite skips these."""
import unittest

try:
    import cryptography  # noqa: F401
    import defusedxml  # noqa: F401
    import pypdf  # noqa: F401
except ImportError as exc:  # pragma: no cover - exercised by the dependency-free CI job
    raise unittest.SkipTest("control extra が未インストールです: pip install '.[control]'") from exc
