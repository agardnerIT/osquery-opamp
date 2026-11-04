"""Access to the OpAMP protobuf definitions.

The stubs are the ones the reference server ships (``agardnerIT/opamp-server-py``),
generated from ``opamp-spec`` v0.20.0, and they are vendored so this package has no
codegen step. They import each other as ``from proto import anyvalue_pb2``, so
``vendor/`` has to be importable as a path root; that is done once here rather
than sprinkling ``sys.path`` changes through the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

# pb.py -> opamp/ -> osquery_opamp/ -> src/ -> repo root
_VENDOR = Path(__file__).resolve().parents[3] / "vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

from proto import anyvalue_pb2 as anyvalue  # noqa: E402
from proto import opamp_pb2 as opamp  # noqa: E402

__all__ = ["opamp", "anyvalue"]
