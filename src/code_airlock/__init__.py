"""code-airlock: local PII/secret redaction and rehydration for coding agents."""

from .engine import CascadeEngine
from .sanitizer import StreamRehydrator, VaultSession

__version__ = "1.1.0"
__all__ = ["CascadeEngine", "StreamRehydrator", "VaultSession", "__version__"]
