"""Short, stable identifiers derived from content (not for security)."""

from __future__ import annotations

import hashlib


def short_id(text: str, length: int = 8) -> str:
    """Return a stable short hex id for ``text``.

    Uses MD5 purely to derive a compact, deterministic identifier/cache key —
    never for passwords or integrity — hence ``usedforsecurity=False``.
    """
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()[:length]
