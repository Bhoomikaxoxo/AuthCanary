"""
AuthCanary — Shared output utilities.

Lightweight helpers used by both report.py and server.py.
"""

from __future__ import annotations


class DotDict:
    """Lightweight dict-to-namespace wrapper for Jinja2 dot access.

    Recursively converts nested dicts and lists so that
    ``obj.key`` works in templates instead of ``obj['key']``.
    """

    def __init__(self, d: dict) -> None:
        for k, v in d.items():
            if isinstance(v, dict):
                setattr(self, k, DotDict(v))
            elif isinstance(v, list):
                setattr(self, k, [
                    DotDict(item) if isinstance(item, dict) else item
                    for item in v
                ])
            else:
                setattr(self, k, v)
