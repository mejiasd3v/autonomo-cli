"""Masking of personal identifiers in output and error messages."""

from __future__ import annotations

import re
from typing import Any

# NIF / NIE / CIF.
ID_RE = re.compile(r"\b([0-9XYZ]\d{7}[A-Z]|[A-HJ-NP-SUVW]\d{7}[0-9A-J])\b")
# NUSS / NAF: 12 digits, sometimes written as 28/12345678/90.
NUSS_RE = re.compile(r"\b(\d{2})[ /]?(\d{8})[ /]?(\d{2})\b")


def mask_ids(text: str) -> str:
    """Mask NIF/NIE/CIF so logs and agent transcripts do not carry them."""
    return ID_RE.sub(lambda m: "*" * 6 + m.group(1)[-3:], text)


def mask_text(text: str) -> str:
    """Mask NIF/NIE/CIF and NUSS."""
    return NUSS_RE.sub(lambda m: "*" * 10 + m.group(3), mask_ids(text))


def mask_tree(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: mask_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_tree(v) for v in value]
    return mask_text(value) if isinstance(value, str) else value
