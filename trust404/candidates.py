"""Stable candidate identities used to avoid redundant verification.

The scoring loop may receive equivalent Solidity from more than one provider.
Comments, formatting and pragma spelling are irrelevant to the execution, so
they must not consume another expensive Forge attempt.
"""
from __future__ import annotations

import hashlib
import re


def normalize_candidate(source: str) -> str:
    """Return a deterministic, formatting-insensitive Solidity form.

    This intentionally stays conservative: it removes comments, SPDX/pragma
    lines and whitespace, but does not rename identifiers or reorder calls.
    Distinct argument expressions therefore remain distinct candidates.
    """
    src = source or ""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"\bpragma\s+solidity\s+[^;]+;", "", src)
    src = re.sub(r"\s+", "", src)
    return src


def candidate_fingerprint(source: str) -> str:
    """Hash the executable candidate shape for cross-provider de-duplication."""
    return hashlib.sha256(normalize_candidate(source).encode("utf-8")).hexdigest()

