"""Constant-time comparison utilities preventing side-channel timing leaks."""

import secrets


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks.

    Args:
        val1: First string.
        val2: Second string.

    Returns:
        True if strings match exactly, False otherwise.
    """
    return secrets.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))


def constant_time_compare_bytes(val1: bytes, val2: bytes) -> bool:
    """Compare two byte sequences in constant time."""
    return secrets.compare_digest(val1, val2)
