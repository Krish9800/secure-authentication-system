"""Argon2id cryptographic password hashing with side-channel timing defense."""

import logging

from argon2 import PasswordHasher, Type, exceptions

from secure_auth.config.settings import settings

logger = logging.getLogger("secure_auth.crypto")


class Argon2PasswordHasher:
    """Argon2id (RFC 9106) password hashing and verification engine.

    Implements timing-attack defense via pre-computed synthetic dummy hashes
    to ensure authentication response times are identical whether a user exists or not.
    """

    def __init__(
        self,
        time_cost: int | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
        hash_len: int | None = None,
        salt_len: int | None = None,
    ) -> None:
        self.time_cost = time_cost or settings.ARGON2_TIME_COST
        self.memory_cost = memory_cost or settings.ARGON2_MEMORY_COST
        self.parallelism = parallelism or settings.ARGON2_PARALLELISM
        self.hash_len = hash_len or settings.ARGON2_HASH_LEN
        self.salt_len = salt_len or settings.ARGON2_SALT_LEN

        self._hasher = PasswordHasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=self.salt_len,
            type=Type.ID,
        )

        # Pre-compute a synthetic dummy hash for timing-invariance verification
        # Used when an unknown username is supplied to neutralize timing enumeration
        self._dummy_hash = self._hasher.hash("Synthetic_Dummy_Timing_Anchor_987#")

    def hash_password(self, password: str) -> str:
        """Hash a plaintext password using Argon2id with unique CSPRNG salt.

        Args:
            password: Raw plaintext password.

        Returns:
            Encoded Argon2id hash string ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
        """
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        """Verify password against Argon2id hash with side-channel mitigation.

        Args:
            password_hash: Encoded Argon2id hash string.
            password: Plaintext password attempt.

        Returns:
            True if verification succeeds, False otherwise.
        """
        try:
            return self._hasher.verify(password_hash, password)
        except (exceptions.VerifyMismatchError, exceptions.VerificationError):
            return False
        except exceptions.InvalidHashError:
            logger.warning("Attempted verification against invalid hash format")
            return False

    def verify_dummy(self, password: str | None = None) -> bool:
        """Execute a full synthetic Argon2id verification cycle for missing users.

        Guarantees that an authentication attempt for a non-existent account
        incurs the exact same memory and CPU work factor as a valid account.

        Args:
            password: User-provided password attempt or default baseline.

        Returns:
            Always returns False.
        """
        candidate = password or "synthetic_timing_baseline"
        try:
            self._hasher.verify(self._dummy_hash, candidate)
        except exceptions.VerificationError:
            pass  # Expected dummy verification failure
        except exceptions.InvalidHashError:
            logger.error("Dummy anchor hash is corrupted")
        return False

    def check_needs_rehash(self, password_hash: str) -> bool:
        """Check if hash parameters require updating due to policy changes."""
        return self._hasher.check_needs_rehash(password_hash)


# Global singleton instance with production defaults
password_hasher = Argon2PasswordHasher()
