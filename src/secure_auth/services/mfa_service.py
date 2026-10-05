"""Multi-factor authentication lifecycle and step-up challenge service."""

from sqlmodel import Session

from secure_auth.config.settings import settings
from secure_auth.core.exceptions import InvalidMFACodeError
from secure_auth.core.mfa import (
    generate_backup_recovery_codes,
    generate_provisioning_uri,
    generate_totp_secret,
    verify_totp_code,
)
from secure_auth.core.tokens import hash_token
from secure_auth.models.user import User
from secure_auth.services.audit_service import AuditService
from secure_auth.storage.repository import RecoveryCodeRepository, UserRepository


class MFAService:
    """Orchestrates 2FA TOTP secret provisioning, verification, and recovery codes."""

    def __init__(self, db_session: Session) -> None:
        self.db_session = db_session
        self.user_repo = UserRepository(db_session)
        self.code_repo = RecoveryCodeRepository(db_session)
        self.audit_service = AuditService(db_session)

    def setup_mfa(self, user: User) -> tuple[str, str, list[str]]:
        """Initiate TOTP setup, provision secret, and create backup recovery codes.

        Args:
            user: User entity configuring MFA.

        Returns:
            Tuple of (base32_secret, provisioning_uri, plaintext_backup_codes).
        """
        assert user.id is not None
        secret = generate_totp_secret()
        uri = generate_provisioning_uri(
            username=user.email,
            secret=secret,
            issuer_name=settings.TOTP_ISSUER_NAME,
        )

        # Generate emergency single-use backup recovery codes
        raw_codes, code_hashes = generate_backup_recovery_codes(
            settings.BACKUP_RECOVERY_CODES_COUNT
        )
        self.code_repo.store_codes(user.id, code_hashes)

        # Stage secret on user without activating mfa_enabled until verified
        user.mfa_secret = secret
        self.user_repo.update(user)

        self.audit_service.log(
            event_type="MFA_SETUP_INITIATED",
            user_id=user.id,
            username=user.username,
            status="SUCCESS",
        )

        return secret, uri, raw_codes

    def confirm_mfa(self, user: User, code: str) -> bool:
        """Confirm newly staged TOTP secret with a valid authenticator code.

        Args:
            user: User entity finalizing setup.
            code: 6-digit numeric TOTP code.

        Returns:
            True if activation succeeded.

        Raises:
            InvalidMFACodeError: If code fails verification or secret is missing.
        """
        assert user.id is not None
        if not user.mfa_secret:
            raise InvalidMFACodeError("MFA setup has not been initiated for this account.")

        if not verify_totp_code(user.mfa_secret, code.strip(), window=settings.TOTP_WINDOW):
            self.audit_service.log(
                event_type="MFA_CHALLENGE_FAILURE",
                user_id=user.id,
                username=user.username,
                status="FAILURE",
                details={"step": "setup_confirmation"},
            )
            raise InvalidMFACodeError("Invalid authentication code. Verification failed.")

        user.mfa_enabled = True
        self.user_repo.update(user)

        self.audit_service.log(
            event_type="MFA_ENABLED",
            user_id=user.id,
            username=user.username,
            status="SUCCESS",
        )
        return True

    def verify_mfa_code(self, user: User, code: str) -> bool:
        """Validate an MFA challenge using either a live TOTP code or a single-use backup code.

        Args:
            user: User entity undergoing verification.
            code: 6-digit TOTP code or alphanumeric backup recovery code.

        Returns:
            True if verification passed.

        Raises:
            InvalidMFACodeError: If code is invalid or already consumed.
        """
        assert user.id is not None
        normalized_code = code.strip()

        # 1. Try TOTP authenticator validation
        if user.mfa_secret and verify_totp_code(
            user.mfa_secret, normalized_code, window=settings.TOTP_WINDOW
        ):
            self.audit_service.log(
                event_type="MFA_CHALLENGE_SUCCESS",
                user_id=user.id,
                username=user.username,
                status="SUCCESS",
                details={"method": "totp"},
            )
            return True

        # 2. Try single-use backup recovery code
        normalized_recovery = normalized_code.replace("-", "").replace(" ", "").upper()
        code_digest = hash_token(normalized_recovery)
        if self.code_repo.verify_and_consume(user.id, code_digest):
            remaining = self.code_repo.get_remaining_count(user.id)
            self.audit_service.log(
                event_type="MFA_BACKUP_CODE_USED",
                user_id=user.id,
                username=user.username,
                status="WARNING",
                details={"remaining_codes": remaining},
            )
            return True

        self.audit_service.log(
            event_type="MFA_CHALLENGE_FAILURE",
            user_id=user.id,
            username=user.username,
            status="FAILURE",
            details={"method": "unknown_or_invalid"},
        )
        raise InvalidMFACodeError("Invalid or already consumed multi-factor verification code.")

    def disable_mfa(self, user: User, code: str) -> bool:
        """Safely disable MFA after validating credentials/code.

        Args:
            user: User entity requesting disabling.
            code: Valid TOTP code or backup recovery code.

        Returns:
            True if disabled.
        """
        assert user.id is not None
        # Must verify code before disabling
        self.verify_mfa_code(user, code)

        user.mfa_enabled = False
        user.mfa_secret = None
        self.user_repo.update(user)

        self.audit_service.log(
            event_type="MFA_DISABLED",
            user_id=user.id,
            username=user.username,
            status="WARNING",
        )
        return True
