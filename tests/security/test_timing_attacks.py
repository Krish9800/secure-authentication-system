"""Security test suite: Timing side-channel statistical verification."""

import statistics
import time
from collections.abc import Generator

import pytest
from sqlmodel import Session, create_engine

from secure_auth.core.exceptions import AccountLockedError, InvalidCredentialsError
from secure_auth.core.hasher import Argon2PasswordHasher
from secure_auth.services.auth_service import AuthService
from secure_auth.storage.database import init_db
from secure_auth.storage.repository import UserRepository


@pytest.fixture
def timing_db() -> Generator[Session, None, None]:
    """Isolated database session for timing benchmarks."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    init_db(engine)
    with Session(engine) as session:
        yield session


def test_timing_side_channel_mitigation(timing_db: Session) -> None:
    """Verify that authentication duration for non-existent users is comparable

    to existing users with incorrect passwords (mitigating timing attacks).

    Attack Vector:
        An attacker measures round-trip latency to determine whether a username exists.
        Naive implementations return immediately (e.g., 0.1ms) when a user does not exist,
        while spending ~50ms hashing for existing users, creating a huge observable delta.

    Defense Verification:
        AuthService calls `hasher.verify_dummy()` when a user is not found, ensuring both
        code paths execute an identical Argon2id verification cycle.
    """
    # Use realistic cost parameters for distinguishable timing measurement
    hasher = Argon2PasswordHasher(time_cost=2, memory_cost=8192, parallelism=1)
    auth = AuthService(timing_db, hasher=hasher)

    # Provision reference existing user
    auth.register("target_account", "target@example.com", "CorrectPassword123!")

    # Warm up JIT/cache
    for _ in range(3):
        try:
            auth.authenticate("target_account", "WrongPass123!")
        except InvalidCredentialsError:
            pass
        try:
            auth.authenticate("missing_account", "WrongPass123!")
        except InvalidCredentialsError:
            pass

    # Collect timing samples (15 iterations each)
    iterations = 15
    existing_user_times: list[float] = []
    missing_user_times: list[float] = []

    user_repo = UserRepository(timing_db)
    target_user = user_repo.get_by_username("target_account")
    assert target_user is not None

    for _ in range(iterations):
        # Reset lockout counter so verify_password always executes
        auth.lockout_service.unlock_user(target_user)

        # 1. Measure invalid password for existing account
        t0 = time.perf_counter()
        try:
            auth.authenticate("target_account", "WrongPass123!")
        except (InvalidCredentialsError, AccountLockedError):
            pass
        t1 = time.perf_counter()
        existing_user_times.append(t1 - t0)

        # 2. Measure non-existent account
        t2 = time.perf_counter()
        try:
            auth.authenticate("nonexistent_ghost_user", "WrongPass123!")
        except (InvalidCredentialsError, AccountLockedError):
            pass
        t3 = time.perf_counter()
        missing_user_times.append(t3 - t2)

    mean_existing = statistics.mean(existing_user_times)
    mean_missing = statistics.mean(missing_user_times)

    # Ratio of execution times: with dummy hashing, ratio must be close to 1.0 (e.g., 0.5 to 2.0)
    # Without dummy hashing, ratio would be 100x to 500x difference!
    ratio = mean_missing / mean_existing

    # Assert both paths spent substantial CPU time on Argon2id (e.g. > 1ms each)
    assert mean_existing > 0.001, f"Existing user path too fast: {mean_existing}s"
    assert mean_missing > 0.001, f"Missing user path too fast: {mean_missing}s"

    assert 0.4 <= ratio <= 2.5, (
        f"Timing discrepancy detected: existing={mean_existing:.4f}s, "
        f"missing={mean_missing:.4f}s, ratio={ratio:.2f}"
    )
