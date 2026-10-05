"""Integration tests for REST API endpoints and security middleware."""

from collections.abc import Generator
from typing import Annotated

import pyotp
import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, create_engine

from secure_auth.api.app import create_app
from secure_auth.api.dependencies import get_auth_service, get_db
from secure_auth.core.hasher import Argon2PasswordHasher
from secure_auth.services.auth_service import AuthService
from secure_auth.storage.database import init_db


@pytest.fixture
def fast_hasher() -> Argon2PasswordHasher:
    """Fast Argon2id hasher for integration testing."""
    return Argon2PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)


@pytest.fixture
def client(fast_hasher: Argon2PasswordHasher) -> Generator[TestClient, None, None]:
    """TestClient with in-memory database and fast hasher overrides."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(engine)

    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        with Session(engine) as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise

    def override_get_auth_service(
        session: Annotated[Session, Depends(get_db)],
    ) -> AuthService:
        return AuthService(session, hasher=fast_hasher)

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_auth_service] = override_get_auth_service

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_health_check_and_security_headers(client: TestClient) -> None:
    """Test health endpoint and defensive security response headers."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

    # Verify defensive headers applied by middleware
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "0"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert "no-store" in response.headers["Cache-Control"]


def test_register_and_login_flow(client: TestClient) -> None:
    """Test full registration and primary login workflow."""
    # 1. Register
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "username": "api_user",
            "email": "api_user@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert reg_res.status_code == 201
    data = reg_res.json()
    assert data["username"] == "api_user"
    assert data["email"] == "api_user@example.com"
    assert "uuid" in data

    # 2. Duplicate registration fails with 409 Conflict
    dup_res = client.post(
        "/api/v1/auth/register",
        json={
            "username": "api_user",
            "email": "other@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert dup_res.status_code == 409

    # 3. Wrong password returns 401
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "api_user", "password": "WrongPassword!"},
    )
    assert bad_login.status_code == 401
    assert "WWW-Authenticate" in bad_login.headers

    # 4. Successful login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "api_user", "password": "SecurePassword123!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["status"] == "authenticated"
    assert login_data["mfa_required"] is False
    assert len(login_data["token"]) >= 32

    token = login_data["token"]

    # 5. Access protected /me endpoint with bearer token
    me_res = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "api_user"

    # 6. Logout
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_res.status_code == 200

    # 7. Accessing /me after logout returns 401
    post_logout_res = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert post_logout_res.status_code == 401


def test_mfa_full_api_workflow(client: TestClient) -> None:
    """Test MFA setup, confirmation, step-up challenge, and verification via REST."""
    # Register & Login
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "mfa_user",
            "email": "mfa_user@example.com",
            "password": "SecurePassword123!",
        },
    )
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "mfa_user", "password": "SecurePassword123!"},
    )
    token = login_res.json()["token"]
    auth_header = {"Authorization": f"Bearer {token}"}

    # 1. Setup MFA
    setup_res = client.post("/api/v1/mfa/setup", headers=auth_header)
    assert setup_res.status_code == 200
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    assert "otpauth://" in setup_data["provisioning_uri"]
    assert len(setup_data["backup_recovery_codes"]) == 10

    # 2. Confirm MFA with TOTP code
    totp = pyotp.TOTP(secret)
    confirm_res = client.post(
        "/api/v1/mfa/confirm",
        json={"code": totp.now()},
        headers=auth_header,
    )
    assert confirm_res.status_code == 200

    # 3. Subsequent login requires MFA
    mfa_login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "mfa_user", "password": "SecurePassword123!"},
    )
    assert mfa_login_res.status_code == 200
    mfa_data = mfa_login_res.json()
    assert mfa_data["status"] == "mfa_required"
    assert mfa_data["mfa_required"] is True
    mfa_token = mfa_data["token"]

    # 4. Verify MFA step with TOTP
    verify_res = client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_token": mfa_token, "code": totp.now()},
    )
    assert verify_res.status_code == 200
    full_session = verify_res.json()["token"]

    # 5. Access protected endpoint with promoted session
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {full_session}"})
    assert me.status_code == 200
    assert me.json()["mfa_enabled"] is True


def test_lockout_http_status_code(client: TestClient) -> None:
    """Ensure account lockout responds with HTTP 423 Locked and Retry-After header."""
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "lockout_target",
            "email": "lockout@example.com",
            "password": "RealPassword123!",
        },
    )

    # 4 failed attempts -> 401
    for _ in range(4):
        res = client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "lockout_target", "password": "Wrong"},
        )
        assert res.status_code == 401

    # 5th attempt -> 423 Locked
    locked_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "lockout_target", "password": "Wrong"},
    )
    assert locked_res.status_code == 423
    assert "Retry-After" in locked_res.headers
    assert locked_res.json()["error"] == "AccountLocked"
