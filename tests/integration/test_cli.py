"""Integration tests for Typer administrative CLI."""

from typer.testing import CliRunner

from secure_auth.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Ensure version command outputs cryptographic configuration."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Argon2id Memory Cost" in result.stdout
    assert "Lockout Threshold" in result.stdout


def test_cli_db_init() -> None:
    """Ensure db init command creates database schema."""
    result = runner.invoke(app, ["db", "init"])
    assert result.exit_code == 0
    assert "Database schema successfully initialized" in result.stdout


def test_cli_user_lifecycle() -> None:
    """Test user creation, listing, and unlocking via CLI commands."""
    import uuid

    uid = uuid.uuid4().hex[:6]
    test_user = f"u_{uid}"
    test_email = f"u_{uid}@test.com"

    # 1. Create User
    result = runner.invoke(
        app,
        [
            "user",
            "create",
            "--username",
            test_user,
            "--email",
            test_email,
            "--password",
            "SuperSecret123!",
        ],
    )
    assert result.exit_code == 0
    assert "created successfully" in result.stdout

    # 2. List Users
    list_res = runner.invoke(app, ["user", "list"])
    assert list_res.exit_code == 0
    assert test_user in list_res.stdout

    # 3. Unlock User
    unlock_res = runner.invoke(app, ["user", "unlock", test_user])
    assert unlock_res.exit_code == 0
    assert "successfully unlocked" in unlock_res.stdout

    # 4. Unlock Non-existent User
    fail_unlock = runner.invoke(app, ["user", "unlock", "nonexistent_ghost"])
    assert fail_unlock.exit_code == 1
    assert "not found" in fail_unlock.stdout


def test_cli_audit_list() -> None:
    """Ensure audit list displays security audit log table."""
    result = runner.invoke(app, ["audit", "list"])
    assert result.exit_code == 0
    assert "Security Audit Log Trail" in result.stdout
