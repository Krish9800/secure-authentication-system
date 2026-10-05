# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-05

### Added
- **Cryptographic Core:**
  - Argon2id password hashing compliant with RFC 9106 and OWASP parameters ($m=64\text{MB}, t=3, p=4$).
  - Constant-time string and byte comparisons using `secrets.compare_digest`.
  - Synthetic dummy hash calculation (`verify_dummy()`) to mitigate user enumeration side-channel timing attacks.
  - 256-bit CSPRNG bearer session tokens stored strictly as SHA-256 digests at rest.
  - RFC 6238 TOTP Multi-Factor Authentication with $\pm 30\text{s}$ window drift tolerance.
  - Single-use emergency backup recovery codes stored as SHA-256 digests.
- **Persistence & Data Layer:**
  - SQLModel relational schema (`users`, `sessions`, `backup_recovery_codes`, `security_audit_events`).
  - Strict foreign key enforcement on SQLite connections via `PRAGMA foreign_keys=ON`.
  - Transactional repository layer (`UserRepository`, `SessionRepository`, `RecoveryCodeRepository`, `AuditRepository`).
- **Security Services:**
  - `LockoutService` implementing progressive exponential backoff (base 5 minutes up to 24 hours) after 5 consecutive failures.
  - `AuditService` recording structured, tamper-evident security telemetry with automated sensitive key redaction.
  - `MFAService` orchestrating secret generation, QR provisioning URIs, confirmation, and single-use code redemption.
  - `AuthService` orchestrating timing-invariant authentication, step-up MFA challenge tokens, and session lifecycles.
- **REST API:**
  - FastAPI application factory with modular routers under `/api/v1` (`/auth`, `/mfa`, `/users`).
  - `SecurityHeadersMiddleware` enforcing `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `no-store` cache control.
  - `RateLimitMiddleware` providing in-memory sliding-window IP throttling (15 auth attempts/min).
  - Clean error handlers mapping security exceptions to RFC-compliant HTTP status codes (`401`, `423 Locked`, `409 Conflict`).
- **Operational CLI:**
  - Rich and Typer command-line interface `secure-auth`.
  - Administrative commands: `serve`, `version`, `db init`, `user create`, `user list`, `user unlock`, `audit list`.
- **Testing & DevSecOps:**
  - 30 comprehensive unit, integration, and security tests achieving $\ge 93\%$ code coverage.
  - Statistical side-channel timing test verifying indistinguishable latency on non-existent users.
  - Multi-stage non-root `Dockerfile` with healthcheck.
  - GitHub Actions CI workflow with matrix testing across Python 3.12 and 3.13, Ruff linting, Mypy strict typechecking, and Bandit SAST scanner.
