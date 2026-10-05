# Secure Authentication Service

> **Educational Defensive Security Project (Cybersecurity Portfolio — Project 02)**  
> A production-grade, defense-in-depth authentication microservice demonstrating modern password hashing (Argon2id), timing side-channel mitigation, TOTP Multi-Factor Authentication (RFC 6238), progressive account lockouts, and structured security audit logging.

---

## 🔒 Security Posture & Architecture Guarantees

> [!IMPORTANT]
> **Core Cryptographic & Architectural Controls:**
> - **Argon2id (RFC 9106):** State-of-the-art password hashing with configurable memory-hardness ($64\text{MB}$), time cost ($t=3$), and parallelism ($p=4$) preventing GPU/ASIC brute-force economies.
> - **Timing Invariance:** Defends against user enumeration and password length timing side-channels via constant-time verification and synthetic dummy hash calculations for missing users.
> - **Multi-Factor Authentication (MFA):** RFC 6238 compliant Time-Based One-Time Passwords (TOTP) with replay attack prevention and single-use backup recovery codes.
> - **Progressive Account Lockouts:** Per-account progressive delays and exponential backoff mitigating automated brute-force attacks.
> - **Session Security:** 256-bit CSPRNG session tokens stored as SHA-256 hashes to prevent token exposure in database read breaches.
> - **Structured Audit Telemetry:** RFC 5424 compliant immutable security events with zero credential leakage.

---

## Overview & Threat Model

Authentication systems are the front gate of any secure infrastructure. Naive authentication implementations suffer from several critical vulnerabilities:
1. **User Enumeration via Error Messages or Timing:** An attacker observes that authenticating with an invalid username responds in $2\text{ms}$ while a valid username with wrong password takes $120\text{ms}$ (due to password hashing). This allows mass discovery of registered user accounts.
2. **Brute Force & Credential Stuffing:** Automated botnets spray credentials without being rate-limited or locked out.
3. **Weak Hashing Algorithms:** Legacy algorithms (MD5, SHA-1, unkeyed SHA-256) offer no memory hardness and are cracked in seconds on consumer GPUs.

The **Secure Authentication Service** implements defensive counter-measures against each of these threats.

---

## Architecture

```
secure-authentication-service/
├── src/
│   └── secure_auth/
│       ├── config/          # Central configuration and security parameters
│       ├── core/            # Cryptographic primitives (Argon2id, TOTP, CSPRNG tokens)
│       ├── models/          # SQLModel database schemas (User, Session, AuditLog)
│       ├── storage/         # Database engine and transaction isolation
│       ├── services/        # Business logic (Auth, Lockout, MFA, Audit)
│       ├── api/             # FastAPI REST endpoints with security middleware
│       └── cli/             # Administrative and security audit CLI
├── tests/
│   ├── unit/                # Unit tests for cryptography, timing, and lockout
│   ├── integration/         # API flows and session management
│   └── security/            # Timing side-channel statistical verification & fuzzing
└── pyproject.toml           # Modern package configuration
```

---

## Installation & Setup

```bash
# Clone and enter directory
cd secure-authentication-service

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

---

## Usage

### 1. Starting the Service
```bash
# Launch the REST API server on 127.0.0.1:8000
secure-auth serve --port 8000
```

### 2. Administrative CLI
```bash
# Inspect system security audit logs
secure-auth audit list

# Unlock an account locked out due to failed attempts
secure-auth user unlock admin@example.com
```

### 3. API Endpoints
- `POST /api/v1/auth/register` — Create new account with Argon2id hash.
- `POST /api/v1/auth/login` — Timing-safe login returning session token.
- `POST /api/v1/auth/mfa/setup` — Generate TOTP secret and QR code URI.
- `POST /api/v1/auth/mfa/verify` — Verify and activate TOTP MFA.
- `POST /api/v1/auth/logout` — Revoke and invalidate session token.
- `GET  /api/v1/auth/profile` — Access protected user profile.
