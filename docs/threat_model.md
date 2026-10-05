# Threat Model (STRIDE) — Secure Authentication Service

## 1. System Overview & Boundaries

The Secure Authentication Service processes and manages identity credentials, session tokens, and cryptographic keys.

### Protected Assets:
1. **Plaintext Passwords (In-flight):** Must never be logged, persisted, or leaked through exceptions.
2. **Password Hashes & Salts:** Protected at rest in SQL database; must resist offline GPU cracking.
3. **MFA Secrets:** Base32 TOTP seeds; must be encrypted or strictly protected in storage.
4. **Session Tokens:** Active bearer tokens; stored as one-way SHA-256 hashes in the database.
5. **Security Audit Log:** Immutable audit trail of authentication events and anomalies.

---

## 2. STRIDE Threat Analysis

| Category | Specific Threat Scenario | Technical Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Credential stuffing, brute-force dictionary attacks, TOTP code replay. | 1. Memory-hard Argon2id KDF.<br>2. Per-account progressive lockout (5 failed attempts = 5 min lock, exponential thereafter).<br>3. Per-IP rate limiting.<br>4. TOTP consumed timestamp tracking to prevent replay within same 30s window. |
| **Tampering** | Modifying user role in database, altering session token, bypassing MFA flags. | 1. Strict SQLModel ORM parameterization preventing SQL injection.<br>2. Session tokens stored as SHA-256 hashes.<br>3. Two-phase login flow requiring verified MFA state before session creation. |
| **Repudiation** | User denies login or password change action. | Structured, append-only security audit log recording UTC timestamp, IP address, user ID, event type, and outcome. |
| **Information Disclosure** | Username enumeration via timing side-channels, credential leakage in log streams. | 1. Constant-time dummy verification on non-existent users.<br>2. Identical generic error: "Invalid username or password".<br>3. Custom middleware redacting sensitive fields. |
| **Denial of Service** | Argon2id CPU exhaustion via registration flooding, distributed lockout harassment. | 1. IP-level token bucket rate limiting before expensive KDF execution.<br>2. Maximum password length bound (512 characters).<br>3. Admin unlock capability via CLI. |
| **Elevation of Privilege** | Session hijacking, IDOR on profile endpoints, role manipulation. | 1. 256-bit CSPRNG session tokens.<br>2. Token rotation upon privilege transition.<br>3. Explicit role-based access checks. |
