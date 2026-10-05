# REST API Reference & Integration Guide

The **Secure Authentication Service** exposes an RFC-compliant REST API under the `/api/v1` namespace.

All requests accept and return `application/json`. Authenticated endpoints require a standard HTTP Authorization header:
```http
Authorization: Bearer <session_token>
```

---

## Response Headers

Every API response includes defensive HTTP security headers:

```http
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
```

---

## 1. Authentication Endpoints

### 1.1 Register Account
Creates a new user account with Argon2id password hashing.

- **URL:** `/api/v1/auth/register`
- **Method:** `POST`
- **Status:** `201 Created`

#### Request Body
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "CorrectHorseBatteryStaple123!"
}
```

#### Response Body
```json
{
  "uuid": "4f9d2d0c-23d9-47ea-a7ad-3d027f67ad81",
  "username": "alice",
  "email": "alice@example.com",
  "message": "User account successfully registered."
}
```

#### Example cURL
```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "CorrectHorseBatteryStaple123!"}'
```

---

### 1.2 Primary Login
Authenticates user credentials. If multi-factor authentication (MFA) is enabled, returns a short-lived step-up token instead of an active session token.

- **URL:** `/api/v1/auth/login`
- **Method:** `POST`
- **Status:** `200 OK` (or `423 Locked` if brute-force threshold exceeded)

#### Request Body
```json
{
  "username_or_email": "alice",
  "password": "CorrectHorseBatteryStaple123!"
}
```

#### Response Body (No MFA)
```json
{
  "status": "authenticated",
  "token": "d74f26b52c00a6e4d75f2849bca74e2d847291a0c8b26e01...",
  "mfa_required": false,
  "message": "Authentication successful."
}
```

#### Response Body (MFA Enabled)
```json
{
  "status": "mfa_required",
  "token": "a1b2c3d4e5f6...",
  "mfa_required": true,
  "message": "Primary authentication successful. Secondary factor challenge required."
}
```

---

### 1.3 Complete MFA Challenge
Verifies a 6-digit TOTP code or emergency backup recovery code using the temporary step-up token.

- **URL:** `/api/v1/auth/mfa/verify`
- **Method:** `POST`
- **Status:** `200 OK`

#### Request Body
```json
{
  "mfa_token": "a1b2c3d4e5f6...",
  "code": "482910"
}
```

#### Response Body
```json
{
  "status": "authenticated",
  "token": "f892a01bc83...",
  "mfa_required": false,
  "message": "Multi-factor challenge satisfied. Session established."
}
```

---

### 1.4 Logout
Revokes the current bearer session token immediately.

- **URL:** `/api/v1/auth/logout`
- **Method:** `POST`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Response Body
```json
{
  "message": "Session successfully revoked.",
  "detail": null
}
```

---

### 1.5 Global Logout
Revokes all active sessions for the user across all browsers, mobile devices, and clients.

- **URL:** `/api/v1/auth/logout-all`
- **Method:** `POST`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Response Body
```json
{
  "message": "All sessions revoked.",
  "detail": "Revoked 3 active sessions."
}
```

---

## 2. Multi-Factor Authentication Endpoints

### 2.1 Initiate MFA Setup
Generates an RFC 6238 Base32 secret, an `otpauth://` provisioning URI (for QR codes), and 10 single-use emergency backup recovery codes.

- **URL:** `/api/v1/mfa/setup`
- **Method:** `POST`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Response Body
```json
{
  "secret": "JBSWY3DPEHPK3PXP...",
  "provisioning_uri": "otpauth://totp/CyberSecurityPortfolio:alice%40example.com?secret=JBSWY3DPEHPK3PXP...&issuer=CyberSecurityPortfolio",
  "backup_recovery_codes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    "I9J0-K1L2",
    "M3N4-O5P6",
    "Q7R8-S9T0",
    "U1V2-W3X4",
    "Y5Z6-A7B8",
    "C9D0-E1F2",
    "G3H4-I5J6",
    "K7L8-M9N0"
  ],
  "message": "Scan QR URI or enter secret in authenticator app, then confirm with a code."
}
```

---

### 2.2 Confirm & Activate MFA
Validates the initial live 6-digit TOTP code to permanently activate MFA on the account.

- **URL:** `/api/v1/mfa/confirm`
- **Method:** `POST`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Request Body
```json
{
  "code": "583921"
}
```

#### Response Body
```json
{
  "message": "Multi-factor authentication successfully enabled.",
  "detail": null
}
```

---

### 2.3 Disable MFA
Deactivates 2FA after validating a live code (TOTP or recovery code).

- **URL:** `/api/v1/mfa/disable`
- **Method:** `POST`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Request Body
```json
{
  "code": "583921"
}
```

#### Response Body
```json
{
  "message": "Multi-factor authentication successfully disabled.",
  "detail": null
}
```

---

## 3. User Introspection Endpoints

### 3.1 Get Profile
Returns user account details for the authenticated bearer token.

- **URL:** `/api/v1/users/me`
- **Method:** `GET`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Response Body
```json
{
  "uuid": "4f9d2d0c-23d9-47ea-a7ad-3d027f67ad81",
  "username": "alice",
  "email": "alice@example.com",
  "mfa_enabled": true,
  "created_at": "2026-10-05T14:30:00Z"
}
```

---

### 3.2 Audit Log History
Retrieves recent security audit events associated with the authenticated account.

- **URL:** `/api/v1/users/me/audit`
- **Method:** `GET`
- **Header:** `Authorization: Bearer <token>`
- **Status:** `200 OK`

#### Response Body
```json
[
  {
    "id": 14,
    "timestamp": "2026-10-05T14:45:10Z",
    "event_type": "AUTH_LOGIN_SUCCESS",
    "status": "SUCCESS",
    "details": "{\"mfa_used\": true}"
  },
  {
    "id": 13,
    "timestamp": "2026-10-05T14:45:05Z",
    "event_type": "MFA_CHALLENGE_SUCCESS",
    "status": "SUCCESS",
    "details": "{\"method\": \"totp\"}"
  }
]
```
