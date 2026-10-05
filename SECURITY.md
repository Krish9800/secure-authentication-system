# Security Policy

## Reporting Security Issues

We take the security of the Secure Authentication Service seriously. Please report any potential vulnerabilities responsibly via private disclosure.

## Security Engineering Invariants

1. **Argon2id (RFC 9106):** Passwords are never stored in cleartext. Hashes use OWASP-recommended memory ($64\text{MB}$) and time parameters.
2. **Side-Channel Timing Invariance:** Response times for invalid usernames and valid usernames with wrong passwords must remain statistically indistinguishable.
3. **Session Token Hashing:** Plaintext session tokens are never persisted in the database; only SHA-256 hashes of tokens are stored.
4. **Log Sanitization:** Sensitive arguments (passwords, TOTP secrets, recovery codes) are never written to logs or stdout.
