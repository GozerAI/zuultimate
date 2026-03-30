# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Zuultimate, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@zuultimate.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity (critical: 72 hours, high: 1 week, medium: 2 weeks)

## Security Features

Zuultimate includes the following security measures:

- **Encryption**: AES-256-GCM for vault data, Argon2id for password hashing
- **Authentication**: JWT with session validation, MFA (TOTP) support
- **Authorization**: Role-based access control with policy evaluation
- **Rate Limiting**: Redis-backed sliding window with in-memory fallback
- **Input Validation**: Pydantic schema validation on all endpoints
- **Security Headers**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- **Request Size Limits**: Configurable body size enforcement
- **AI Security**: Prompt injection detection (30+ patterns), tool guard with RBAC
- **Audit Logging**: All security events logged with retention and archival
- **Secret Key Validation**: Runtime check prevents insecure defaults in production

## Deployment Checklist

Before deploying to production, ensure:

1. `ZUUL_SECRET_KEY` is set to a cryptographically random value
2. `ZUUL_ENVIRONMENT` is set to `production` (enforces secret key validation)
3. `ZUUL_REDTEAM_PASSPHRASE` is set if red team endpoints are enabled
4. Crypto salts are overridden: `ZUUL_VAULT_SALT`, `ZUUL_MFA_SALT`, `ZUUL_PASSWORD_VAULT_SALT`
5. `ZUUL_SSO_ALLOWED_REDIRECT_ORIGINS` is restricted to your actual domains
6. `ZUUL_CORS_ORIGINS` is restricted to your frontend origins
7. Redis is configured for distributed rate limiting across workers
8. Database URLs point to production databases (not SQLite)
