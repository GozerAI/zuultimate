# Zuultimate

**Identity, Vault, and Zero-Trust Security Platform**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Zuultimate is a self-hosted identity management, secrets vaulting, and zero-trust security platform built on FastAPI. It provides user registration, JWT authentication, TOTP multi-factor auth, AES-256-GCM encrypted vault, and multi-tenant isolation out of the box. Part of the [GozerAI](https://gozerai.com) ecosystem.

---

## Features

- **Identity Management** -- User registration, login, email verification, password reset
- **JWT Authentication** -- Dual access + refresh tokens with blacklisting on logout
- **Multi-Factor Auth** -- TOTP-based MFA with recovery codes
- **Encrypted Vault** -- AES-256-GCM encryption/decryption, data tokenization, key rotation
- **Password Vault** -- User-scoped password storage with Argon2id key derivation
- **Multi-Tenancy** -- Tenant creation, isolation, and deactivation
- **Plugins** -- Runtime plugin registry with webhook forwarding
- **Webhooks** -- Outbound HMAC-signed webhook subscriptions with event filtering
- **Infrastructure** -- Rate limiting, correlation IDs, security headers, Alembic migrations, health probes

---

## Quick Start

### Installation

```bash
# From PyPI
pip install zuultimate

# From source
git clone https://github.com/GozerAI/zuultimate.git
cd zuultimate
pip install -e ".[dev]"
```

### Configuration

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
ZUUL_SECRET_KEY=your-random-secret-key-here
```

### Start the Server

```bash
zuul serve --reload
```

The API is available at `http://localhost:8000`.

### Usage Examples

#### Register a User

```bash
curl -X POST http://localhost:8000/v1/identity/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "Str0ngP4ssword!"}'
```

#### Log In (Get JWT Tokens)

```bash
curl -X POST http://localhost:8000/v1/identity/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Str0ngP4ssword!"}'
```

Response: `{ "access_token": "...", "refresh_token": "...", "token_type": "bearer" }`

#### Access a Protected Endpoint

```bash
curl http://localhost:8000/v1/identity/auth/me \
  -H "Authorization: Bearer <access_token>"
```

#### Refresh Tokens

```bash
curl -X POST http://localhost:8000/v1/identity/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

#### Encrypt Data (Vault)

```bash
curl -X POST http://localhost:8000/v1/vault/encrypt \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "sensitive-data-here"}'
```

Response: `{ "ciphertext": "...", "nonce": "..." }`

#### Decrypt Data (Vault)

```bash
curl -X POST http://localhost:8000/v1/vault/decrypt \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "...", "nonce": "..."}'
```

#### Enable MFA

```bash
# Generate TOTP secret
curl -X POST http://localhost:8000/v1/identity/mfa/setup \
  -H "Authorization: Bearer <access_token>"
# Returns: { "secret": "...", "provisioning_uri": "otpauth://..." }

# Verify TOTP code to activate MFA
curl -X POST http://localhost:8000/v1/identity/mfa/verify \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

---

## API Endpoints

| Module | Prefix | Endpoints |
|--------|--------|-----------|
| **Auth** | `/v1/identity/auth` | `POST /register`, `POST /login`, `POST /logout`, `POST /refresh`, `GET /me`, `GET /validate` |
| **MFA** | `/v1/identity/mfa` | `POST /setup`, `POST /verify`, `POST /disable` |
| **Tenants** | `/v1/tenants` | `POST /`, `GET /`, `GET /{id}`, `PATCH /{id}`, `DELETE /{id}` |
| **Vault** | `/v1/vault` | `POST /encrypt`, `POST /decrypt`, `POST /tokenize`, `POST /detokenize`, `POST /rotate-key` |
| **Password Vault** | `/v1/vault/passwords` | `POST /`, `GET /`, `GET /{id}`, `PUT /{id}`, `DELETE /{id}` |
| **Plugins** | `/v1/plugins` | `POST /`, `GET /`, `GET /{id}`, `DELETE /{id}` |
| **Webhooks** | `/v1/webhooks` | `POST /`, `GET /`, `DELETE /{id}` |
| **Health** | `/health` | `GET /` |

---

## Feature Tiers

| Feature | Community | Pro | Enterprise |
|---------|:---------:|:---:|:----------:|
| User registration, login, JWT auth | Yes | Yes | Yes |
| Email verification & password reset | Yes | Yes | Yes |
| TOTP multi-factor authentication | Yes | Yes | Yes |
| AES-256-GCM vault encrypt/decrypt | Yes | Yes | Yes |
| Data tokenization & key rotation | Yes | Yes | Yes |
| User-scoped password vault | Yes | Yes | Yes |
| Multi-tenant isolation | Yes | Yes | Yes |
| Plugin registry & webhooks | Yes | Yes | Yes |
| Rate limiting & security headers | Yes | Yes | Yes |
| AI security (injection detection, red team) | -- | Yes | Yes |
| Backup & resilience (snapshots, restore) | -- | Yes | Yes |
| Advanced access control & SSO (OIDC/SAML) | -- | -- | Yes |
| CRM integration | -- | -- | Yes |
| POS integration | -- | -- | Yes |

Community tier provides a fully functional identity and vault platform. Pro and Enterprise add AI-specific security and enterprise integration capabilities.

---

## Unlocking Pro & Enterprise Features

Pro and Enterprise modules are available with a commercial license. Visit **[gozerai.com/pricing](https://gozerai.com/pricing)** for details.

---

## Configuration

All settings use the `ZUUL_` environment variable prefix. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ZUUL_SECRET_KEY` | (insecure default) | JWT signing secret -- **change in production** |
| `ZUUL_ENVIRONMENT` | `development` | Runtime environment |
| `ZUUL_IDENTITY_DB_URL` | `sqlite+aiosqlite:///./data/identity.db` | Identity database URL |
| `ZUUL_CREDENTIAL_DB_URL` | `sqlite+aiosqlite:///./data/credentials.db` | Credentials database URL |
| `ZUUL_SESSION_DB_URL` | `sqlite+aiosqlite:///./data/sessions.db` | Sessions database URL |
| `ZUUL_REDIS_URL` | *(optional)* | Redis URL for rate limiting (falls back to in-memory) |
| `ZUUL_VAULT_SALT` | (default) | Salt for vault key derivation |
| `ZUUL_MFA_SALT` | (default) | Salt for MFA secret derivation |
| `ZUUL_PASSWORD_VAULT_SALT` | (default) | Salt for password vault key derivation |

See `.env.example` for the full list.

---

## CLI

```bash
zuul serve          # Start the API server
zuul serve --reload # Start with auto-reload for development
zuul health         # Check server health
```

---

## Docker

```bash
docker compose up --build
```

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

---

## Security

- **Encryption** -- AES-256-GCM for vault data, Argon2id for password hashing and key derivation
- **Authentication** -- JWT access/refresh tokens, TOTP MFA, token blacklisting on logout
- **Rate Limiting** -- Sliding window with automatic in-memory fallback
- **Transport** -- Security headers, CORS configuration, request size limits
- **Multi-tenancy** -- Tenant isolation across identity and data layers

Report security vulnerabilities via [SECURITY.md](SECURITY.md).

---

## License

Zuultimate is dual-licensed:

- **[AGPL-3.0](LICENSE)** -- Free for open-source use with copyleft obligations
- **Commercial License** -- For proprietary use without AGPL requirements

Visit [gozerai.com/pricing](https://gozerai.com/pricing) for commercial licensing. See [LICENSING.md](LICENSING.md) for details.

---

## Contributing

We welcome contributions. Please see our [Contributing Guide](CONTRIBUTING.md) for details.

---

## Links

- [GozerAI](https://gozerai.com) -- Main site
- [Pricing](https://gozerai.com/pricing) -- License tiers and pricing
- [Issues](https://github.com/GozerAI/zuultimate/issues) -- Bug reports and feature requests

Copyright (c) 2025-2026 GozerAI.
