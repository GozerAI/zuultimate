# Zuultimate

Enterprise identity, vault, and zero-trust security platform -- part of the [GozerAI](https://gozerai.com) ecosystem.

Built with Python 3.11+, FastAPI, SQLAlchemy async, and a modular architecture
for identity management, secrets vaulting, and security infrastructure.

## Community Features

- **Identity** -- User registration, JWT auth (access + refresh tokens), email verification, TOTP MFA, multi-tenant isolation
- **Vault** -- AES-256-GCM encryption/decryption, data tokenization, key rotation, user-scoped password vault with Argon2id key derivation
- **Plugins** -- Runtime plugin registry with webhook forwarding and lifecycle management
- **Webhooks** -- Configurable outbound webhook subscriptions with event filtering and HMAC signing
- **Infrastructure** -- Rate limiting with in-memory fallback, request correlation IDs, security headers, request size limits, session cleanup, health probes, structured logging, Alembic migrations

## Pro & Enterprise Features

Additional modules are available with a commercial license:

- **AI Security** (Pro) -- Prompt injection detection, tool guard with RBAC, red team testing, compliance reporting
- **Backup/Resilience** (Pro) -- Snapshot creation, point-in-time restore, data integrity verification
- **Access Control** (Enterprise) -- Policy-based authorization, role assignment, SSO (OIDC/SAML)
- **POS** (Enterprise) -- Terminal management, transaction processing, settlements, fraud alerting
- **CRM** (Enterprise) -- Provider-agnostic sync engine with pluggable adapters

Visit [gozerai.com/pricing](https://gozerai.com/pricing) for details.

## Quick Start

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env
# Edit .env -- at minimum set ZUUL_SECRET_KEY

# Run tests
pytest tests/ -q

# Start dev server
zuul serve --reload
```

## Architecture

| Module    | Prefix         | Description                                       |
|-----------|----------------|---------------------------------------------------|
| Identity  | `/v1/identity` | Registration, login, JWT tokens, email verify, MFA |
| Tenants   | `/v1/tenants`  | Multi-tenant creation, listing, deactivation       |
| Vault     | `/v1/vault`    | Encrypt/decrypt, tokenize, key rotation, secrets   |
| Plugins   | `/v1/plugins`  | Plugin registry, info, webhook forwarding          |
| Webhooks  | `/v1/webhooks` | Outbound webhook subscriptions                     |

## Configuration

All settings use the `ZUUL_` prefix. See `.env.example` for full list.

## Docker

```bash
docker compose up --build
```

## CLI

```bash
zuul serve    # Start API server
zuul health   # Check server health
```

## Testing

```bash
pytest tests/ -q
```

## Security

- **Encryption** -- AES-256-GCM for vault data, Argon2id for password hashing and key derivation
- **Authentication** -- JWT access/refresh tokens, TOTP MFA, token blacklisting on logout
- **Rate Limiting** -- Sliding window with automatic in-memory fallback
- **Transport** -- Security headers, CORS configuration, request size limits
- **Multi-tenancy** -- Tenant isolation across identity and data layers
- **Secrets Management** -- User-scoped password vault, data tokenization, key rotation

## License

This project is dual-licensed:

- **AGPL-3.0** -- free for open-source use. See [LICENSE](LICENSE).
- **Commercial License** -- for proprietary use. Visit [gozerai.com/pricing](https://gozerai.com/pricing).

Copyright (c) 2025-2026 GozerAI.
