# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-20

### Added

- **AI Security module** -- Injection detector with 30+ patterns across prompt injection, jailbreak, data exfiltration, and privilege escalation categories. Tool guard with per-agent RBAC and parameter scanning. Red team testing suite gated by Argon2id-hashed passphrase. Security audit log with bounded in-memory buffer and async database persistence. Compliance reporting endpoint. Audit retention service with statistics, archival, and purge operations.
- **Identity module** -- User registration with email/username/password. JWT authentication with access and refresh tokens. Token blacklisting on logout. Email verification flow (send + confirm). TOTP-based multi-factor authentication (setup, verify, challenge). Configurable token lifetimes.
- **Tenant management** -- Multi-tenant isolation with create, list, get, and deactivate operations. Tenant-scoped data across identity, access, and storage layers.
- **SSO module** -- OIDC and SAML provider registration with client credentials. SSO login initiation with redirect URI validation. Callback handling for completing federated authentication. Provider listing and deactivation.
- **Access control module** -- Policy-based authorization with allow/deny effects, resource and action pattern matching, and priority evaluation. Role assignment to users. Access check endpoint for runtime policy evaluation.
- **Vault module** -- AES-256-GCM encryption and decryption with labeled blobs and owner tracking. Data tokenization and detokenization. Single-blob and bulk key rotation. User-scoped password vault for storing, listing, retrieving, and deleting secrets with Argon2id key derivation. Configurable crypto salts per deployment.
- **POS module** -- Terminal registration with name, location, and device type. Transaction processing with idempotency key support (Redis + database dual-write). Batch settlement creation per terminal. Settlement retrieval. Terminal reconciliation. Fraud alert detection and paginated listing.
- **CRM module** -- Provider-agnostic configuration management. Sync job engine with start and status tracking. Pluggable adapter system with registry. Adapter connectivity testing and sample contact fetching.
- **Backup/Resilience module** -- Named backup snapshot creation from any source. Point-in-time restore to specified targets. Data integrity verification checks.
- **Plugin system** -- Runtime plugin registry with name, version, and description. Plugin discovery and detail endpoints. Webhook forwarding to registered plugins. Code-level registration (API registration intentionally blocked).
- **Webhook system** -- Outbound webhook subscriptions with URL, event filter patterns, and optional HMAC secret. Webhook listing and deactivation. Database-backed delivery tracking.
- **Idempotency layer** -- Dual-write idempotency (Redis cache + database) for safe transaction retries. Header-based idempotency key via `X-Idempotency-Key`.
- **Database architecture** -- Six isolated async SQLAlchemy databases (identity, credentials, sessions, transactions, audit, CRM). SQLite defaults with PostgreSQL support via `asyncpg`. Alembic migration infrastructure.
- **Redis integration** -- Redis-backed rate limiting, idempotency caching, and session management. Automatic in-memory fallback when Redis is unavailable.
- **Rate limiting** -- Sliding window rate limiter on login, registration, refresh, red team, and retention purge endpoints. Redis-backed with in-memory fallback.
- **Middleware stack** -- Request correlation ID generation and propagation (`X-Request-ID`). Request body size limiting. Security headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy). CORS with configurable origins.
- **Health probes** -- Detailed `/health` endpoint with per-database and Redis connectivity checks (cached 10s). Kubernetes-compatible `/health/live` (liveness) and `/health/ready` (readiness) probes with graceful shutdown awareness.
- **Session cleanup** -- Background task that periodically purges expired sessions (configurable interval and max age).
- **Structured logging** -- Application-wide structured logging via `structlog`.
- **CLI** -- `zuul serve` (start server), `zuul scan` (prompt injection scan), `zuul redteam` (run attack suite), `zuul health` (check server status). Built with Typer and Rich.
- **Docker support** -- Multi-stage Dockerfile (Python 3.11 slim). Docker Compose with application and Redis services, health checks, persistent data volume, and auto-restart.
- **Configuration** -- Pydantic Settings with `ZUUL_` env prefix. Production validation that rejects insecure default secret key outside development. 20+ configurable environment variables.
- **Error handling** -- Global exception handlers for domain errors (`ZuulError`), validation errors, and unhandled exceptions. Consistent JSON error response schema with error codes.
- **Pagination** -- Reusable paginated response schema with page, page_size, total, and total_pages. Applied to audit events and fraud alerts.

### Security

- AES-256-GCM authenticated encryption for all vault data at rest.
- Argon2id password hashing for user credentials and key derivation for the password vault.
- JWT tokens with configurable expiry, refresh rotation, and blacklist-on-logout.
- TOTP multi-factor authentication with encrypted secret storage.
- SSO federated authentication with redirect URI origin validation.
- 30+ prompt injection detection patterns with threat scoring and severity classification.
- Tool guard enforcing per-agent RBAC before tool execution, with parameter content scanning.
- Red team attack suite gated behind Argon2id-verified passphrase with rate limiting.
- Sliding window rate limiting on authentication endpoints to mitigate brute force.
- Security headers on all responses (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
- Request body size limits to prevent payload-based denial of service.
- Production startup validation that blocks insecure default secrets.
- Configurable crypto salts for vault, MFA, and password vault (override per deployment).
- Bounded in-memory collections to prevent unbounded memory growth.
