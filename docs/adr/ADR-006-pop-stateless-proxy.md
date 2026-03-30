# ADR-006: Point-of-Presence as Stateless Proxy

## Status

Accepted

## Date

2026-03-12

## Context

PoPs (Point-of-Presence nodes) need to be highly available and easy to deploy across geographic regions. They serve as the zero trust enforcement point at the edge, handling mTLS termination, certificate validation, and device posture assessment. The architectural question is whether PoPs should maintain local state (sessions, policies, user data) or operate as stateless proxies.

## Decision

PoPs are stateless proxies. Their responsibilities are:

1. **Terminate mTLS** and extract client certificate details.
2. **Validate certificates** against a locally cached CRL (refreshed every 15 minutes from the PKI service).
3. **Assess device posture** from the posture blob submitted by the client agent.
4. **Sign attestation headers** (X-PoP-Posture, X-PoP-Region, X-PoP-CertFingerprint) and forward to zuultimate.
5. **Emit Prometheus metrics** (pop_auth_total, pop_cert_validations_total, pop_posture_checks_total, pop_request_duration_seconds, crl_age_seconds).

PoPs have no local database. All authoritative state (users, policies, sessions, audit logs) lives in zuultimate. The only local data is the cached CRL, which is ephemeral and periodically refreshed.

## Consequences

- Easy horizontal scaling: spin up a new PoP instance with zero data migration.
- Fast failover: any PoP can serve any region since there is no regional state affinity.
- CRL cache introduces a 15-minute stale window where a newly revoked certificate may still be accepted. This is an acceptable tradeoff for the operational simplicity gained.
- PoP deployment is a simple container image with configuration for the upstream zuultimate URL and PKI CRL endpoint.
- Monitoring via Prometheus metrics enables centralized observability without PoP-local storage.
