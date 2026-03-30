# ADR-005: Zero Trust Architecture over VPN

## Status

Accepted

## Date

2026-03-12

## Context

Traditional VPN-based access grants implicit trust to all traffic once a user connects to the corporate network. This model has well-documented weaknesses: lateral movement after breach, coarse-grained access control, poor visibility into per-request behavior, and difficulty scaling to remote/hybrid workforces. Zuultimate serves as an enterprise identity and security platform and must adopt a security model appropriate for modern threat landscapes.

## Decision

Implement a zero trust model where every request is individually verified regardless of network location. The core principles are:

1. **Never trust, always verify.** Every request carries credentials (mTLS cert + JWT) that are validated per-request.
2. **Device posture evaluation.** PoP proxies assess device health (OS patch level, disk encryption, endpoint protection) before forwarding requests.
3. **Certificate validity.** Client certificates are validated against the cached CRL on every request.
4. **ABAC policy evaluation.** Attribute-based access control policies are evaluated per-request, not per-session.
5. **No implicit trust from network location.** A request from inside a corporate network receives the same scrutiny as one from a coffee shop.

PoP (Point-of-Presence) proxies handle mTLS termination and posture validation at the edge, forwarding authenticated requests to zuultimate with signed attestation headers.

## Consequences

- Higher per-request overhead compared to VPN (certificate validation, posture checks, ABAC evaluation on every call).
- Dramatically better security posture: no lateral movement risk, no implicit trust zones.
- Better audit trail: every access decision is logged with full context.
- Easier to support remote and hybrid workforces without VPN infrastructure.
- Requires robust PoP infrastructure and cached CRL management (see ADR-006).
