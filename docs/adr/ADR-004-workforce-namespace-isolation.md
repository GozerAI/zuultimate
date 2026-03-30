# ADR-004: Workforce Namespace Isolation

## Status

Accepted

## Date

2026-03-12

## Context

Consumer and workforce identities have different security requirements. Workforce users access through mTLS + device posture. Consumer users access with standard OIDC. Mixing these identity types in a single namespace creates risk: workforce security policies (mandatory device posture, certificate validation) could leak into consumer flows, degrading UX. Conversely, consumer-grade auth must never be accepted for workforce-privileged operations.

## Decision

Separate consumer and workforce identities into distinct JWT namespaces. The namespace is embedded in JWT claims (`zuul_ns: "consumer"` or `zuul_ns: "workforce"`) and validated by middleware on every request. Cross-namespace access is forbidden at the middleware layer. Workforce tokens are only issued through the PoP mTLS flow. Consumer tokens are issued through standard OIDC/password flows.

Key rules:
- A workforce JWT cannot be used on consumer endpoints and vice versa.
- Namespace is set at token issuance and cannot be changed during the token lifetime.
- Refresh tokens inherit and enforce the same namespace.
- Service tokens (X-Service-Token) operate outside the namespace system as they represent machine-to-machine trust.

## Consequences

- Clean separation of security domains. Workforce policies (posture checks, cert validation) do not affect consumer UX.
- Slightly more complex token management: two token issuance paths, namespace-aware middleware.
- API clients must be aware of which namespace they are operating in.
- Reduces blast radius: compromise of consumer auth does not grant workforce access.
