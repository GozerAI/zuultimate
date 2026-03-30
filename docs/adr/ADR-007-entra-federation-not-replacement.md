# ADR-007: Entra ID Federation, Not Replacement

## Status

Accepted

## Date

2026-03-12

## Context

Enterprise customers use Microsoft Entra ID (formerly Azure AD) as their workforce identity provider. These organizations have invested heavily in Entra ID for user lifecycle management, group membership, MFA policies, and conditional access. Zuultimate must integrate with these existing identity systems rather than requiring enterprises to migrate away from them.

Two integration approaches were considered:

1. **Replacement:** Zuultimate becomes the sole IdP, importing users from Entra ID. This would require enterprises to abandon their Entra ID investment and reconfigure all downstream applications.
2. **Federation:** Zuultimate federates with Entra ID, accepting its authentication assertions while maintaining its own authorization layer.

## Decision

Federate with Entra ID via SAML 2.0 and OIDC. Zuultimate remains the authorization source. The division of responsibility is:

- **Entra ID provides:** Authentication (username/password, MFA), user lifecycle (provisioning/deprovisioning), group membership claims, conditional access policies on the Entra side.
- **Zuultimate provides:** Authorization (ABAC policy evaluation), workforce namespace enforcement, JIT access grants, break-glass procedures, sovereignty controls, and audit logging.

Claim mapping is configured per-tenant. Entra ID group claims are mapped to zuultimate ABAC attributes during token exchange. The federation trust is established via SAML metadata exchange or OIDC discovery.

## Consequences

- Enterprises keep their existing IdP investment. No user migration required.
- Zuultimate maintains full authorization control independent of the upstream IdP.
- Claim mapping configuration must be maintained per-tenant, adding operational overhead for multi-tenant deployments.
- Federation introduces a dependency on Entra ID availability for initial authentication (mitigated by cached session tokens).
- The same federation pattern can be extended to other IdPs (Okta, Ping, Google Workspace) in the future.
