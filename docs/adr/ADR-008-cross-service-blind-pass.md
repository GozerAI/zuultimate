# ADR-008: Cross-Service Blind Pass via Split-Key Encryption

## Status

Accepted

## Date

2026-03-12

## Context

Vinzy-engine (license management) and zuultimate (identity/security) need to link customer records to associate licenses with tenant identities. However, exposing PII across the service boundary violates the principle of least privilege and creates a data breach amplification risk: compromising one service should not reveal data owned by the other.

## Decision

Use split-key encryption for cross-service identity binding. Neither service alone can decrypt the binding record.

**Key split:**
- Zuultimate holds the **vault key shard** (derived from the tenant's vault master key).
- Vinzy-engine generates a **per-token client key shard** (derived from the license key material).

**Binding process:**
1. During provisioning, a binding record is created with an **ephemeral per-binding salt**.
2. The binding payload is encrypted with a key derived from both shards + the ephemeral salt.
3. Each service stores only its own shard and the encrypted binding blob.
4. Resolution requires a JIT grant (ADR not yet written) that temporarily allows both shards to be combined.

**Correlation prevention:**
- Per-binding ephemeral salts ensure that the same customer linked to two different licenses produces two completely different binding records.
- No shared database between services.
- No direct API lookups that could reveal customer data.

### Alternatives Considered

- **Shared database:** Rejected. Exposes PII across the service boundary. A breach in either service compromises all linked records.
- **Direct API lookups:** Rejected. Creates tight coupling between services and reveals data in transit. Either service could enumerate the other's records.
- **Fully homomorphic encryption:** Rejected. Computationally impractical for real-time request flows at the performance levels required.

## Consequences

- Strong privacy guarantees: neither service can unilaterally access the linked identity.
- Resolution requires JIT grant approval + both key shards, creating a deliberate friction point with full audit trail.
- Operational complexity for debugging is increased by design. Support engineers cannot casually look up cross-service bindings; they must go through the JIT grant flow, which is logged.
- Per-binding salts prevent correlation attacks but mean that binding lookups require knowing which specific binding to resolve (no cross-referencing by customer ID alone).
- Key rotation requires re-encrypting all binding records for the affected tenant, which is a batch operation coordinated between both services.
