# Zuultimate Phase 2: Capability-Based Identity Layer

> Author: COO | Date: 2026-03-05
> Status: DESIGN — ready for implementation

---

## 1. Problem Statement

Phase 1 identity answers **"who are you?"** (JWT/API key → User → Tenant) and **"what plan are you on?"** (PLAN_ENTITLEMENTS static mapping). This works for human users accessing web services.

Phase 2 must answer **"what can this entity do right now, in this context?"** — supporting AI agents, service-to-service delegation, scoped temporary access, and fine-grained data shape enforcement. The GozerAI ecosystem has 16 C-Suite agents, multiple microservices, and external integrations that all need identity beyond username/password.

---

## 2. Design Principles

1. **Capability, not identity** — tokens represent permissions, not people
2. **Least privilege** — capabilities are scoped, time-limited, and revocable
3. **Composable** — capabilities can be combined, delegated, and attenuated (never amplified)
4. **Auditable** — every capability grant, delegation, and enforcement is logged
5. **Backwards compatible** — Phase 1 auth continues to work unchanged

---

## 3. New Concepts

### 3.1 IdentityToken

An **IdentityToken** extends the current User/ApiKey identity to represent any authenticated entity in the system — human user, AI agent, or service.

```
IdentityToken
├── id (UUID)
├── entity_type: "user" | "agent" | "service"
├── entity_id: str         # user_id, agent codename, or service name
├── tenant_id: str (FK)
├── display_name: str
├── parent_token_id: str (nullable)  # delegation chain
├── metadata: JSON         # entity-specific data (agent role, service version, etc.)
├── is_active: bool
├── created_at, updated_at
```

**Why?** The current system has User and ApiKey as separate identity types with different auth flows. IdentityToken unifies them under one concept. A User logs in and gets an IdentityToken. An AI agent authenticates via service token and gets an IdentityToken. A microservice authenticates and gets an IdentityToken. Downstream, everything is just an IdentityToken with capabilities.

### 3.2 CapabilityToken

A **CapabilityToken** represents a specific, scoped permission granted to an IdentityToken. Unlike RBAC roles (which are static and broad), capabilities are dynamic, time-limited, and can be delegated.

```
CapabilityToken
├── id (UUID)
├── identity_token_id: str (FK)
├── capability: str        # e.g., "vault:encrypt", "csuite:delegate:cmo", "data:read:trends"
├── resource_scope: str    # resource pattern (glob), e.g., "tenant/*/trends/*"
├── constraints: JSON      # additional limits: {max_calls: 100, ip_range: "10.0.0.0/8"}
├── granted_by: str        # identity_token_id of grantor
├── delegatable: bool      # can this capability be further delegated?
├── expires_at: datetime
├── revoked_at: datetime (nullable)
├── created_at
```

**Key behaviors:**
- Capabilities are **attenuation-only**: a delegated capability can never exceed the grantor's scope
- Capabilities have mandatory expiry (max 24h default, configurable per tenant)
- Revocation is immediate and cascading (revoking a parent revokes all delegated children)

### 3.3 DataShape

A **DataShape** defines the structure and sensitivity classification of data that flows through the system. It's used by PolicyDecision to determine what data an entity can access.

```
DataShape
├── id (UUID)
├── name: str              # e.g., "user_profile", "financial_report", "trend_data"
├── tenant_id: str (FK, nullable)  # null = system-wide shape
├── schema_definition: JSON # JSON Schema for the data structure
├── sensitivity: "public" | "internal" | "confidential" | "restricted"
├── retention_days: int    # data retention policy
├── pii_fields: JSON       # list of field paths containing PII
├── created_at, updated_at
```

**Why?** When a C-Suite agent requests data, the system needs to know not just "can this agent access trends?" but "which fields of the trend data can this agent see, given its clearance level?" DataShape enables field-level access control and compliance (GDPR, SOC2).

### 3.4 PolicyDecision

A **PolicyDecision** is the evaluation engine that combines IdentityToken + CapabilityToken + DataShape to produce an allow/deny decision with field-level filtering.

```
PolicyDecision
├── id (UUID)
├── identity_token_id: str (FK)
├── capability_id: str (FK, nullable)  # which capability was evaluated
├── resource: str          # what was accessed
├── action: str            # what was attempted
├── data_shape_id: str (FK, nullable)  # which data shape applies
├── decision: "allow" | "deny" | "allow_filtered"
├── reason: str            # human-readable explanation
├── filtered_fields: JSON  # fields removed from response (if allow_filtered)
├── evaluated_at: datetime
├── latency_ms: int        # evaluation time for performance monitoring
```

**Decision logic (ordered):**
1. Check IdentityToken is active and not expired
2. Find matching CapabilityTokens for the requested resource+action
3. If no capability matches → DENY
4. If capability matches but DataShape restricts fields → ALLOW_FILTERED (remove restricted fields)
5. If capability matches and no field restrictions → ALLOW
6. Log PolicyDecision for audit

### 3.5 InteractionEnforcer

The **InteractionEnforcer** is the middleware/service that sits at the boundary of every service and enforces PolicyDecisions in real-time.

```
InteractionEnforcer (service, not a model)
├── enforce(identity_token, resource, action, data_shape=None) → PolicyDecision
├── grant_capability(grantor_token, grantee_token, capability, scope, ttl) → CapabilityToken
├── revoke_capability(capability_id, reason) → void
├── delegate(parent_capability_id, grantee_token, attenuated_scope) → CapabilityToken
├── list_capabilities(identity_token_id) → list[CapabilityToken]
├── resolve_identity(auth_header) → IdentityToken
```

**Integration pattern:**
```python
# In any service router
@router.get("/trends/{tenant_id}")
async def get_trends(
    tenant_id: str,
    identity: IdentityToken = Depends(resolve_identity),
    enforcer: InteractionEnforcer = Depends(get_enforcer),
):
    decision = await enforcer.enforce(
        identity_token=identity,
        resource=f"tenant/{tenant_id}/trends",
        action="read",
        data_shape="trend_data",
    )
    if decision.decision == "deny":
        raise HTTPException(403, decision.reason)

    data = await fetch_trends(tenant_id)
    if decision.filtered_fields:
        data = filter_fields(data, decision.filtered_fields)
    return data
```

---

## 4. Relationship to Phase 1

Phase 2 **wraps** Phase 1, it does not replace it.

```
Phase 1 (unchanged):
  Login → JWT → User + Tenant + Plan → PLAN_ENTITLEMENTS
  API Key → gzr_ prefix → Tenant + Plan → PLAN_ENTITLEMENTS

Phase 2 (new layer):
  JWT/API Key → resolve_identity() → IdentityToken
  IdentityToken + CapabilityTokens → enforce() → PolicyDecision
  PolicyDecision + DataShape → filtered response
```

Phase 1 auth remains the **authentication** layer. Phase 2 adds **authorization** with capabilities. The `get_current_user` dependency continues to work — `resolve_identity` calls it internally and wraps the result in an IdentityToken.

---

## 5. Agent Identity Flow

When a C-Suite agent needs to perform work:

```
1. CoS receives task from user
2. CoS calls InteractionEnforcer.grant_capability(
       grantor=cos_identity,
       grantee=cmo_identity,
       capability="content:create",
       scope="tenant/123/blog/*",
       ttl=3600  # 1 hour
   )
3. CMO receives capability token
4. CMO calls blog_content service with capability token
5. InteractionEnforcer.enforce() validates capability → ALLOW
6. CMO completes task, capability expires
```

This ensures:
- Agents only get the permissions they need for the current task
- Delegation is audited (CoS granted CMO access)
- Access is time-limited (1 hour)
- CMO cannot access data outside the granted scope

---

## 6. Database Placement

All Phase 2 models go in the **identity database** (`zuultimate_identity`), alongside existing User/Tenant/etc. models:

- `identity_tokens` table
- `capability_tokens` table
- `data_shapes` table
- `policy_decisions` table (high-write; consider partitioning later)

---

## 7. Migration Strategy

1. Add Phase 2 tables via Alembic migration (additive, no schema changes to Phase 1 tables)
2. Create default IdentityTokens for existing Users (backfill migration)
3. Create system DataShapes for known data types (trends, commerce, etc.)
4. InteractionEnforcer starts in **permissive mode**: if no CapabilityToken exists, fall through to Phase 1 RBAC
5. Gradually add capability requirements to services as they adopt Phase 2

---

## 8. Module Structure

```
src/zuultimate/identity/
├── models.py              # Phase 1 models (unchanged)
├── phase2_models.py       # IdentityToken, CapabilityToken, DataShape, PolicyDecision
├── service.py             # Phase 1 service (unchanged)
├── phase2_service.py      # InteractionEnforcer
├── router.py              # Phase 1 routes (unchanged)
├── phase2_router.py       # Phase 2 capability management routes
├── tenant_service.py      # (unchanged)
├── mfa_service.py         # (unchanged)
└── sso_service.py         # (unchanged)
```

---

## 9. New API Endpoints

```
POST   /v1/identity/capabilities              # Grant a capability
GET    /v1/identity/capabilities               # List my capabilities
DELETE /v1/identity/capabilities/{id}          # Revoke a capability
POST   /v1/identity/capabilities/{id}/delegate # Delegate a capability

POST   /v1/identity/tokens/resolve             # Resolve auth → IdentityToken
GET    /v1/identity/tokens/{id}                # Get IdentityToken details

POST   /v1/identity/enforce                    # Evaluate a policy decision
GET    /v1/identity/decisions                   # Query policy decision audit log

POST   /v1/identity/data-shapes                # Create a data shape
GET    /v1/identity/data-shapes                 # List data shapes
GET    /v1/identity/data-shapes/{id}            # Get data shape details
```

---

## 10. Success Criteria

- [ ] All Phase 2 models created with Alembic migration
- [ ] InteractionEnforcer service with enforce(), grant_capability(), revoke_capability(), delegate()
- [ ] Permissive fallback mode (Phase 1 RBAC still works)
- [ ] 20+ tests covering model CRUD, capability lifecycle, delegation chains, and enforcement
- [ ] No breaking changes to Phase 1 auth flow
