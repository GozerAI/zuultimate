"""Phase 2 Identity Router — capability management endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.phase2_schemas import (
    CapabilityTokenResponse,
    CreateDataShapeRequest,
    DataShapeResponse,
    DelegateCapabilityRequest,
    EnforceRequest,
    GrantCapabilityRequest,
    IdentityTokenResponse,
    PolicyDecisionResponse,
    ResolveIdentityRequest,
    RevokeCapabilityRequest,
)
from zuultimate.identity.phase2_service import InteractionEnforcer

router = APIRouter(
    prefix="/identity/phase2",
    tags=["identity-phase2"],
    responses=STANDARD_ERRORS,
)


def _get_enforcer(request: Request) -> InteractionEnforcer:
    return InteractionEnforcer(request.app.state.db, request.app.state.settings)


def _identity_to_response(token) -> IdentityTokenResponse:
    return IdentityTokenResponse(
        id=token.id,
        entity_type=token.entity_type,
        entity_id=token.entity_id,
        tenant_id=token.tenant_id,
        display_name=token.display_name,
        parent_token_id=token.parent_token_id,
        is_active=token.is_active,
        created_at=token.created_at,
    )


def _capability_to_response(cap) -> CapabilityTokenResponse:
    return CapabilityTokenResponse(
        id=cap.id,
        identity_token_id=cap.identity_token_id,
        capability=cap.capability,
        resource_scope=cap.resource_scope,
        constraints=json.loads(cap.constraints_json),
        granted_by=cap.granted_by,
        parent_capability_id=cap.parent_capability_id,
        delegatable=cap.delegatable,
        expires_at=cap.expires_at,
        revoked_at=cap.revoked_at,
        created_at=cap.created_at,
    )


def _data_shape_to_response(shape) -> DataShapeResponse:
    return DataShapeResponse(
        id=shape.id,
        name=shape.name,
        tenant_id=shape.tenant_id,
        sensitivity=shape.sensitivity,
        retention_days=shape.retention_days,
        pii_fields=json.loads(shape.pii_fields_json),
        created_at=shape.created_at,
    )


# ── Identity Tokens ──────────────────────────────────────────────────────────


@router.post(
    "/tokens/resolve",
    summary="Resolve or create an IdentityToken",
    response_model=IdentityTokenResponse,
)
async def resolve_identity(
    body: ResolveIdentityRequest,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        token = await enforcer.resolve_identity(
            entity_type=body.entity_type,
            entity_id=body.entity_id or user["user_id"],
            tenant_id=user.get("tenant_id"),
            display_name=body.display_name or user.get("username", ""),
            metadata=body.metadata,
        )
        return _identity_to_response(token)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/tokens/{token_id}",
    summary="Get IdentityToken details",
    response_model=IdentityTokenResponse,
)
async def get_identity_token(
    token_id: str,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        token = await enforcer.get_identity_token(token_id)
        return _identity_to_response(token)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# ── Capabilities ─────────────────────────────────────────────────────────────


@router.post(
    "/capabilities",
    summary="Grant a capability to an identity",
    response_model=CapabilityTokenResponse,
)
async def grant_capability(
    body: GrantCapabilityRequest,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    # Resolve the caller's identity to use as grantor
    try:
        grantor = await enforcer.resolve_identity(
            entity_type="user",
            entity_id=user["user_id"],
            tenant_id=user.get("tenant_id"),
            display_name=user.get("username", ""),
        )
        cap = await enforcer.grant_capability(
            grantor_id=grantor.id,
            grantee_id=body.grantee_identity_id,
            capability=body.capability,
            resource_scope=body.resource_scope,
            constraints=body.constraints,
            delegatable=body.delegatable,
            ttl_seconds=body.ttl_seconds,
        )
        return _capability_to_response(cap)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/capabilities",
    summary="List capabilities for the current user",
    response_model=list[CapabilityTokenResponse],
)
async def list_capabilities(
    identity_id: str | None = None,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        if not identity_id:
            token = await enforcer.resolve_identity(
                entity_type="user",
                entity_id=user["user_id"],
                tenant_id=user.get("tenant_id"),
            )
            identity_id = token.id
        caps = await enforcer.list_capabilities(identity_id)
        return [_capability_to_response(c) for c in caps]
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.delete(
    "/capabilities/{capability_id}",
    summary="Revoke a capability (cascading)",
)
async def revoke_capability(
    capability_id: str,
    body: RevokeCapabilityRequest = RevokeCapabilityRequest(),
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        count = await enforcer.revoke_capability(capability_id, reason=body.reason)
        return {"revoked_count": count}
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/capabilities/{capability_id}/delegate",
    summary="Delegate a capability with attenuation",
    response_model=CapabilityTokenResponse,
)
async def delegate_capability(
    capability_id: str,
    body: DelegateCapabilityRequest,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        cap = await enforcer.delegate(
            parent_capability_id=capability_id,
            grantee_id=body.grantee_identity_id,
            resource_scope=body.resource_scope,
            ttl_seconds=body.ttl_seconds,
        )
        return _capability_to_response(cap)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# ── Enforcement ──────────────────────────────────────────────────────────────


@router.post(
    "/enforce",
    summary="Evaluate a policy decision",
    response_model=PolicyDecisionResponse,
)
async def enforce(
    body: EnforceRequest,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        token = await enforcer.resolve_identity(
            entity_type="user",
            entity_id=user["user_id"],
            tenant_id=user.get("tenant_id"),
        )
        decision = await enforcer.enforce(
            identity_token_id=token.id,
            resource=body.resource,
            action=body.action,
            data_shape_name=body.data_shape_name,
        )
        return PolicyDecisionResponse(
            id=decision.id,
            decision=decision.decision,
            reason=decision.reason,
            filtered_fields=json.loads(decision.filtered_fields_json),
            latency_ms=decision.latency_ms,
            evaluated_at=decision.evaluated_at,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# ── Data Shapes ──────────────────────────────────────────────────────────────


@router.post(
    "/data-shapes",
    summary="Create a data shape definition",
    response_model=DataShapeResponse,
)
async def create_data_shape(
    body: CreateDataShapeRequest,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    try:
        shape = await enforcer.create_data_shape(
            name=body.name,
            sensitivity=body.sensitivity,
            schema_definition=body.schema_definition,
            retention_days=body.retention_days,
            pii_fields=body.pii_fields,
            tenant_id=body.tenant_id,
        )
        return _data_shape_to_response(shape)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get(
    "/data-shapes",
    summary="List data shapes",
    response_model=list[DataShapeResponse],
)
async def list_data_shapes(
    tenant_id: str | None = None,
    user: dict = Depends(get_current_user),
    enforcer: InteractionEnforcer = Depends(_get_enforcer),
):
    shapes = await enforcer.list_data_shapes(tenant_id=tenant_id)
    return [_data_shape_to_response(s) for s in shapes]
