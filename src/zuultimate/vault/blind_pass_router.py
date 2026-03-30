"""Blind pass and cross-service binding API routes."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from zuultimate.common.auth import get_service_caller

router = APIRouter(prefix="/vault", tags=["vault"])


class BlindPassCreateRequest(BaseModel):
    tenant_id: str
    purpose: str = "provisioning"
    client_key_shard: str  # hex-encoded 32 bytes
    ttl_seconds: int = Field(default=86400 * 365, le=86400 * 365 * 2)
    sovereignty_ring: str = "us"


class BlindPassVerifyRequest(BaseModel):
    token: str
    purpose: str


class BlindPassResolveRequest(BaseModel):
    token: str
    client_key_shard: str  # hex
    jit_grant_id: str


class BindingCreateRequest(BaseModel):
    vinzy_lease_signature: str
    blind_pass_token: str
    purpose: str = "provisioning"
    sovereignty_ring: str = "us"


class BindingVerifyRequest(BaseModel):
    vinzy_lease_signature: str
    blind_pass_token: str


@router.post("/blind-pass")
async def create_blind_pass(
    body: BlindPassCreateRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.blind_pass import BlindPassService

    svc = BlindPassService(request.app.state.db, request.app.state.settings)
    shard = bytes.fromhex(body.client_key_shard)
    return await svc.create_blind_pass(
        subject_id=body.tenant_id,
        tenant_id=body.tenant_id,
        purpose=body.purpose,
        ttl_seconds=body.ttl_seconds,
        client_key_shard=shard,
        sovereignty_ring=body.sovereignty_ring,
    )


@router.post("/blind-pass/verify")
async def verify_blind_pass(
    body: BlindPassVerifyRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.blind_pass import BlindPassService

    svc = BlindPassService(request.app.state.db, request.app.state.settings)
    return await svc.verify_blind_pass(body.token, body.purpose)


@router.post("/blind-pass/resolve")
async def resolve_blind_pass(
    body: BlindPassResolveRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.blind_pass import BlindPassService

    svc = BlindPassService(request.app.state.db, request.app.state.settings)
    shard = bytes.fromhex(body.client_key_shard)
    subject = await svc.resolve_blind_pass(body.token, shard)
    return {"subject_id": subject}


@router.post("/blind-pass/revoke")
async def revoke_blind_pass_endpoint(
    request: Request,
    caller: str = Depends(get_service_caller),
):
    body = await request.json()
    from zuultimate.vault.blind_pass import BlindPassService

    svc = BlindPassService(request.app.state.db, request.app.state.settings)
    return await svc.revoke_blind_pass(body["token"])


@router.post("/bindings")
async def create_binding(
    body: BindingCreateRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.cross_service import CrossServiceBindingService

    svc = CrossServiceBindingService(request.app.state.db, request.app.state.settings)
    binding_id = await svc.bind(
        body.vinzy_lease_signature,
        body.blind_pass_token,
        body.purpose,
        body.sovereignty_ring,
    )
    return {"binding_id": binding_id}


@router.post("/bindings/verify")
async def verify_binding(
    body: BindingVerifyRequest,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.cross_service import CrossServiceBindingService

    svc = CrossServiceBindingService(request.app.state.db, request.app.state.settings)
    valid = await svc.verify_binding(body.vinzy_lease_signature, body.blind_pass_token)
    return {"valid": valid}


@router.delete("/bindings/{binding_id}")
async def revoke_binding(
    binding_id: str,
    request: Request,
    caller: str = Depends(get_service_caller),
):
    from zuultimate.vault.cross_service import CrossServiceBindingService

    svc = CrossServiceBindingService(request.app.state.db, request.app.state.settings)
    return await svc.revoke_binding(binding_id)
