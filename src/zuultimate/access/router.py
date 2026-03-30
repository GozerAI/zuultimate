"""Access control router -- policy evaluation, role assignment."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.access.schemas import (
    AccessCheckRequest,
    AccessCheckResponse,
    PolicyResponse,
    PolicySchema,
    RoleAssignRequest,
    RoleAssignResponse,
)
from zuultimate.access.service import AccessService
from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS

router = APIRouter(
    prefix="/access",
    tags=["access"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> AccessService:
    return AccessService(request.app.state.db)


@router.post("/check", summary="Check access permission", response_model=AccessCheckResponse)
async def check_access(body: AccessCheckRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.check_access(
            user_id=body.user_id, resource=body.resource, action=body.action
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/policies", summary="Create access policy", response_model=PolicyResponse)
async def create_policy(body: PolicySchema, request: Request):
    svc = _get_service(request)
    try:
        return await svc.create_policy(
            name=body.name,
            effect=body.effect,
            resource_pattern=body.resource_pattern,
            action_pattern=body.action_pattern,
            priority=body.priority,
            role_id=body.role_id,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/roles/assign", summary="Assign role to user", response_model=RoleAssignResponse)
async def assign_role(body: RoleAssignRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.assign_role(
            role_id=body.role_id,
            user_id=body.user_id,
            assigned_by=body.assigned_by,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
