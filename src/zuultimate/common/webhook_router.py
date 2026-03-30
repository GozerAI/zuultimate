"""Webhook management router."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from zuultimate.common.auth import get_current_user
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.common.webhooks import WebhookService

router = APIRouter(prefix="/webhooks", tags=["webhooks"], responses=STANDARD_ERRORS)


class WebhookCreateRequest(BaseModel):
    url: str = Field(min_length=1)
    events_filter: str = "*"
    secret: str = ""
    description: str = ""


class WebhookResponse(BaseModel):
    id: str
    url: str
    events_filter: str
    is_active: bool
    description: str


def _get_service(request: Request) -> WebhookService:
    return WebhookService(request.app.state.db)


@router.post("", summary="Create webhook", response_model=WebhookResponse)
async def create_webhook(
    body: WebhookCreateRequest,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    return await svc.create_webhook(
        url=body.url,
        events_filter=body.events_filter,
        secret=body.secret,
        description=body.description,
    )


@router.get("", summary="List all webhooks", response_model=list[WebhookResponse])
async def list_webhooks(
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    return await svc.list_webhooks()


@router.delete("/{webhook_id}", summary="Delete webhook")
async def delete_webhook(
    webhook_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    await svc.delete_webhook(webhook_id)
    return {"detail": "Webhook deactivated"}
