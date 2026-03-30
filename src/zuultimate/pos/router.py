"""POS router -- terminals, transactions, fraud alerts."""

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.common.idempotency import IdempotencyService
from zuultimate.common.pagination import paginate_list
from zuultimate.common.redis import RedisManager
from zuultimate.common.schemas import PaginatedResponse
from zuultimate.pos.schemas import (
    FraudAlertResponse,
    TerminalCreate,
    TerminalResponse,
    TransactionCreate,
    TransactionResponse,
)
from zuultimate.pos.service import POSService

router = APIRouter(
    prefix="/pos",
    tags=["pos"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> POSService:
    return POSService(request.app.state.db)


@router.post("/terminals", summary="Register POS terminal", response_model=TerminalResponse)
async def register_terminal(body: TerminalCreate, request: Request):
    svc = _get_service(request)
    try:
        return await svc.register_terminal(
            name=body.name, location=body.location, device_type=body.device_type
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/transactions", summary="Create POS transaction", response_model=TransactionResponse)
async def create_transaction(
    body: TransactionCreate,
    request: Request,
    x_idempotency_key: str | None = Header(default=None),
):
    # Check for cached idempotent response (Redis first, then DB)
    redis: RedisManager = request.app.state.redis
    if x_idempotency_key:
        cached = await redis.get_idempotency(x_idempotency_key)
        if cached is None:
            idem_svc = IdempotencyService(request.app.state.db)
            cached = await idem_svc.get_cached(x_idempotency_key)
        if cached is not None:
            return JSONResponse(
                status_code=cached["status_code"], content=cached["body"]
            )

    svc = _get_service(request)
    try:
        result = await svc.create_transaction(
            terminal_id=body.terminal_id, amount=body.amount, currency=body.currency
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    # Store idempotent response (Redis + DB for durability)
    if x_idempotency_key:
        await redis.store_idempotency(x_idempotency_key, 200, result)
        idem_svc = IdempotencyService(request.app.state.db)
        await idem_svc.store(
            x_idempotency_key, "/v1/pos/transactions", 200, result
        )

    return result


@router.post("/settlements/{terminal_id}", summary="Settle terminal transactions")
async def create_settlement(terminal_id: str, request: Request):
    svc = _get_service(request)
    try:
        return await svc.create_settlement(terminal_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/settlements/{settlement_id}", summary="Get settlement details")
async def get_settlement(settlement_id: str, request: Request):
    svc = _get_service(request)
    try:
        return await svc.get_settlement(settlement_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/reconcile/{terminal_id}", summary="Reconcile terminal ledger")
async def reconcile(terminal_id: str, request: Request):
    svc = _get_service(request)
    return await svc.reconcile(terminal_id)


@router.get("/fraud-alerts", summary="List fraud alerts", response_model=PaginatedResponse[FraudAlertResponse])
async def get_fraud_alerts(
    request: Request,
    resolved: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    svc = _get_service(request)
    try:
        alerts = await svc.get_fraud_alerts(resolved=resolved)
        return paginate_list(alerts, page=page, page_size=page_size)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
