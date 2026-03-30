"""PoP (Point-of-Presence) registry management router."""

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.workforce.models import PopRegistration
from zuultimate.identity.workforce.schemas import PopRegisterRequest, PopResponse

router = APIRouter(
    prefix="/admin/pops", tags=["admin-pops"], responses=STANDARD_ERRORS
)


@router.post("", summary="Register a new PoP", response_model=PopResponse)
async def register_pop(body: PopRegisterRequest, request: Request):
    db = request.app.state.db
    async with db.get_session("identity") as session:
        # Check for duplicate pop_id
        result = await session.execute(
            select(PopRegistration).where(PopRegistration.pop_id == body.pop_id)
        )
        if result.scalar_one_or_none() is not None:
            raise HTTPException(status_code=409, detail="PoP already registered")

        pop = PopRegistration(
            pop_id=body.pop_id,
            pop_name=body.pop_name,
            region=body.region,
            public_key=body.public_key,
            status="active",
        )
        session.add(pop)
        await session.flush()

        return PopResponse(
            id=pop.id,
            pop_id=pop.pop_id,
            pop_name=pop.pop_name,
            region=pop.region,
            status=pop.status,
            registered_at=pop.registered_at,
            last_heartbeat=pop.last_heartbeat,
        )


@router.get("", summary="List registered PoPs", response_model=list[PopResponse])
async def list_pops(request: Request):
    db = request.app.state.db
    async with db.get_session("identity") as session:
        result = await session.execute(select(PopRegistration))
        pops = result.scalars().all()
        return [
            PopResponse(
                id=p.id,
                pop_id=p.pop_id,
                pop_name=p.pop_name,
                region=p.region,
                status=p.status,
                registered_at=p.registered_at,
                last_heartbeat=p.last_heartbeat,
            )
            for p in pops
        ]


@router.delete(
    "/{pop_id}", summary="Deregister a PoP", response_model=PopResponse
)
async def deregister_pop(pop_id: str, request: Request):
    db = request.app.state.db
    async with db.get_session("identity") as session:
        result = await session.execute(
            select(PopRegistration).where(PopRegistration.pop_id == pop_id)
        )
        pop = result.scalar_one_or_none()
        if pop is None:
            raise HTTPException(status_code=404, detail="PoP not found")

        pop.status = "deregistered"

        return PopResponse(
            id=pop.id,
            pop_id=pop.pop_id,
            pop_name=pop.pop_name,
            region=pop.region,
            status=pop.status,
            registered_at=pop.registered_at,
            last_heartbeat=pop.last_heartbeat,
        )
