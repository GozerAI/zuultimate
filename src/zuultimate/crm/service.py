"""CRM service -- config management, sync jobs."""

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.crm.models import CRMConfig, SyncJob

_DB_KEY = "crm"


class CRMService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_config(self, provider: str, api_url: str = "") -> dict:
        if not provider:
            raise ValidationError("Provider must not be empty")
        async with self.db.get_session(_DB_KEY) as session:
            config = CRMConfig(provider=provider, api_url=api_url)
            session.add(config)
            await session.flush()
        return {
            "id": config.id,
            "provider": config.provider,
            "api_url": config.api_url,
            "is_active": config.is_active,
        }

    async def start_sync(self, config_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(CRMConfig).where(
                    CRMConfig.id == config_id, CRMConfig.is_active == True
                )
            )
            if result.scalar_one_or_none() is None:
                raise NotFoundError("Active CRM config not found")

            job = SyncJob(config_id=config_id, status="pending")
            session.add(job)
            await session.flush()
        return {
            "id": job.id,
            "config_id": job.config_id,
            "status": job.status,
            "records_synced": job.records_synced,
        }

    async def get_sync_status(self, job_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SyncJob).where(SyncJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            if job is None:
                raise NotFoundError("Sync job not found")
        return {
            "id": job.id,
            "config_id": job.config_id,
            "status": job.status,
            "records_synced": job.records_synced,
        }
