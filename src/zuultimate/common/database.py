"""Async database manager for Zuultimate's multi-DB architecture."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from zuultimate.common.config import ZuulSettings, get_settings
from zuultimate.common.models import Base


class DatabaseManager:
    """Manages multiple async database engines keyed by name."""

    DB_KEYS = ("identity", "credential", "session", "transaction", "audit", "crm")

    def __init__(self, settings: ZuulSettings | None = None):
        self._settings = settings or get_settings()
        self.engines: dict[str, AsyncEngine] = {}
        self._session_factories: dict[str, async_sessionmaker[AsyncSession]] = {}

    def _url_for(self, key: str) -> str:
        return getattr(self._settings, f"{key}_db_url")

    async def init(self) -> None:
        for key in self.DB_KEYS:
            url = self._url_for(key)
            engine = create_async_engine(url, echo=False)
            self.engines[key] = engine
            self._session_factories[key] = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def get_session(self, db_name: str) -> AsyncGenerator[AsyncSession, None]:
        factory = self._session_factories[db_name]
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def create_all(self) -> None:
        for engine in self.engines.values():
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

    async def close_all(self) -> None:
        for engine in self.engines.values():
            await engine.dispose()
        self.engines.clear()
        self._session_factories.clear()
