"""Alembic environment configuration.

Zuultimate uses 6 separate SQLite databases. This Alembic configuration
tracks ALL model metadata via a shared Base.metadata so auto-generation
captures every table. At migration time, Alembic operates against a single
database URL (set in alembic.ini or via -x sqlalchemy.url=...).

For multi-DB deployments, run migrations per database:
    alembic -x sqlalchemy.url=sqlite:///data/identity.db upgrade head
    alembic -x sqlalchemy.url=sqlite:///data/credential.db upgrade head
    ...
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import Base with all model metadata
from zuultimate.common.models import Base

# Import all models so they register with Base.metadata
import zuultimate.identity.models  # noqa: F401
import zuultimate.identity.phase2_models  # noqa: F401
import zuultimate.access.models  # noqa: F401
import zuultimate.vault.models  # noqa: F401
import zuultimate.pos.models  # noqa: F401
import zuultimate.crm.models  # noqa: F401
import zuultimate.backup_resilience.models  # noqa: F401
import zuultimate.ai_security.models  # noqa: F401

config = context.config

# Allow CLI override: alembic -x sqlalchemy.url=... upgrade head
cmd_url = context.get_x_argument(as_dictionary=True).get("sqlalchemy.url")
if cmd_url:
    config.set_main_option("sqlalchemy.url", cmd_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
