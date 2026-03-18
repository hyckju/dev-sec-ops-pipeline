import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ── 프로젝트 모듈 ──────────────────────────────────────────────────────────────
from app.core.config import settings
from app.db.base import Base  # noqa: F401

# 모든 ORM 모델을 import 해서 Base.metadata 에 등록시킨다.
from app.db.models import project, pipeline, vulnerability, report  # noqa: F401

# ── Alembic Config 객체 ────────────────────────────────────────────────────────
config = context.config

# alembic.ini 의 로깅 설정을 적용한다.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 자동 마이그레이션 대상 메타데이터
target_metadata = Base.metadata

# DATABASE_URL 을 settings 에서 주입한다.
# alembic.ini 의 sqlalchemy.url = %(DATABASE_URL)s 를 덮어쓴다.
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)


# ── 오프라인 마이그레이션 (DB 연결 없이 SQL 출력) ─────────────────────────────
def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ── 온라인 마이그레이션 (실제 DB 연결) ────────────────────────────────────────
def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations within a proper context."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


# ── 엔트리포인트 ───────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
