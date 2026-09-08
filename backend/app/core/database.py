from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import JSON, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB as PGJSONB
from app.core.config import settings


class JSONBType(TypeDecorator):
    """JSONB that works on both PostgreSQL and SQLite (for tests)."""
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PGJSONB())
        return dialect.type_descriptor(JSON())


class Base(DeclarativeBase):
    pass


engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, pool_size=20)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # live tables (alerts, baseline) created lazily; ensure here too for fresh DBs
        try:
            from sqlalchemy import text
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    ts TIMESTAMPTZ DEFAULT NOW(),
                    severity TEXT,
                    title TEXT,
                    five_tuple TEXT,
                    payload JSONB
                )
            """))
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS baseline_features (
                    id SERIAL PRIMARY KEY,
                    ts TIMESTAMPTZ DEFAULT NOW(),
                    features JSONB
                )
            """))
        except Exception:
            pass
