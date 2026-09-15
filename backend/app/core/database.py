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
    await _seed_auth()


async def _seed_auth():
    """Create default org + bootstrap admin on first boot (idempotent).

    Production MUST override CIPHERPOST_ADMIN_PASSWORD and CIPHERPOST_JWT_SECRET.
    """
    import logging
    import uuid
    log = logging.getLogger("cipherpost.auth.seed")
    try:
        from app.models.entities import Organization, User, UserRole
        from app.core.auth import hash_password
        async with async_session() as session:
            from sqlalchemy import select
            org = (await session.execute(
                select(Organization).where(
                    Organization.name == settings.DEFAULT_ORG_NAME))).scalars().first()
            if org is None:
                org = Organization(id="org-" + uuid.uuid4().hex[:12],
                                   name=settings.DEFAULT_ORG_NAME)
                session.add(org)
                await session.commit()
            admin = (await session.execute(
                select(User).where(User.email == settings.ADMIN_EMAIL))).scalars().first()
            if admin is None:
                session.add(User(
                    id="user-" + uuid.uuid4().hex[:12],
                    org_id=org.id, email=settings.ADMIN_EMAIL,
                    password_hash=hash_password(settings.ADMIN_PASSWORD),
                    role=UserRole.ADMIN, is_active=True,
                ))
                await session.commit()
                log.warning("bootstrap admin created (%s) — change the password immediately",
                            settings.ADMIN_EMAIL)
        if (settings.JWT_SECRET or "") in ("", "change-me-in-production"):
            log.warning("CIPHERPOST_JWT_SECRET is not set — tokens use a dev-only secret")
        # Backfill pre-auth rows into the default org so tenant scoping is total.
        try:
            from sqlalchemy import text as _text
            async with async_session() as session:
                async with session.begin():
                    await session.execute(_text(
                        "UPDATE analysis_jobs SET org_id = :oid "
                        "WHERE org_id IS NULL"), {"oid": org.id})
                    await session.execute(_text(
                        "UPDATE sessions SET org_id = :oid "
                        "WHERE org_id IS NULL"), {"oid": org.id})
                    try:
                        await session.execute(_text(
                            "UPDATE alerts SET org_id = :oid "
                            "WHERE org_id IS NULL"), {"oid": org.id})
                    except Exception:
                        pass  # alerts table may not exist yet on some backends
        except Exception as e:
            log.warning("org backfill skipped: %s", e)
    except Exception as e:
        logging.getLogger("cipherpost.auth.seed").warning("auth seed skipped: %s", e)
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
                    payload JSONB,
                    org_id TEXT
                )
            """))
            try:
                await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS org_id TEXT"))
            except Exception:
                pass
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS baseline_features (
                    id SERIAL PRIMARY KEY,
                    ts TIMESTAMPTZ DEFAULT NOW(),
                    features JSONB
                )
            """))
        except Exception:
            pass
