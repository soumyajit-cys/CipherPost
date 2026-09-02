from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "CipherPost"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://cipherpost:cipherpost@db:5432/cipherpost"
    DATABASE_URL_SYNC: str = "postgresql+psycopg2://cipherpost:cipherpost@db:5432/cipherpost"
    REDIS_URL: str = "redis://redis:6379/0"

    UPLOAD_DIR: Path = Path("/data/uploads")
    REPORTS_DIR: Path = Path("/data/reports")
    BLOB_DIR: Path = Path("/data/blobs")
    MODELS_DIR: Path = Path("/data/models")

    MAX_UPLOAD_SIZE_MB: int = 500
    CELERY_BROKER_URL: str = "redis://redis:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/0"

    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    TRUSTED_CA_BUNDLE_PATH: Optional[str] = None

    class Config:
        env_prefix = "CIPHERPOST_"
        env_file = ".env"


settings = Settings()

_local_data = Path(__file__).resolve().parents[3] / "data"


def _ensure_dir(p: Path) -> Path:
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".write_test"
        probe.write_text("x")
        probe.unlink()
        return p
    except Exception:
        p = _local_data / p.parts[-1]
        p.mkdir(parents=True, exist_ok=True)
        return p


settings.UPLOAD_DIR = _ensure_dir(settings.UPLOAD_DIR)
settings.REPORTS_DIR = _ensure_dir(settings.REPORTS_DIR)
settings.BLOB_DIR = _ensure_dir(settings.BLOB_DIR)
settings.MODELS_DIR = _ensure_dir(settings.MODELS_DIR)
