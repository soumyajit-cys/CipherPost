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
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.BLOB_DIR.mkdir(parents=True, exist_ok=True)
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
