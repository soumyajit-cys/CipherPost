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

    # --- live acquisition (stage 2+) ----------------------------------------
    LIVE_IFACE: str = "lo"                     # SPAN/TAP-fed interface (promiscuous)
    LIVE_PROMISC: bool = True
    LIVE_BPF_PORTS: str = "25,587,465,110,995,143,993"
    LIVE_EXTRA_PORTS: str = ""                 # comma-separated, appended to BPF filter
    LIVE_MAX_SESSIONS: int = 4096              # concurrent tracked sessions cap
    LIVE_MAX_SESSION_BUFFER_BYTES: int = 512 * 1024  # per-half-stream cap
    LIVE_IDLE_TIMEOUT: float = 60.0            # seconds of silence → finalize session
    LIVE_DRAIN_INTERVAL: float = 1.0           # closed-session drain sweep period
    LIVE_SNIFF_BATCH: int = 200                # packets processed per sniff chunk
    RAW_CAPTURE_DIR: Path = Path("/data/capture")
    RAW_RETENTION_SECONDS: int = 6 * 3600      # rolling raw-capture window
    RAW_SEGMENT_SECONDS: int = 300             # time-chunked segment file length
    LIVE_REPLAY_SPEED: float = 0.0             # 0 = as fast as possible (replay mode)
    SESSION_STREAM: str = "cipherpost:sessions"
    FINDINGS_STREAM: str = "cipherpost:findings"
    ALERT_STREAM: str = "cipherpost:alerts"
    LIVE_PUBSUB_PREFIX: str = "cipherpost:live"
    LIVE_JOB_TAG: str = "live"                 # DB job tag for live-ingested sessions
    CAPTURE_DROP_SAMPLING: bool = True         # drop new sessions when over cap w/ logging
    ANALYSIS_CONSUMER_GROUP: str = "analysis-workers"
    ALERT_CONSUMER_GROUP: str = "alert-workers"

    # --- alerting (stage 5) ---------------------------------------------------
    ALERT_MIN_SEVERITY: str = "high"           # findings below this are not dispatched
    ALERT_DEDUP_WINDOW_SECONDS: int = 300      # per-rule-id dedup window
    ALERT_RATE_LIMIT_PER_MINUTE: int = 60
    ALERT_WEBHOOK_URL: Optional[str] = None
    ALERT_SLACK_URL: Optional[str] = None
    ALERT_CEF_SYSLOG_HOST: Optional[str] = None
    ALERT_CEF_SYSLOG_PORT: int = 514
    ALERT_EMAIL_SMTP_HOST: Optional[str] = None
    ALERT_EMAIL_SMTP_PORT: int = 25
    ALERT_EMAIL_FROM: str = "cipherpost@localhost"
    ALERT_EMAIL_TO: str = ""
    ALERT_CHANNEL_CONFIG_PATH: Path = Path("/data/alert_channels.json")

    # --- rolling fleet baseline (stage 4) --------------------------------------
    FLEET_BASELINE_WINDOW_DAYS: int = 7
    FLEET_BASELINE_MIN_SAMPLES: int = 20
    FLEET_BASELINE_REFIT_EVERY: int = 200      # session count between refits
    FLEET_ANOMALY_CONTAMINATION: float = 0.1

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
settings.RAW_CAPTURE_DIR = _ensure_dir(settings.RAW_CAPTURE_DIR)
