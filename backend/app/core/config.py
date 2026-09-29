from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "CipherPost"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    # Deployment environment: "dev" relaxes secret checks (ephemeral secret +
    # loud warning); "production" (default) refuses to start with weak secrets.
    ENV: str = "production"

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

    # --- auth / tenancy (track 1) -------------------------------------------
    AUTH_REQUIRED: bool = True  # set False only for isolated demo environments
    JWT_SECRET: str = "change-me-in-production"
    JWT_EXPIRY_SECONDS: int = 86400
    ADMIN_EMAIL: str = "admin@cipherpost.local"
    ADMIN_PASSWORD: str = "change-me-on-first-login"
    DEFAULT_ORG_NAME: str = "default"

    # --- http surface ---------------------------------------------------------
    # Comma-separated allowlist for CORS. Empty = same-origin only (no CORS
    # headers). Never use "*" with credentials in production.
    CORS_ORIGINS: str = ""

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

    # --- reliable streams (phase 2) -----------------------------------------
    STREAM_MAX_ATTEMPTS: int = 5  # deliveries before dead-letter
    STREAM_IDLE_RECLAIM_MS: int = 60_000  # XAUTOCLAIM idle threshold
    STREAM_DLQ_SUFFIX: str = ":dlq"  # dead-letter stream suffix
    STREAM_RECLAIM_BATCH: int = 16
    # Capture publisher resilience: bounded buffer + backoff, never block sniff.
    CAPTURE_PUBLISH_BUFFER: int = 512  # max queued sessions when Redis down
    CAPTURE_PUBLISH_RETRIES: int = 5
    CAPTURE_PUBLISH_BACKOFF_MS: int = 200  # base, exponential + jitter
    CAPTURE_PUBLISH_BACKOFF_MAX_MS: int = 5_000

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

    # --- SIEM (track 4: Splunk HEC) -------------------------------------------
    SPLUNK_HEC_URL: Optional[str] = None
    SPLUNK_HEC_TOKEN: str = ""
    SPLUNK_HEC_INDEX: str = ""
    SPLUNK_HEC_SOURCETYPE: str = "cipherpost:alert"

    # --- ticketing (track 4) ----------------------------------------------------
    TICKETING_ENABLED: bool = False
    TICKET_MIN_SEVERITY: str = "critical"
    JIRA_URL: Optional[str] = None  # e.g. https://your.atlassian.net
    JIRA_EMAIL: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT: str = ""
    JIRA_ISSUE_TYPE: str = "Task"

    # --- capture agents (track 3) ---------------------------------------------
    AGENT_ID: str = ""  # default: <hostname>/<iface>
    AGENT_HEARTBEAT_SECONDS: float = 10.0
    AGENT_TTL_SECONDS: float = 30.0

    # --- proactive detection (track 2) ----------------------------------------
    CERT_EXPIRY_WARN_DAYS: int = 30  # forecast horizon for expiry alerts
    CERT_EXPIRY_CHECK_INTERVAL_SECONDS: int = 900  # alerter sweep cadence
    DNS_RESOLVER: Optional[str] = None  # e.g. "8.8.8.8"; unset = MTA-STS/DANE stay stubbed

    # --- rolling fleet baseline (stage 4) --------------------------------------
    FLEET_BASELINE_WINDOW_DAYS: int = 7
    FLEET_BASELINE_MIN_SAMPLES: int = 20
    FLEET_BASELINE_REFIT_EVERY: int = 200      # session count between refits
    FLEET_ANOMALY_CONTAMINATION: float = 0.1

    # --- ML maturity (track 5) --------------------------------------------------
    DRIFT_Z_THRESHOLD: float = 3.0
    DRIFT_MIN_FEATURES: int = 3

    class Config:
        env_prefix = "CIPHERPOST_"
        env_file = ".env"

    def is_dev(self) -> bool:
        return (self.ENV or "").strip().lower() == "dev"

    def cors_origins_list(self) -> list[str]:
        raw = (self.CORS_ORIGINS or "").strip()
        if not raw:
            return []
        return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


# Known placeholder / default secrets that must never be used in production.
_KNOWN_JWT_DEFAULTS = {
    "",
    "change-me-in-production",
    "changeme-long-random-64-chars-minimum",
    "changeme-long-random-64-chars",
    "changeme",
    "change-me-on-first-login",
    "cipherpost-dev-only-secret",
}


def _norm(v: str | None) -> str:
    return (v or "").strip()


def is_default_jwt_secret(secret: str | None) -> bool:
    s = _norm(secret)
    if not s:
        return True
    low = s.lower()
    if low in _KNOWN_JWT_DEFAULTS:
        return True
    if "changeme" in low or "change-me" in low:
        return True
    return False


def is_default_admin_password(pw: str | None) -> bool:
    s = _norm(pw)
    if not s:
        return True
    low = s.lower()
    if low in {"", "change-me-on-first-login", "changeme-on-first-login", "changeme"}:
        return True
    if "changeme" in low or "change-me" in low:
        return True
    return False


def validate_startup_secrets(cfg: "Settings | None" = None) -> None:
    """Refuse to start in production with weak/missing secrets.

    Raises RuntimeError with a clear message. In dev mode returns silently
    (auth uses an ephemeral random secret + loud warning instead).
    """
    s = cfg or settings
    if s.is_dev():
        return
    problems: list[str] = []
    jwt_secret = _norm(s.JWT_SECRET)
    if is_default_jwt_secret(jwt_secret):
        problems.append(
            "CIPHERPOST_JWT_SECRET is missing or a known default "
            "(unset / change-me / CHANGEME). Set a long random value."
        )
    elif len(jwt_secret.encode()) < 32:
        problems.append(
            "CIPHERPOST_JWT_SECRET must be at least 32 bytes "
            f"(got {len(jwt_secret.encode())}). Generate with e.g. "
            "`openssl rand -hex 32`."
        )
    admin_pw = _norm(s.ADMIN_PASSWORD)
    if is_default_admin_password(admin_pw):
        problems.append(
            "CIPHERPOST_ADMIN_PASSWORD is a known default "
            "(change-me / CHANGEME). Set a strong bootstrap password."
        )
    elif len(admin_pw) < 12:
        problems.append(
            "CIPHERPOST_ADMIN_PASSWORD must be at least 12 characters "
            f"(got {len(admin_pw)})."
        )
    if (s.ENV or "").strip().lower() not in ("dev", "production"):
        problems.append(
            f"CIPHERPOST_ENV must be 'dev' or 'production' (got {s.ENV!r})."
        )
    if problems:
        raise RuntimeError("Refusing to start in production: " + " ".join(problems))


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
