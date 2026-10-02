"""
Alert dispatcher: consumes findings stream, applies threshold/dedup/rate-limit,
dispatches via pluggable adapters (webhook base, slack, syslog CEF, email stub).

Runs as a long-lived worker. Also exposes channel config load/save.
"""
from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

import redis
import httpx

from app.core.config import settings
from app.live import streams as bus
from app.live.metrics import Gossiper

log = logging.getLogger("cipherpost.live.alerts")

SEV_ORDER = {"info":0, "low":1, "medium":2, "high":3, "critical":4}

class AlertAdapter(ABC):
    name: str = "base"
    @abstractmethod
    def send(self, alert: dict) -> bool:
        ...

class WebhookAdapter(AlertAdapter):
    name = "webhook"
    def __init__(self, url: str, timeout: float = 5):
        self.url = url
        self.timeout = timeout
    def send(self, alert: dict) -> bool:
        try:
            r = httpx.post(self.url, json=alert, timeout=self.timeout)
            return r.status_code < 300
        except Exception as e:
            log.warning("webhook send failed: %s", e)
            return False

class SlackAdapter(AlertAdapter):
    name = "slack"
    def __init__(self, webhook_url: str):
        self.url = webhook_url
    def send(self, alert: dict) -> bool:
        text = f":warning: *{alert.get('title','CipherPost alert')}* ({alert.get('severity','unknown')})\\n{alert.get('description','')}\\n`{alert.get('five_tuple','')}` risk={alert.get('risk_score')}"
        try:
            r = httpx.post(self.url, json={"text": text}, timeout=5)
            return r.status_code < 300
        except Exception as e:
            log.warning("slack send failed: %s", e)
            return False

class SyslogCefAdapter(AlertAdapter):
    name = "syslog-cef"
    def __init__(self, host: str, port: int = 514):
        self.host = host; self.port = port
    def send(self, alert: dict) -> bool:
        # CEF: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        sev_map = {"critical":10, "high":8, "medium":5, "low":3, "info":1}
        sev = sev_map.get(alert.get("severity","info"), 1)
        line = f"CEF:0|CipherPost|CipherPost|1.0|{alert.get('rule_id','unknown')}|{alert.get('title','finding')}|{sev}|msg={alert.get('description','')} dhost={alert.get('five_tuple','')} cs1={alert.get('protocol','')}"
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(line.encode(), (self.host, self.port))
            sock.close()
            return True
        except Exception as e:
            log.warning("syslog send failed: %s", e)
            return False

class SplunkHECAdapter(AlertAdapter):
    """Splunk HTTP Event Collector: documented SIEM path (track 4).

    Configure SPLUNK_HEC_URL (e.g. https://splunk:8088/services/collector),
    SPLUNK_HEC_TOKEN, optionally SPLUNK_HEC_INDEX / SOURCETYPE.
    """
    name = "splunk-hec"

    def __init__(self, url: str, token: str, index: str = "",
                 sourcetype: str = "cipherpost:alert", verify: bool = True):
        self.url = url.rstrip("/")
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.verify = verify

    def send(self, alert: dict) -> bool:
        event = {"time": alert.get("ts"), "source": "cipherpost",
                 "sourcetype": self.sourcetype, "event": alert}
        if self.index:
            event["index"] = self.index
        try:
            r = httpx.post(self.url, json=event,
                           headers={"Authorization": f"Splunk {self.token}"},
                           timeout=5, verify=self.verify)
            return r.status_code < 300
        except Exception as e:
            log.warning("splunk hec send failed: %s", e)
            return False


class EmailAdapter(AlertAdapter):
    name = "email"
    def __init__(self, host: str, port: int, frm: str, to: str):
        self.host=host; self.port=port; self.frm=frm; self.to=to
    def send(self, alert: dict) -> bool:
        if not self.to:
            return False
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"]=self.frm; msg["To"]=self.to; msg["Subject"]=f"[CipherPost] {alert.get('severity','')} {alert.get('title','')}"
        msg.set_content(json.dumps(alert, indent=2))
        try:
            with smtplib.SMTP(self.host, self.port, timeout=5) as s:
                s.send_message(msg)
            return True
        except Exception as e:
            log.warning("email send failed: %s", e)
            return False

def load_channels() -> list[AlertAdapter]:
    adapters: list[AlertAdapter] = []
    cfg_path = Path(settings.ALERT_CHANNEL_CONFIG_PATH)
    cfg = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            pass
    # env overrides
    webhook = cfg.get("webhook_url") or settings.ALERT_WEBHOOK_URL
    if webhook:
        adapters.append(WebhookAdapter(webhook))
    slack = cfg.get("slack_url") or settings.ALERT_SLACK_URL
    if slack:
        adapters.append(SlackAdapter(slack))
    cef_host = cfg.get("cef_host") or settings.ALERT_CEF_SYSLOG_HOST
    if cef_host:
        adapters.append(SyslogCefAdapter(cef_host, int(cfg.get("cef_port", settings.ALERT_CEF_SYSLOG_PORT))))
    email_host = cfg.get("email_host") or settings.ALERT_EMAIL_SMTP_HOST
    if email_host:
        adapters.append(EmailAdapter(email_host, int(cfg.get("email_port", settings.ALERT_EMAIL_SMTP_PORT)), cfg.get("email_from", settings.ALERT_EMAIL_FROM), cfg.get("email_to", settings.ALERT_EMAIL_TO)))
    splunk_url = cfg.get("splunk_hec_url") or settings.SPLUNK_HEC_URL
    if splunk_url:
        adapters.append(SplunkHECAdapter(
            splunk_url, cfg.get("splunk_hec_token") or settings.SPLUNK_HEC_TOKEN,
            index=cfg.get("splunk_hec_index") or settings.SPLUNK_HEC_INDEX,
            sourcetype=cfg.get("splunk_hec_sourcetype") or settings.SPLUNK_HEC_SOURCETYPE))
    return adapters

def save_channel_config(cfg: dict):
    p = Path(settings.ALERT_CHANNEL_CONFIG_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))

class AlertDispatcher:
    def __init__(self, redis_client=None, adapters: list[AlertAdapter] | None = None,
                 group_hold_seconds: float = 10.0):
        from app.live.alert_state import RedisAlertState, GroupBuffer
        self.r = redis_client or redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        self.adapters = adapters if adapters is not None else load_channels()
        self.gossip = Gossiper(self.r, "alerts", interval=5)
        self._stop = threading.Event()
        self.state = RedisAlertState(self.r, settings.ALERT_DEDUP_WINDOW_SECONDS,
                                     settings.ALERT_RATE_LIMIT_PER_MINUTE)
        self.groups = GroupBuffer(hold_seconds=group_hold_seconds)
        # Legacy in-memory maps kept as the Redis-unavailable fallback lives
        # inside RedisAlertState; these remain for ticketing dedup compat.
        self._dedup: dict[str, float] = {}  # key -> last_ts
        self._rate_window: list[float] = []
        self.consumer = bus.StreamConsumer(self.r, settings.FINDINGS_STREAM, settings.ALERT_CONSUMER_GROUP, f"alerter-{uuid.uuid4().hex[:6]}")
        self.min_sev = SEV_ORDER.get(settings.ALERT_MIN_SEVERITY, 3)
        self._ticketing = None
        self._ticketing_tried = False

    def _signal(self, s, f):
        self._stop.set()

    def _should_alert(self, finding: dict) -> bool:
        sev = finding.get("max_severity") or finding.get("severity") or "info"
        threshold = self.min_sev
        try:
            policy = self._policy_for(finding.get("org_id"))
            threshold = SEV_ORDER.get(policy.get("min_severity", ""), threshold)
        except Exception:
            pass
        if SEV_ORDER.get(sev, 0) < threshold:
            return False
        return True

    # -- phase 4 task 5: ownership routing, per-org policy, digest, quiet hours
    _policy_cache: dict = {}
    _routes_cache: dict = {}

    def _policy_for(self, org_id: str | None) -> dict:
        """Per-org alert policy (cached 60 s); defaults when absent."""
        now = time.time()
        entry = self._policy_cache.get(org_id)
        if entry is not None and now - entry[0] < 60:
            return entry[1]
        policy = {"min_severity": settings.ALERT_MIN_SEVERITY,
                  "digest": "off", "quiet_start_hour": None,
                  "quiet_end_hour": None, "quiet_tz": "UTC"}
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from app.models.entities import AlertPolicy
            engine = create_engine(settings.DATABASE_URL_SYNC)
            db = sessionmaker(bind=engine)()
            try:
                row = db.get(AlertPolicy, org_id) if org_id else None
                if row is not None:
                    policy.update({"min_severity": row.min_severity or policy["min_severity"],
                                   "digest": row.digest or "off",
                                   "quiet_start_hour": row.quiet_start_hour,
                                   "quiet_end_hour": row.quiet_end_hour,
                                   "quiet_tz": row.quiet_tz or "UTC"})
            finally:
                db.close()
        except Exception as e:
            log.debug("policy load skipped: %s", e)
        self._policy_cache[org_id] = (now, policy)
        return policy

    def _routes_for(self, org_id: str | None) -> list[dict]:
        now = time.time()
        entry = self._routes_cache.get(org_id)
        if entry is not None and now - entry[0] < 60:
            return entry[1]
        routes: list[dict] = []
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from app.models.entities import AlertRoute
            engine = create_engine(settings.DATABASE_URL_SYNC)
            db = sessionmaker(bind=engine)()
            try:
                for r in db.query(AlertRoute).filter(
                        AlertRoute.org_id == org_id).all():
                    routes.append({"match_type": r.match_type,
                                   "match_value": r.match_value,
                                   "owner": r.owner, "channel": r.channel})
            finally:
                db.close()
        except Exception as e:
            log.debug("routes load skipped: %s", e)
        self._routes_cache[org_id] = (now, routes)
        return routes

    def _route_finding(self, finding: dict) -> dict:
        """Most specific route wins (domain > host > rule); never suppresses."""
        import fnmatch as _fn
        routes = self._routes_for(finding.get("org_id"))
        hosts = [finding.get("server") or ""]
        ft = finding.get("five_tuple") or ""
        if ft:
            from app.parsing.reassembly import split_five_tuple as _split
            _, _, server, _ = _split(ft)
            hosts.append(server)
        domains = [finding.get("sni") or ""]
        for specificity, mtype in (("domain", "domain"), ("host", "host"),
                                   ("rule", "rule")):
            _ = specificity
            for r in routes:
                if r["match_type"] != mtype:
                    continue
                if mtype == "rule" and r["match_value"] == finding.get("rule_id"):
                    return {"owner": r["owner"], "channel": r["channel"]}
                if mtype == "host" and any(r["match_value"] == h for h in hosts if h):
                    return {"owner": r["owner"], "channel": r["channel"]}
                if mtype == "domain" and any(
                        _fn.fnmatchcase((d or "").lower(), r["match_value"].lower())
                        for d in domains if d):
                    return {"owner": r["owner"], "channel": r["channel"]}
        return {}

    def _in_quiet(self, policy: dict, now: float | None = None) -> bool:
        start, end = policy.get("quiet_start_hour"), policy.get("quiet_end_hour")
        if start is None or end is None or start == end:
            return False
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(policy.get("quiet_tz") or "UTC")
        except Exception:
            tz = None
        import datetime as _dt
        hour = _dt.datetime.fromtimestamp(now or time.time(), tz).hour if tz else \
            _dt.datetime.utcfromtimestamp(now or time.time()).hour
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end  # overnight window

    def _digest_bucket(self, org_id: str | None, period: str) -> str:
        return f"digest:{org_id or 'none'}:{period}"

    def _current_period(self, digest: str, now: float | None = None) -> str:
        import datetime as _dt
        ts = _dt.datetime.fromtimestamp(now or time.time(), _dt.timezone.utc)
        if digest == "weekly":
            iso = ts.isocalendar()
            return f"{iso[0]}-W{iso[1]:02d}"
        return ts.strftime("%Y-%m-%d")

    def _stash_digest(self, finding: dict, org_id: str | None, period: str,
                      bucket: str = "digest") -> None:
        import json as _jj
        if bucket == "digest":
            key = self._digest_bucket(org_id, self._current_period(
                "daily" if period in ("daily", "off") else "weekly"))
        else:
            key = f"quiet:{org_id or 'none'}"
        try:
            raw = self.r.get(key)
            items = _jj.loads(raw) if raw else []
        except Exception:
            items = []
        items.append({"rule_id": finding.get("rule_id"),
                      "severity": finding.get("max_severity") or finding.get("severity"),
                      "title": finding.get("title"),
                      "five_tuple": finding.get("five_tuple"),
                      "ts": finding.get("ts", time.time())})
        if len(items) > 200:
            items = items[-200:]
            try:
                self.gossip.counters.inc("digest_dropped")
            except Exception:
                pass
        try:
            self.r.setex(key, 8 * 86400, _jj.dumps(items))
            self.r.sadd("digest:orgs", org_id or "none")
        except Exception as e:
            log.debug("digest stash skipped: %s", e)

    def _flush_digests(self, now: float | None = None) -> int:
        """Emit due digest summaries (schedule rollover) and quiet-held items
        once quiet hours end. Critical alerts never enter buckets."""
        import json as _jj
        now = now if now is not None else time.time()
        flushed = 0
        try:
            orgs = [o.decode() if isinstance(o, bytes) else o
                    for o in (self.r.smembers("digest:orgs") or [])]
        except Exception:
            orgs = []
        for org in orgs:
            org_id = None if org == "none" else org
            policy = self._policy_for(org_id)
            digest = policy.get("digest", "off")
            buckets = []
            if digest in ("daily", "weekly"):
                # Yesterday's / last week's bucket is due once the period turns.
                current = self._current_period(digest, now)
                buckets.append((f"digest:{org}:{current}", False))
                prev = self._current_period(digest, now - 86400)
                if prev != current:
                    buckets.append((f"digest:{org}:{prev}", True))
            # Quiet-held items flush when quiet ends.
            buckets.append((f"quiet:{org}", not self._in_quiet(policy, now)))
            for bkey, due in buckets:
                if not due:
                    continue
                try:
                    raw = self.r.get(bkey)
                except Exception:
                    continue
                if not raw:
                    continue
                try:
                    items = _jj.loads(raw)
                except Exception:
                    items = []
                try:
                    self.r.delete(bkey)
                except Exception:
                    pass
                if items:
                    self._dispatch_digest(org_id, items)
                    flushed += 1
        return flushed

    def _dispatch_digest(self, org_id: str | None, items: list[dict]) -> None:
        from collections import Counter
        counts = Counter(i.get("rule_id", "?") for i in items)
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        top_sev = max((i.get("severity", "info") for i in items),
                      key=lambda s: order.get(s, 0), default="info")
        summary = ", ".join(f"{rule} x{n}" for rule, n in counts.most_common(8))
        self._dispatch({
            "rule_id": "digest-summary",
            "severity": top_sev,
            "title": f"Alert digest: {len(items)} findings ({summary})",
            "description": (" Rolled-up non-critical findings for the period. "
                            "Critical alerts always bypass digests and quiet hours."),
            "five_tuple": "",
            "protocol": "",
            "org_id": org_id,
            "risk_score": None,
            "findings": [],
        })

    _sup_cache: dict = {}

    def _suppressed(self, finding: dict) -> bool:
        """True when an active suppression covers this finding (cached 60s)."""
        try:
            from app.proactive.suppressions import match_suppression, filter_active
            org = finding.get("org_id")
            now = time.time()
            key = f"sup:{org}"
            entry = self._sup_cache.get(key)
            if entry is None or now - entry[0] > 60:
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                from app.models.entities import Suppression
                engine = create_engine(settings.DATABASE_URL_SYNC)
                db = sessionmaker(bind=engine)()
                try:
                    rows = db.query(Suppression).filter(
                        Suppression.org_id == org,
                        Suppression.status == "approved").all()
                    entry = (now, filter_active(rows))
                    self._sup_cache[key] = entry
                finally:
                    db.close()
            _, active = entry
            rule = finding.get("rule_id") or ""
            return match_suppression(rule, finding, active) is not None
        except Exception as e:
            log.debug("suppression check skipped: %s", e)
            return False

    def _dispatch(self, finding: dict):
        """Dispatch one finding. Dedup + rate budget are shared via Redis so a
        restart or a second replica cannot double-alert. Each channel is tried
        independently with one retry; per-channel status is recorded in
        Postgres (alert_deliveries) and failures never block other channels."""
        from app.live.alert_state import group_key_of
        # Severity gate only; grouping/dedup handled below via shared state.
        sev = finding.get("max_severity") or finding.get("severity") or "info"
        if SEV_ORDER.get(sev, 0) < self.min_sev:
            return
        dedup_key = group_key_of(finding)
        if not self.state.check_and_set_dedup(dedup_key):
            try:
                self.gossip.counters.inc("alerts_deduped")
            except Exception:
                pass
            return
        if not self.state.check_rate():
            try:
                self.gossip.counters.inc("alerts_rate_limited")
            except Exception:
                pass
            return
        # build alert object (grouped fields default to single occurrence;
        # GroupBuffer flush path fills occurrence_count/first/last_seen)
        alert = {
            "id": uuid.uuid4().hex,
            "ts": time.time(),
            "five_tuple": finding.get("five_tuple"),
            "protocol": finding.get("protocol"),
            "severity": finding.get("max_severity") or finding.get("severity") or "info",
            "title": finding.get("title") or (finding.get("findings", [{}])[0].get("title") if finding.get("findings") else "finding"),
            "description": finding.get("description") or "",
            "rule_id": finding.get("rule_id") or (finding.get("findings", [{}])[0].get("rule_id") if finding.get("findings") else ""),
            "risk_score": finding.get("risk_score"),
            "findings": finding.get("findings", []),
            "org_id": finding.get("org_id"),
            "occurrence_count": finding.get("occurrence_count", 1),
            "first_seen": finding.get("first_seen"),
            "last_seen": finding.get("last_seen", time.time()),
        }
        ok_any = False
        start = time.time()
        results: list[tuple[str, bool, str]] = []
        for ad in self.adapters:
            sent, err = self._send_one(ad, alert)
            results.append((ad.name, sent, err))
            ok_any = ok_any or sent
        latency = time.time() - start
        self.gossip.counters.inc("alerts_dispatched" if ok_any else "alerts_failed")
        self.gossip.counters.set("alert_latency_ms", latency*1000)
        self._record_deliveries(alert, results)
        # ticketing (track 4): best-effort, deduped per rule+target like alerts
        try:
            from app.live.ticketing import load_ticket_backend, should_ticket
            if self._ticketing is None and not self._ticketing_tried:
                self._ticketing_tried = True
                self._ticketing = load_ticket_backend()
            if self._ticketing is not None and should_ticket(alert):
                tkey = f"ticket:{alert['rule_id']}:{alert['five_tuple']}"
                if self.state.check_and_set_dedup(tkey):
                    url = self._ticketing.create(alert)
                    if url:
                        alert["ticket_url"] = url
                        self.gossip.counters.inc("tickets_created")
        except Exception as e:
            log.debug("ticketing skipped: %s", e)
        # persist alert to DB + publish
        try:
            bus.publish_alert(self.r, alert)
            bus.notify(self.r, "alerts", "alert", alert)
            # also persist to Postgres alerts table if exists
            self._persist_alert(alert)
        except Exception as e:
            log.debug("alert publish failed: %s", e)

    def _send_one(self, adapter, alert: dict, retries: int = 1) -> tuple[bool, str]:
        """Send via one channel with a single retry; never raises."""
        import time as _t
        last_err = ""
        for attempt in range(retries + 1):
            try:
                if adapter.send(alert):
                    return True, ""
                last_err = "adapter returned false"
            except Exception as e:
                last_err = str(e)[:300]
                log.warning("adapter %s failed (attempt %d): %s",
                            adapter.name, attempt + 1, last_err)
            if attempt < retries:
                _t.sleep(0.2 * (2 ** attempt))
        return False, last_err

    def _record_deliveries(self, alert: dict, results: list[tuple[str, bool, str]]) -> None:
        """Best-effort per-channel delivery rows; never breaks dispatch."""
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(settings.DATABASE_URL_SYNC)
            with engine.connect() as conn:
                for channel, sent, err in results:
                    conn.execute(text(
                        "INSERT INTO alert_deliveries (alert_id, channel, status,"
                        " attempts, last_error, org_id) VALUES"
                        " (:aid,:ch,:st,:att,:err,:org)"),
                        {"aid": alert["id"], "ch": channel,
                         "st": "sent" if sent else "failed",
                         "att": 2 if err else 1,
                         "err": err or None, "org": alert.get("org_id")})
                conn.commit()
        except Exception as e:
            log.debug("delivery record skipped: %s", e)

    def _persist_alert(self, alert: dict):
        try:
            from sqlalchemy import create_engine, text
            engine = create_engine(settings.DATABASE_URL_SYNC)
            with engine.connect() as conn:
                conn.execute(text("""
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
                # idempotent column add for pre-existing tables
                try:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS org_id TEXT"))
                except Exception:
                    pass
                conn.execute(text("INSERT INTO alerts (id, severity, title, five_tuple, payload, org_id) VALUES (:id,:sev,:title,:ft,:payload,:org) ON CONFLICT DO NOTHING"),
                             {"id": alert["id"], "sev": alert["severity"], "title": alert["title"], "ft": alert["five_tuple"], "payload": json.dumps(alert), "org": alert.get("org_id")})
                conn.commit()
        except Exception as e:
            log.debug("alert persist failed: %s", e)

    def _expiry_sweep(self):
        """Proactive cert-expiry alerts (track 2): warn before expiry."""
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from app.proactive.certs import find_expiring, mark_alerted
            engine = create_engine(settings.DATABASE_URL_SYNC)
            db = sessionmaker(bind=engine)()
            try:
                rows = find_expiring(None, settings.CERT_EXPIRY_WARN_DAYS, db)
                fresh = [r for r in rows
                         if not r.expiry_alerted_at or
                         (time.time() - r.expiry_alerted_at.timestamp()) > 86400]
                for r in fresh:
                    try:
                        from datetime import datetime, timezone
                        _now = datetime.now(timezone.utc)
                        _na = r.not_after
                        if _na is not None and _na.tzinfo is None:
                            _na = _na.replace(tzinfo=timezone.utc)
                        days = (_na - _now).days if _na else -1
                    except Exception:
                        days = -1
                    self._dispatch({
                        "rule_id": "cert-expiry-forecast",
                        "severity": "high" if days < 0 else ("medium" if days > 7 else "high"),
                        "title": ("Certificate already expired" if days < 0
                                  else f"Certificate expires in {days} days"),
                        "description": (f"{r.subject_cn} (issuer {r.issuer_cn}) "
                                        f"expires {r.not_after}; seen {r.seen_count}x "
                                        f"since {r.first_seen}. Rotate before expiry."),
                        "five_tuple": "",
                        "protocol": "",
                        "org_id": r.org_id,
                        "risk_score": None,
                        "findings": [],
                    })
                if fresh:
                    mark_alerted(db, [r.fingerprint for r in fresh])
            finally:
                db.close()
        except Exception as e:
            log.debug("expiry sweep skipped: %s", e)

    def _transport_sweep(self):
        """Scheduled MTA-STS/DANE re-checks (phase 2 task 5).

        Re-checks a bounded set of domains seen in the cert inventory.
        Dispatches alerts ONLY for proven `misconfigured` policies (never for
        dns-error/insecure — those are informational). DNS failures never raise.
        """
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            from app.models.entities import TrackedCert
            from app.proactive.mta_sts import check_domain
            engine = create_engine(settings.DATABASE_URL_SYNC)
            db = sessionmaker(bind=engine)()
            try:
                rows = db.query(TrackedCert.subject_cn).limit(25).all()
            finally:
                db.close()
            domains = sorted({(r[0] or "").strip().lower().lstrip("*.")
                              for r in rows if r[0]})
            for dom in domains:
                if not dom or "." not in dom:
                    continue
                try:
                    posture = check_domain(dom)
                except Exception as e:
                    log.debug("transport recheck %s skipped: %s", dom, e)
                    continue
                if posture.get("status") == "misconfigured":
                    try:
                        self.gossip.counters.inc("transport_misconfigured")
                    except Exception:
                        pass
                    self._dispatch({
                        "rule_id": "transport-misconfigured",
                        "severity": "medium",
                        "title": f"Transport security misconfigured for {dom}",
                        "description": (
                            f"MTA-STS/DANE check for {dom}: "
                            f"{(posture.get('mta_sts') or {}).get('error') or 'policy invalid'}"),
                        "five_tuple": dom,
                        "protocol": "",
                        "org_id": None,
                        "risk_score": None,
                        "findings": [],
                    })
        except Exception as e:
            log.debug("transport sweep skipped: %s", e)

    def _handle_entry(self, entry_id: str, payload) -> None:
        """At-least-once handling: dispatch, then ACK; failures retry/DLQ."""
        from app.live import streams as _bus
        try:
            finding = payload if isinstance(payload, dict) else json.loads(payload)
        except Exception as e:
            attempts = _bus.note_attempt(self.r, self.consumer.stream, entry_id)
            if attempts >= settings.STREAM_MAX_ATTEMPTS:
                self.consumer.dead_letter(entry_id, {}, f"decode: {e}", attempts)
            return
        try:
            if isinstance(finding.get("findings"), list) and finding["findings"]:
                if not self._should_alert(finding):
                    self.consumer.ack(entry_id)
                    _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
                    return
            else:
                if not self._should_alert(finding):
                    self.consumer.ack(entry_id)
                    _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
                    return
            if self._suppressed(finding):
                try:
                    self.gossip.counters.inc("alerts_suppressed")
                except Exception:
                    pass
                self.consumer.ack(entry_id)
                _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
                return
            # Phase 4 task 5: per-org policy (digest/quiet) before grouping.
            # Critical alerts always bypass quiet hours and digests.
            sev_now = finding.get("max_severity") or finding.get("severity") or "info"
            if SEV_ORDER.get(sev_now, 0) < SEV_ORDER.get("critical", 4):
                policy = self._policy_for(finding.get("org_id"))
                if self._in_quiet(policy):
                    self._stash_digest(finding, finding.get("org_id"),
                                       policy.get("digest", "off"), bucket="quiet")
                    try:
                        self.gossip.counters.inc("alerts_quiet_held")
                    except Exception:
                        pass
                    self.consumer.ack(entry_id)
                    _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
                    return
                if policy.get("digest", "off") in ("daily", "weekly"):
                    self._stash_digest(finding, finding.get("org_id"),
                                       policy["digest"])
                    try:
                        self.gossip.counters.inc("alerts_digested")
                    except Exception:
                        pass
                    self.consumer.ack(entry_id)
                    _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
                    return
            # Ownership routing tags (never suppresses).
            try:
                finding = dict(finding)
                finding["routing"] = self._route_finding(finding)
            except Exception:
                pass
            # Group by root cause; dispatch any groups whose hold expired.
            self.groups.add(finding)
            for grouped in self.groups.flush_expired():
                merged = dict(finding)
                merged.update({k: grouped[k] for k in (
                    "rule_id", "severity", "title", "description", "protocol",
                    "org_id", "risk_score", "occurrence_count",
                    "first_seen", "last_seen") if k in grouped})
                merged["server"] = grouped.get("server")
                self._dispatch(merged)
        except Exception as e:
            attempts = _bus.note_attempt(self.r, self.consumer.stream, entry_id)
            if attempts >= settings.STREAM_MAX_ATTEMPTS:
                self.consumer.dead_letter(entry_id, finding
                                          if isinstance(finding, dict) else {},
                                          str(e), attempts)
                log.warning("finding %s dead-lettered after %d attempts: %s",
                            entry_id, attempts, e)
            else:
                log.debug("finding %s attempt %d failed: %s", entry_id, attempts, e)
            return
        _bus.clear_attempts(self.r, self.consumer.stream, entry_id)
        self.consumer.ack(entry_id)
        try:
            self.gossip.counters.set("dlq_depth", self.consumer.dlq_depth())
        except Exception:
            pass

    def run(self):
        log.info("alert dispatcher starting, min_severity=%s adapters=%s", settings.ALERT_MIN_SEVERITY, [a.name for a in self.adapters])
        self.gossip.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass
        last_expiry = 0.0
        last_transport = 0.0
        while not self._stop.is_set():
            if time.time() - last_expiry > settings.CERT_EXPIRY_CHECK_INTERVAL_SECONDS:
                last_expiry = time.time()
                self._expiry_sweep()
            if time.time() - last_transport > settings.TRANSPORT_RECHECK_INTERVAL_SECONDS:
                last_transport = time.time()
                self._transport_sweep()
            try:
                self._flush_digests()
            except Exception as e:
                log.debug("digest flush failed: %s", e)
            items = self.consumer.poll_raw(timeout_ms=800)
            # Flush grouped alerts whose hold window expired, even on idle polls.
            try:
                for grouped in self.groups.flush_expired():
                    self._dispatch(grouped)
            except Exception as e:
                log.debug("group flush failed: %s", e)
            if not items:
                for eid, payload in self.consumer.reclaim():
                    if self._stop.is_set():
                        break
                    try:
                        self._handle_entry(eid, payload)
                    except Exception as e:
                        log.warning("reclaim dispatch error: %s", e)
                continue
            for entry_id, payload in items:
                if self._stop.is_set():
                    break
                try:
                    self._handle_entry(entry_id, payload)
                except Exception as e:
                    log.warning("alert dispatch error: %s", e)
        self.gossip.stop()
        log.info("alert dispatcher stopped")

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="CipherPost alert dispatcher")
    ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    d = AlertDispatcher()
    d.run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
