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
    return adapters

def save_channel_config(cfg: dict):
    p = Path(settings.ALERT_CHANNEL_CONFIG_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))

class AlertDispatcher:
    def __init__(self, redis_client=None, adapters: list[AlertAdapter] | None = None):
        self.r = redis_client or redis.Redis.from_url(settings.REDIS_URL, decode_responses=False)
        self.adapters = adapters if adapters is not None else load_channels()
        self.gossip = Gossiper(self.r, "alerts", interval=5)
        self._stop = threading.Event()
        self._dedup: dict[str, float] = {}  # key -> last_ts
        self._rate_window: list[float] = []
        self.consumer = bus.StreamConsumer(self.r, settings.FINDINGS_STREAM, settings.ALERT_CONSUMER_GROUP, f"alerter-{uuid.uuid4().hex[:6]}")
        self.min_sev = SEV_ORDER.get(settings.ALERT_MIN_SEVERITY, 3)

    def _signal(self, s, f):
        self._stop.set()

    def _should_alert(self, finding: dict) -> bool:
        sev = finding.get("max_severity") or finding.get("severity") or "info"
        if SEV_ORDER.get(sev, 0) < self.min_sev:
            return False
        # dedup per rule+five_tuple
        key = f"{finding.get('rule_id','')}:{finding.get('five_tuple','')}"
        now = time.time()
        last = self._dedup.get(key, 0)
        if now - last < settings.ALERT_DEDUP_WINDOW_SECONDS:
            return False
        # rate limit
        self._rate_window = [t for t in self._rate_window if now - t < 60]
        if len(self._rate_window) >= settings.ALERT_RATE_LIMIT_PER_MINUTE:
            return False
        return True

    def _dispatch(self, finding: dict):
        # build alert object
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
        }
        ok_any = False
        start = time.time()
        for ad in self.adapters:
            try:
                if ad.send(alert):
                    ok_any = True
            except Exception as e:
                log.warning("adapter %s failed: %s", ad.name, e)
        latency = time.time() - start
        self.gossip.counters.inc("alerts_dispatched" if ok_any else "alerts_failed")
        self.gossip.counters.set("alert_latency_ms", latency*1000)
        # persist alert to DB + publish
        try:
            bus.publish_alert(self.r, alert)
            bus.notify(self.r, "alerts", "alert", alert)
            # also persist to Postgres alerts table if exists
            self._persist_alert(alert)
        except Exception as e:
            log.debug("alert publish failed: %s", e)
        if ok_any:
            key = f"{alert['rule_id']}:{alert['five_tuple']}"
            self._dedup[key] = time.time()
            self._rate_window.append(time.time())

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
                        payload JSONB
                    )
                """))
                conn.execute(text("INSERT INTO alerts (id, severity, title, five_tuple, payload) VALUES (:id,:sev,:title,:ft,:payload) ON CONFLICT DO NOTHING"),
                             {"id": alert["id"], "sev": alert["severity"], "title": alert["title"], "ft": alert["five_tuple"], "payload": json.dumps(alert)})
                conn.commit()
        except Exception as e:
            log.debug("alert persist failed: %s", e)

    def run(self):
        log.info("alert dispatcher starting, min_severity=%s adapters=%s", settings.ALERT_MIN_SEVERITY, [a.name for a in self.adapters])
        self.gossip.start()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._signal)
            except ValueError:
                pass
        while not self._stop.is_set():
            items = self.consumer.poll(timeout_ms=800)
            if not items:
                continue
            for payload in items:
                if self._stop.is_set():
                    break
                try:
                    # payload is decoded finding dict
                    finding = payload if isinstance(payload, dict) else json.loads(payload)
                    # findings stream contains aggregated finding dict with max_severity etc
                    # also handle per-rule finding
                    if isinstance(finding.get("findings"), list) and finding["findings"]:
                        # aggregated session findings: check max severity
                        if not self._should_alert(finding):
                            continue
                        self._dispatch(finding)
                    else:
                        if not self._should_alert(finding):
                            continue
                        self._dispatch(finding)
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
