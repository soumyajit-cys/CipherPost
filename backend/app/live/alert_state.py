"""Shared, durable alert state (Phase 2 Task 2).

- Dedup keys in Redis (SET NX + TTL) so restarts and multiple dispatcher
  replicas share one budget. Falls back to small in-memory maps only when
  Redis is unavailable (logged loudly, once).
- Sliding-window rate limiting via Redis sorted sets (ZADD + ZREMRANGEBYSCORE
  + ZCARD); in-memory fallback mirrors the same semantics.
- GroupBuffer aggregates related findings by root cause
  (rule_id + server host) within a hold window and emits ONE alert with
  occurrence_count / first_seen / last_seen instead of one alert per session.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("cipherpost.live.alert_state")

_fallback_warned = False


def _warn_fallback_once(msg: str) -> None:
    global _fallback_warned
    if not _fallback_warned:
        _fallback_warned = True
        log.warning("ALERT STATE FALLBACK TO MEMORY (Redis unavailable): %s", msg)


def server_host_of(finding: dict) -> str:
    """Extract the server side of a five_tuple 'c1:p1-s1:p2' or explicit host."""
    for k in ("server", "mx_host", "host", "dst_ip"):
        v = finding.get(k)
        if v:
            return str(v)
    ft = str(finding.get("five_tuple", "") or "")
    if "-" in ft and ":" in ft:
        try:
            server = ft.split("-", 1)[1]
            return server.rsplit(":", 1)[0]
        except Exception:
            pass
    return ft or "unknown"


def group_key_of(finding: dict) -> str:
    return f"{finding.get('rule_id', 'unknown')}:{server_host_of(finding)}"


class RedisAlertState:
    """Dedup + rate budget shared via Redis, memory fallback when down."""

    def __init__(self, r, dedup_window: int, rate_per_minute: int):
        self.r = r
        self.dedup_window = dedup_window
        self.rate_per_minute = rate_per_minute
        self._mem_dedup: dict[str, float] = {}
        self._mem_rate: list[float] = []

    # -- redis helpers ----------------------------------------------------
    def _redis(self):
        try:
            self.r.ping()
            return self.r
        except Exception as e:
            _warn_fallback_once(str(e)[:200])
            return None

    # -- dedup ------------------------------------------------------------
    def check_and_set_dedup(self, key: str) -> bool:
        """True if this key is fresh (caller may alert); False if duplicate."""
        now = time.time()
        r = self._redis()
        if r is not None:
            try:
                ok = r.set(f"alert:dedup:{key}", "1", nx=True, ex=self.dedup_window)
                return bool(ok)
            except Exception as e:
                _warn_fallback_once(str(e)[:200])
        # memory fallback (bounded)
        last = self._mem_dedup.get(key, 0)
        if now - last < self.dedup_window:
            return False
        self._mem_dedup[key] = now
        if len(self._mem_dedup) > 5000:
            oldest = sorted(self._mem_dedup.items(), key=lambda kv: kv[1])[:1000]
            for k, _ in oldest:
                self._mem_dedup.pop(k, None)
        return True

    # -- rate limit -------------------------------------------------------
    def check_rate(self) -> bool:
        """True if under budget (and consume one token); False if limited."""
        now = time.time()
        window_start = now - 60.0
        r = self._redis()
        if r is not None:
            try:
                zkey = "alert:rate"
                member = f"{now}:{id(self)}"
                pipe = r.pipeline()
                pipe.zadd(zkey, {member: now})
                pipe.zremrangebyscore(zkey, 0, window_start)
                pipe.zcard(zkey)
                pipe.expire(zkey, 70)
                _, _, count, _ = pipe.execute()
                return int(count) <= self.rate_per_minute
            except Exception as e:
                _warn_fallback_once(str(e)[:200])
        self._mem_rate = [t for t in self._mem_rate if t > window_start]
        if len(self._mem_rate) >= self.rate_per_minute:
            return False
        self._mem_rate.append(now)
        return True


class GroupBuffer:
    """Hold related findings briefly, then emit one grouped alert.

    Grouped by (rule_id, server host). First occurrence opens a bucket with a
    deadline of `hold_seconds`; further occurrences increment the bucket.
    `flush_expired()` returns aggregated alert payloads ready to dispatch.
    Pure in-memory per process, but dedup is enforced by RedisAlertState so a
    restart cannot emit a duplicate group (the group's dedup key persists).
    """

    def __init__(self, hold_seconds: float = 10.0):
        self.hold_seconds = hold_seconds
        self._buckets: dict[str, dict] = {}

    def add(self, finding: dict, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        key = group_key_of(finding)
        b = self._buckets.get(key)
        if b is None:
            self._buckets[key] = {
                "key": key,
                "rule_id": finding.get("rule_id", "unknown"),
                "server": server_host_of(finding),
                "severity": finding.get("max_severity") or finding.get("severity") or "info",
                "title": finding.get("title") or "",
                "description": finding.get("description") or "",
                "protocol": finding.get("protocol", ""),
                "org_id": finding.get("org_id"),
                "risk_score": finding.get("risk_score"),
                "count": 1,
                "first_seen": now,
                "last_seen": now,
                "sample": finding,
                "deadline": now + self.hold_seconds,
            }
        else:
            b["count"] += 1
            b["last_seen"] = now
            # keep the highest severity seen
            order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if order.get(str(b["severity"]), 0) < order.get(
                    str(finding.get("max_severity") or finding.get("severity")), 0):
                b["severity"] = finding.get("max_severity") or finding.get("severity")
                b["title"] = finding.get("title") or b["title"]

    def flush_expired(self, now: float | None = None) -> list[dict]:
        now = now if now is not None else time.time()
        ready = []
        for key in [k for k, b in self._buckets.items() if b["deadline"] <= now]:
            b = self._buckets.pop(key)
            ready.append({
                "group_key": key,
                "rule_id": b["rule_id"],
                "server": b["server"],
                "severity": b["severity"],
                "title": b["title"],
                "description": b["description"],
                "protocol": b["protocol"],
                "org_id": b["org_id"],
                "risk_score": b["risk_score"],
                "occurrence_count": b["count"],
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
                "sample": b["sample"],
            })
        return ready

    def __len__(self) -> int:
        return len(self._buckets)
