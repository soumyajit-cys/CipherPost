"""
Rolling raw-capture retention (write-ahead segment store).

Raw frames are appended to time-chunked segment files. Segments older than the
configured window are purged on a timer. Each written frame returns a
(segment, offset, length) ref so emitted Sessions can later replay their exact
frames while the window still contains them.

Segment file format: per-frame header '<QdIII' (ts, magic, length, pad) +
payload. Simple, seekable, self-describing.
"""
from __future__ import annotations

import logging
import os
import struct
import threading
import time
from pathlib import Path

log = logging.getLogger("cipherpost.live.retention")

_FRAME_HDR = struct.Struct("<QdI")  # ts_ms, ts_f, length
_MAGIC = 0x43505720  # "CPW "
_EXT = ".seg"
_CHUNK_MIN_FRAMES = 16
_DISK_CHECK_EVERY_WRITES = 128   # check free disk at most this often
_DISK_LOG_EVERY_SECONDS = 60.0   # rate-limit the disk-guard alert line


def _disk_free_bytes(path) -> int | None:
    """Free bytes on the filesystem holding `path`. Module-level so tests can
    simulate low disk without touching real storage."""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except OSError:
        return None


class RollingRawStore:
    """Append frames to time-chunked segment files; purge old ones."""

    def __init__(self, directory: Path | str, retention_seconds: int,
                 segment_seconds: int = 300,
                 disk_min_free_bytes: int | None = None):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.retention = int(retention_seconds)
        self.segment_seconds = int(segment_seconds)
        # Disk guard (unattended-run safety): stop capture storage before the
        # disk fills. Free-space checks are cached; drops are counted and
        # alerted (rate-limited), and writing resumes automatically.
        if disk_min_free_bytes is None:
            from app.core.config import settings as _s
            disk_min_free_bytes = _s.RAW_DISK_MIN_FREE_BYTES
        self.disk_min_free_bytes = int(disk_min_free_bytes)
        self._disk_guard_active = False
        self._disk_guard_dropped = 0
        self._writes_since_check = _DISK_CHECK_EVERY_WRITES  # check on first write
        self._last_guard_log = 0.0
        self._current: Path | None = None
        self._fh = None
        self._lock = threading.RLock()
        self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True)
        self._stop = threading.Event()
        self._frames = 0
        self._bytes = 0

    def start(self):
        if not self._purge_thread.is_alive():
            self._purge_thread = threading.Thread(target=self._purge_loop, daemon=True)
            self._purge_thread.start()

    def stop(self):
        self._stop.set()
        try:
            self._purge_thread.join(timeout=2)
        except RuntimeError:
            pass
        self._close_current()

    def _close_current(self):
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
                self._current = None

    def _open_segment(self, ts: float) -> Path:
        seg = int(ts) // self.segment_seconds * self.segment_seconds
        path = self.dir / f"cap-{seg}{_EXT}"
        with self._lock:
            if path == self._current and self._fh:
                return path
            # inline close without re-locking (we already hold RLock, so safe to call)
            if self._fh:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
                self._current = None
            self._fh = open(path, "ab")
            self._current = path
            return path

    def _disk_guard_should_drop(self) -> bool:
        """True while free space on the capture filesystem is below the floor.
        Cached between checks; flips off automatically on recovery."""
        self._writes_since_check += 1
        if self._disk_guard_active or \
                self._writes_since_check >= _DISK_CHECK_EVERY_WRITES:
            self._writes_since_check = 0
            free = _disk_free_bytes(self.dir)
            if free is None:
                # cannot measure: do not drop, but say so once per window
                if not self._disk_guard_active:
                    log.warning("disk guard: cannot measure free space on %s", self.dir)
            else:
                active = free < self.disk_min_free_bytes
                if active and not self._disk_guard_active:
                    log.error(
                        "DISK GUARD: stopping raw-capture writes on %s "
                        "(%.2f GB free < %.2f GB floor). Frames are DROPPED until "
                        "space recovers; alerts stay live. Check docs/live-run/"
                        "ops-checklist.md.",
                        self.dir, free / 1024 ** 3, self.disk_min_free_bytes / 1024 ** 3)
                elif not active and self._disk_guard_active:
                    log.warning("disk guard: space recovered on %s — capture writes resumed",
                                self.dir)
                self._disk_guard_active = active
        return self._disk_guard_active

    def write(self, ts: float, frame: bytes):
        """Append a frame; returns (segment_name, offset, length), or None when
        the disk guard is dropping frames (counted, never silent)."""
        with self._lock:
            if self._disk_guard_should_drop():
                self._disk_guard_dropped += 1
                now = time.time()
                if now - self._last_guard_log >= _DISK_LOG_EVERY_SECONDS:
                    self._last_guard_log = now
                    log.error("disk guard: %d frames dropped so far on %s",
                              self._disk_guard_dropped, self.dir)
                return None
            path = self._open_segment(ts)
            offset = self._fh.tell()
            self._fh.write(_FRAME_HDR.pack(0, int(ts * 1e6), len(frame)))
            self._fh.write(_MAGIC.to_bytes(4, "little"))
            self._fh.write(frame)
            self._fh.flush()
            self._frames += 1
            self._bytes += _FRAME_HDR.size + 4 + len(frame)
            return (path.name, offset, _FRAME_HDR.size + 4 + len(frame))

    def read_frames(self, refs) -> list[bytes]:
        """Replay raw frames from a list of (segment, offset, length) refs."""
        frames = []
        for seg, offset, length in refs or []:
            path = self.dir / seg
            if not path.exists():
                continue  # purged
            try:
                with open(path, "rb") as f:
                    f.seek(offset)
                    data = f.read(length)
                frames.append(data)
            except (OSError, ValueError):
                pass
        return frames

    def replayed_bytes(self, refs) -> bytes:
        return b"".join(self.read_frames(refs))

    def purge(self, now: float | None = None):
        """Delete segment files fully older than the retention window."""
        now = now or time.time()
        cutoff = int(now) - self.retention
        removed = 0
        for path in self.dir.glob(f"*{_EXT}"):
            ts_seg = int(path.stem.split("-")[1])
            if ts_seg + self.segment_seconds < cutoff and path != getattr(self, "_current", None):
                try:
                    path.unlink()
                    removed += 1
                except OSError as e:
                    log.warning("purge failed for %s: %s", path.name, e)
        if removed:
            log.info("raw-capture purge: removed %d segment file(s)", removed)
        return removed

    def _purge_loop(self):
        while not self._stop.wait(30):
            try:
                self.purge()
            except Exception as e:
                log.warning("retention purge error: %s", e)

    def stats(self) -> dict:
        return {
            "frames": self._frames,
            "bytes": self._bytes,
            "retention_seconds": self.retention,
            "segments": len(list(self.dir.glob(f"*{_EXT}"))),
            "dir": str(self.dir),
        }


def run_db_retention_once() -> dict[str, int]:
    """Entry point for cron/K8s CronJob: purge old rows, log counts."""
    totals = DBRetention().purge_all()
    for table, n in totals.items():
        if n:
            log.info("retention purged %d rows from %s", n, table)
    return totals


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="CipherPost retention: purge old DB rows")
    _p.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(run_db_retention_once())


class DBRetention:
    """Batch-purge old rows per data type without long table locks.

    - Deletes in batches (RETENTION_BATCH_SIZE) with a commit per batch.
    - Never touches rows with legal_hold set, rows with NULL timestamps
      (legacy), or audit rows (longest retention, still purged eventually).
    - Reports rows purged per table via the injected metrics mapping
      (or returns the counts for tests).
    """

    def __init__(self, session_factory=None, batch_size: int | None = None,
                 metrics=None):
        from app.core.config import settings as _s
        self.batch_size = batch_size or _s.RETENTION_BATCH_SIZE
        self.metrics = metrics
        self._session_factory = session_factory or self._default_factory

    @staticmethod
    def _default_factory():
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.core.config import settings as _s
        engine = create_engine(_s.DATABASE_URL_SYNC)
        return sessionmaker(bind=engine)()

    def _count_metric(self, table: str, n: int) -> None:
        try:
            if self.metrics is not None:
                self.metrics.inc(f"retention_purged_total{{table=\"{table}\"}}", n)
        except Exception:
            pass

    def _purge_batch(self, db, model, cutoff, extra=None) -> int:
        ts_col = getattr(model, "created_at", None) or getattr(model, "ts", None)
        q = db.query(model).filter(ts_col.is_not(None), ts_col < cutoff)
        if hasattr(model, "legal_hold"):
            q = q.filter((model.legal_hold.is_(False)) | (model.legal_hold.is_(None)))
        if extra is not None:
            q = extra(q)
        rows = q.limit(self.batch_size).all()
        for r in rows:
            db.delete(r)
        return len(rows)

    def purge_all(self, now=None) -> dict[str, int]:
        from datetime import datetime, timezone, timedelta
        from app.core.config import settings as _s
        from app.models.entities import Session, Finding, AuditLog, Alert, BaselineFeature
        now = now or datetime.now(timezone.utc)
        totals: dict[str, int] = {}
        db = self._session_factory()
        try:
            plans = [
                ("sessions", Session, _s.RETENTION_SESSIONS_DAYS),
                ("findings", Finding, _s.RETENTION_FINDINGS_DAYS),
                ("alerts", Alert, _s.RETENTION_ALERTS_DAYS),
                ("audit_log", AuditLog, _s.RETENTION_AUDIT_DAYS),
            ]
            for table, model, days in plans:
                if not days or days <= 0:
                    totals[table] = 0
                    continue
                cutoff = now - timedelta(days=days)
                n_total = 0
                while True:
                    if table == "sessions":
                        from app.models.entities import AnalysisJob as _Job
                        held = db.query(_Job.id).filter(
                            (_Job.legal_hold.is_(True)))
                        n = self._purge_batch(
                            db, model, cutoff,
                            extra=lambda q: q.filter(~model.job_id.in_(held)))
                    else:
                        n = self._purge_batch(db, model, cutoff)
                    if n == 0:
                        break
                    db.commit()
                    n_total += n
                    self._count_metric(table, n)
                # findings belonging to purged sessions cascade via FK only
                # when the DB enforces it; sessions deleted above leave
                # orphan findings to the findings pass (same cutoff).
                totals[table] = n_total
            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            log.warning("retention purge failed: %s", e)
        finally:
            try:
                db.close()
            except Exception:
                pass
        return totals