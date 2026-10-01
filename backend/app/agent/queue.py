"""Persistent on-disk queue (Phase 3 Task 3): outage-safe sensor buffer.

Append-only JSONL with fsync per batch; reads track an offset file; ACK by
compaction (rewrite without acked prefix). Bounded: oldest entries are dropped
and counted when the file exceeds max bytes. Crash-safe: the offset file is
rewritten atomically (tmp + rename).
"""
from __future__ import annotations

import json
import logging
import os
import threading

log = logging.getLogger("cipherpost.agent.queue")


class DiskQueue:
    def __init__(self, path: str, max_bytes: int = 64 * 1024 * 1024):
        self.path = path
        self.off_path = path + ".off"
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.dropped = 0
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._offset = self._read_offset()

    def _read_offset(self) -> int:
        try:
            with open(self.off_path) as f:
                return int(f.read().strip() or 0)
        except Exception:
            return 0

    def _write_offset(self, n: int) -> None:
        tmp = self.off_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(n))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.off_path)
        self._offset = n

    def append(self, item: dict) -> None:
        line = (json.dumps(item) + "\n").encode()
        with self._lock:
            with open(self.path, "ab") as f:
                f.write(line)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            try:
                if os.path.getsize(self.path) > self.max_bytes:
                    self._drop_oldest_locked()
            except Exception as e:
                log.debug("queue bound check skipped: %s", e)

    def _drop_oldest_locked(self) -> None:
        # Drop the oldest ~10% of lines; count them (never grow unbounded).
        try:
            with open(self.path, "rb") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return
        drop = max(1, len(lines) // 10)
        self.dropped += drop
        with open(self.path, "wb") as f:
            f.writelines(lines[drop:])
        self._write_offset(0)  # offsets restart after compaction
        log.warning("agent queue full: dropped oldest %d entries", drop)

    def read_batch(self, limit: int = 200) -> tuple[int, list[dict]]:
        """Return (start_offset, items) from the current offset."""
        with self._lock:
            try:
                with open(self.path, "rb") as f:
                    lines = f.readlines()
            except FileNotFoundError:
                return 0, []
        start = min(self._offset, len(lines))
        out = []
        for raw in lines[start:start + limit]:
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
        return start, out

    def ack(self, through_offset: int) -> None:
        """Advance past entries and compact the file when idle-large."""
        with self._lock:
            self._write_offset(through_offset)
            try:
                if through_offset > 5000:
                    with open(self.path, "rb") as f:
                        lines = f.readlines()
                    with open(self.path, "wb") as f:
                        f.writelines(lines[through_offset:])
                    self._write_offset(0)
            except Exception as e:
                log.debug("queue compaction skipped: %s", e)

    def depth(self) -> int:
        try:
            with open(self.path, "rb") as f:
                total = sum(1 for _ in f)
            return max(0, total - self._offset)
        except FileNotFoundError:
            return 0
