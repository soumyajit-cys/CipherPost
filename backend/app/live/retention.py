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


class RollingRawStore:
    """Append frames to time-chunked segment files; purge old ones."""

    def __init__(self, directory: Path | str, retention_seconds: int,
                 segment_seconds: int = 300):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.retention = int(retention_seconds)
        self.segment_seconds = int(segment_seconds)
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

    def write(self, ts: float, frame: bytes):
        """Append a frame; returns (segment_name, offset, length)."""
        with self._lock:
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