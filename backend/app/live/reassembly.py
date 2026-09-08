"""
Live streaming TCP reassembly.

Subclasses the Stage-2 StreamAssembler (which is already online: one packet per
feed call) and adds the properties a live daemon needs:
  - incremental finalization: finished sessions (FIN/RST) are drained per sweep,
    and idle sessions are finalized after a timeout instead of buffering forever
  - hard memory caps: max concurrent sessions + max bytes per stream, with
    flagged finalization / eviction instead of unbounded growth
  - raw-capture refs: each emitted Session records (segment, offset, length)
    pointing at its exact frames in the rolling raw store, for forensic replay

Emits are debounced: you collect completed sessions via drain() on an interval.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.live.packets import Packet
from app.parsing.reassembly import (
    StreamAssembler, Session, Protocol,
    detect_protocol, _assign_tls_segments,
)

log = logging.getLogger("cipherpost.live.reassembly")


@dataclass
class ReassemblyStats:
    packets: int = 0
    evicted: int = 0
    closed_fin: int = 0
    closed_rst: int = 0
    closed_idle: int = 0
    closed_cap: int = 0
    truncated: int = 0
    completed: int = 0
    active: int = 0

    def as_dict(self) -> dict:
        return {
            "packets": self.packets,
            "evicted": self.evicted,
            "closed_fin": self.closed_fin,
            "closed_rst": self.closed_rst,
            "closed_idle": self.closed_idle,
            "closed_cap": self.closed_cap,
            "truncated": self.truncated,
            "completed": self.completed,
            "active": self.active,
        }


class LiveReassembler(StreamAssembler):
    """Streaming reassembler with idle finalization, caps, and incremental drain."""

    def __init__(self, idle_timeout: float = 60.0,
                 max_sessions: int = 4096,
                 max_buffer_bytes: int = 512 * 1024):
        super().__init__(idle_timeout=idle_timeout)
        self.max_sessions = max_sessions
        self.max_buffer_bytes = max_buffer_bytes
        self.stats = ReassemblyStats()
        # per-stream extra bookkeeping: raw refs + last activity
        self._refs: dict = {}

    # --- raw refs -------------------------------------------------------------

    def _ref_list(self, key) -> list:
        r = self._refs.get(key)
        if r is None:
            r = self._refs[key] = []
        return r

    # --- feed -----------------------------------------------------------------

    def feed_packet(self, pkt: Packet) -> None:
        self.stats.packets += 1
        try:
            self.feed(
                src=pkt.src, dst=pkt.dst, sport=pkt.sport, dport=pkt.dport,
                seq=pkt.seq, ack=pkt.ack, payload=pkt.payload,
                flags=pkt.flags, ts=pkt.ts,
            )
            if pkt.raw_ref is not None:
                key = self._key(pkt.src, pkt.sport, pkt.dst, pkt.dport)
                self._ref_list(key).append(pkt.raw_ref)
        except Exception as e:
            log.warning("feed_packet error: %s", e)

    def _key_of(self, src, sport, dst, dport) -> tuple:
        return self._key(src, sport, dst, dport)

    # --- sweep helpers ----------------------------------------------------------

    def sweep(self, now: float) -> list[Session]:
        """Finalize idle streams; evict when over concurrent cap; drain finished."""
        to_close = []
        for key, st in list(self._streams.items()):
            if st.complete:
                to_close.append((key, st, self._close_reason(st)))
                continue
            last = max(st.ha.last_ts, st.hb.last_ts)
            if last and now - last > self.idle_timeout:
                to_close.append((key, st, "idle"))
                continue
            # per-stream byte cap
            if len(st.ha.buf) + len(st.hb.buf) > self.max_buffer_bytes:
                st.ha.rst = st.hb.rst = True
                to_close.append((key, st, "cap"))
        out = [self._emit_one(key, st, reason) for key, st, reason in to_close]
        # Enforce concurrent-session cap (evict oldest incomplete)
        active = [k for k, st in self._streams.items() if not st.complete]
        if len(active) > self.max_sessions:
            overflow = sorted(active, key=lambda k: self._streams[k].first_ts)[
                : len(active) - self.max_sessions
            ]
            for k in overflow:
                self.stats.evicted += 1
                sess = self._emit_one(k, self._streams[k], "evicted")
                if sess:
                    out.append(sess)
        self.stats.active = len(self._streams)
        return out

    @staticmethod
    def _close_reason(st) -> str:
        if st.ha.rst or st.hb.rst:
            return "rst"
        if st.complete:
            return "fin"
        return "fin"

    # --- drain -------------------------------------------------------------------

    def drain(self) -> list[Session]:
        """Collect all currently-complete sessions (non-idle)."""
        out = []
        for key, st in list(self._streams.items()):
            if st.complete:
                sess = self._emit_one(key, st, self._close_reason(st))
                if sess:
                    out.append(sess)
        self.stats.active = len(self._streams)
        return out

    def tick(self, now: float) -> list[Session]:
        """Full sweep + drain, returns newly completed sessions."""
        return self.sweep(now)

    # --- session construction -----------------------------------------------------

    def _emit_one(self, key, st, reason: str) -> Session | None:
        """Build+emit a Session for a finalized stream. Idempotent per stream."""
        if key not in self._streams:
            return None
        self._streams.pop(key, None)
        refs = self._refs.pop(key, None)
        c = self._resolve_client(st)
        if c == (st.ip_a, st.port_a):
            c_ip, c_port, s_ip, s_port = st.ip_a, st.port_a, st.ip_b, st.port_b
            client_bytes = bytes(st.ha.buf)
            server_bytes = bytes(st.hb.buf)
        else:
            c_ip, c_port, s_ip, s_port = st.ip_b, st.port_b, st.ip_a, st.port_a
            client_bytes = bytes(st.hb.buf)
            server_bytes = bytes(st.ha.buf)

        sess = Session(
            protocol=Protocol.UNKNOWN,
            five_tuple=f"{c_ip}:{c_port}->{s_ip}:{s_port}",
            client_ip=c_ip, server_ip=s_ip,
            client_port=c_port, server_port=s_port,
            start_ts=st.first_ts,
            end_ts=max(st.ha.last_ts, st.hb.last_ts),
        )
        sess.closed_by = reason
        sess.protocol = detect_protocol(sess, client_bytes, server_bytes)
        if sess.protocol == Protocol.UNKNOWN:
            return None
        _assign_tls_segments(sess, client_bytes, server_bytes)
        sess.raw_refs = refs or []
        sess.tracked_bytes = len(client_bytes) + len(server_bytes)
        # stats
        if reason == "idle":
            self.stats.closed_idle += 1
        elif reason == "cap":
            self.stats.closed_cap += 1
            self.stats.truncated += 1
        elif reason == "evicted":
            self.stats.closed_cap += 1
        elif reason == "rst":
            self.stats.closed_rst += 1
        elif reason == "fin":
            self.stats.closed_fin += 1
        self.stats.completed += 1
        return sess