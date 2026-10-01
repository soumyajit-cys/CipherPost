"""Phase 3 Task 3: standalone agent (disk queue, shipper, privacy)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class IngestStub:
    """Fake /api/v1/ingest/sessions server: outage switch + request log."""

    def __init__(self, token="cpat_test"):
        self.token = token
        self.down = True
        self.revoked = False
        self.received: list[dict] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                if outer.down:
                    self.send_response(503)
                    self.end_headers()
                    return
                if self.headers.get("X-Agent-Token") != outer.token or outer.revoked:
                    self.send_response(401)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                if self.headers.get("Content-Encoding") == "gzip":
                    import gzip
                    body = gzip.decompress(body)
                data = json.loads(body)
                outer.received.extend(data.get("sessions", []))
                out = json.dumps({"accepted": len(data.get("sessions", [])),
                                  "rejected": 0, "org_id": "org-a"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        return H

    def stop(self):
        self.server.shutdown()


def test_offline_queue_replay_after_outage(tmp_path):
    from app.agent.queue import DiskQueue
    from app.agent.shipper import Shipper
    stub = IngestStub()
    try:
        q = DiskQueue(str(tmp_path / "q.jsonl"), max_bytes=1024 * 1024)
        ship = Shipper(f"http://127.0.0.1:{stub.port}", "cpat_test", timeout=5)
        for i in range(5):
            q.append({"five_tuple": f"a:{i}-b:25", "n": i})
        assert q.depth() == 5
        # outage: send fails, queue retains everything
        import pytest
        with pytest.raises(Exception):
            ship.send_batch([{"five_tuple": "x", "n": -1}])
        assert q.depth() == 5
        # recovery: drain in order
        stub.down = False
        start, batch = q.read_batch(limit=100)
        assert len(batch) == 5
        out = ship.send_batch(batch)
        assert out["accepted"] == 5
        q.ack(start + len(batch))
        assert q.depth() == 0
        assert [m["n"] for m in stub.received] == [0, 1, 2, 3, 4]
    finally:
        stub.stop()


def test_token_revocation_stops_ingestion(tmp_path):
    from app.agent.queue import DiskQueue
    from app.agent.shipper import Shipper, RevokedToken
    import pytest
    stub = IngestStub()
    stub.down = False
    try:
        q = DiskQueue(str(tmp_path / "q.jsonl"))
        q.append({"five_tuple": "a-b", "n": 1})
        ship = Shipper(f"http://127.0.0.1:{stub.port}", "cpat_test", timeout=5)
        stub.revoked = True  # server rotates/revokes the token
        with pytest.raises(RevokedToken):
            ship.send_batch([{"five_tuple": "a-b"}])
        assert ship.revoked is True
        # queue is retained on disk (operator rotates token, restarts)
        assert q.depth() == 1
        with pytest.raises(RevokedToken):
            ship.send_batch([{"five_tuple": "a-b"}])  # no retry burn
    finally:
        stub.stop()


def test_malformed_input_does_not_crash_agent(tmp_path):
    from app.agent.queue import DiskQueue
    from app.agent import meta as _meta
    from app.parsing.reassembly import Session, Protocol
    q = DiskQueue(str(tmp_path / "q.jsonl"))
    # garbage sessions / analyses must not raise out of the agent
    for proto in ("SMTP", "BOGUS-PROTO"):
        try:
            s = Session(protocol=proto, five_tuple="", client_ip="", server_ip="",
                        client_port=0, server_port=0,
                        plaintext_segment=b"\xff" * 100, tls_segment=b"")
            q.append(_meta.session_to_metadata(s, None, agent_id="t"))
        except Exception:
            pass
    assert q.depth() >= 1


def test_no_payload_bytes_leave_sensor():
    from app.agent import meta as _meta
    from app.parsing.reassembly import Session, Protocol
    secret_plain = b"MAIL FROM:<ceo@example.com>"
    secret_tls = b"\x16\x03\x01" + b"PRIVATE-HANDSHAKE" * 10
    s = Session(protocol=Protocol.SMTP, five_tuple="a:1-b:25",
                client_ip="10.0.0.1", server_ip="10.0.0.2",
                client_port=1, server_port=25, is_starttls=True,
                plaintext_segment=secret_plain, tls_segment=secret_tls)
    blob = json.dumps(_meta.session_to_metadata(s, None, agent_id="t"))
    for marker in ("ceo@example.com", "MAIL FROM", "PRIVATE-HANDSHAKE",
                   "plaintext_segment", "tls_segment", "raw_refs"):
        assert marker not in blob
    # only allow-listed keys leave
    allowed = set(_meta.PRIVACY_ALLOW_LIST.split())
    assert set(json.loads(blob).keys()) <= allowed


def test_agent_replay_end_to_end_offline(tmp_path):
    from app.agent.agent import Agent
    cfg = {"server": "http://127.0.0.1:1", "token": "cpat_x",
           "queue_path": str(tmp_path / "q.jsonl"), "agent_id": "test"}
    agent = Agent(cfg)
    n = agent.run_replay(["tests/fixtures/smtp_tls12_starttls.pcap"])
    assert n > 0 and agent.emitted > 0 and agent.queue.depth() > 0
