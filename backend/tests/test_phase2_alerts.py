"""Phase 2 Task 2: shared durable alert state (fakeredis, no real infra)."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fakeredis


def _finding(rule="weak-cipher-suite", ft="10.0.0.1:5000-10.0.0.2:25", sev="high"):
    return {"rule_id": rule, "five_tuple": ft, "max_severity": sev,
            "severity": sev, "title": rule, "description": "d",
            "protocol": "SMTP", "org_id": "org-a", "findings": [],
            "risk_score": 80.0}


def test_restart_no_duplicate_alert():
    """A restart (new dispatcher, same Redis) must not re-alert the group."""
    from app.live.alerts import AlertDispatcher
    r = fakeredis.FakeRedis(decode_responses=False)
    sent = []
    d1 = AlertDispatcher(redis_client=r, adapters=[], group_hold_seconds=0)
    d1.min_sev = 0
    d1.adapters = []
    # capture dispatches by wrapping _dispatch's send path: use a fake adapter
    class Rec:
        name = "rec"
        def __init__(self, out): self.out = out
        def send(self, alert): self.out.append(alert); return True
    d1.adapters = [Rec(sent)]
    f = _finding()
    # emulate entry handling: severity gate + dispatch (hold=0 flushes at once)
    d1.groups.add(f)
    for g in d1.groups.flush_expired(now=10**10):
        m = dict(f); m.update({k: g[k] for k in (
            "rule_id", "severity", "occurrence_count") if k in g})
        d1._dispatch(m)
    assert len(sent) == 1
    # "Restart": brand-new dispatcher on the same Redis.
    d2 = AlertDispatcher(redis_client=r, adapters=[Rec(sent)], group_hold_seconds=0)
    d2.min_sev = 0
    d2.groups.add(_finding())
    for g in d2.groups.flush_expired(now=10**10):
        m = dict(_finding()); m.update({k: g[k] for k in (
            "rule_id", "severity", "occurrence_count") if k in g})
        d2._dispatch(m)
    assert len(sent) == 1  # no duplicate after restart


def test_two_dispatchers_share_rate_budget():
    from app.live.alerts import AlertDispatcher
    r = fakeredis.FakeRedis(decode_responses=False)
    d1 = AlertDispatcher(redis_client=r, adapters=[])
    d2 = AlertDispatcher(redis_client=r, adapters=[])
    d1.state.rate_per_minute = 2
    d2.state.rate_per_minute = 2
    assert d1.state.check_rate() is True
    assert d2.state.check_rate() is True
    # Budget is shared: third claim (either instance) is limited.
    assert d1.state.check_rate() is False


def test_failing_channel_does_not_block_others():
    from app.live.alerts import AlertDispatcher
    import fakeredis
    r = fakeredis.FakeRedis(decode_responses=False)
    good = []

    class Bad:
        name = "bad"
        def send(self, alert): raise ConnectionError("webhook down")

    class Good:
        name = "good"
        def __init__(self, out): self.out = out
        def send(self, alert): self.out.append(alert); return True

    d = AlertDispatcher(redis_client=r, adapters=[Bad(), Good(good)],
                        group_hold_seconds=0)
    d.min_sev = 0
    # Avoid DB writes: stub delivery recording + persist/publish.
    d._record_deliveries = lambda alert, results: setattr(
        d, "_last_results", list(results))
    d._persist_alert = lambda alert: None
    from app.live import streams as bus
    _pub = bus.publish_alert
    _not = bus.notify
    bus.publish_alert = lambda *a, **k: None
    bus.notify = lambda *a, **k: None
    try:
        d._dispatch(_finding())
    finally:
        bus.publish_alert = _pub
        bus.notify = _not
    assert len(good) == 1  # good channel still delivered
    names = {n for n, _, _ in d._last_results}
    assert names == {"bad", "good"}
    assert dict((n, s) for n, s, _ in d._last_results)["good"] is True
    assert dict((n, s) for n, s, _ in d._last_results)["bad"] is False


def test_grouping_merges_same_rule_same_server():
    from app.live.alert_state import GroupBuffer
    gb = GroupBuffer(hold_seconds=60.0)
    gb.add(_finding(ft="1.1.1.1:100-9.9.9.9:25"), now=1000.0)
    gb.add(_finding(ft="2.2.2.2:200-9.9.9.9:25"), now=1001.0)
    gb.add(_finding(ft="3.3.3.3:300-8.8.8.8:25"), now=1002.0)  # different server
    assert len(gb) == 2
    ready = gb.flush_expired(now=2000.0)
    by_server = {g["server"]: g for g in ready}
    assert by_server["9.9.9.9"]["occurrence_count"] == 2
    assert by_server["8.8.8.8"]["occurrence_count"] == 1
    assert by_server["9.9.9.9"]["first_seen"] <= by_server["9.9.9.9"]["last_seen"]
