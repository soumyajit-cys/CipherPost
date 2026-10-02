"""Grouped, time-aware splitting (Phase 4 Task 4).

Random row-wise splits leak near-duplicate sessions from the same flow/server
across train and test, overstating accuracy. These splits assign WHOLE groups
(server endpoint) to test from the latest time window, so a model is always
evaluated on servers and periods it has not seen.
"""
from __future__ import annotations


def server_of(five_tuple: str) -> str:
    try:
        right = five_tuple.split("-", 1)[1]
        host, _, port = right.rpartition(":")
        return f"{host}:{port}"
    except Exception:
        return five_tuple or "unknown"


def grouped_time_split(items: list, group_key, time_key, test_frac: float = 0.2,
                       min_test_groups: int = 1) -> tuple[list, list]:
    """Split items into (train, test) by whole groups, newest groups to test.

    group_key(item) -> group id (e.g. server endpoint); time_key(item) ->
    sortable time (missing/None sorts first = oldest). At least
    min_test_groups newest groups go to test; if that would take everything,
    the single newest group goes to test.
    """
    groups: dict = {}
    for it in items:
        groups.setdefault(group_key(it), []).append(it)

    def _group_time(members) -> tuple:
        times = [time_key(m) for m in members]
        times = [t for t in times if t is not None]
        return (max(times) if times else 0, len(members))

    ordered = sorted(groups.items(), key=lambda kv: _group_time(kv[1]))
    n_test = max(min_test_groups, int(len(ordered) * test_frac + 0.5))
    n_test = min(n_test, max(len(ordered) - 1, 1))
    test_groups = {g for g, _ in ordered[-n_test:]}
    train = [it for g, ms in ordered for it in ms if g not in test_groups]
    test = [it for g, ms in ordered for it in ms if g in test_groups]
    return train, test


def leakage_report(train, test, group_key) -> dict:
    """Detect group leakage between two splits (must be empty when clean)."""
    train_groups = {group_key(it) for it in train}
    test_groups = {group_key(it) for it in test}
    leaked = sorted(train_groups & test_groups)
    return {"train_groups": len(train_groups), "test_groups": len(test_groups),
            "leaked_groups": leaked, "clean": not leaked}
