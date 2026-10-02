"""Phase 4 Task 4: grouped splits never leak groups across train/test."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _items():
    # (server, week, id): near-duplicates share server groups across weeks.
    out = []
    for srv in ("mx-a:25", "mx-b:25", "mx-c:25", "mx-d:25", "mx-e:25"):
        for week in range(4):
            for dup in range(3):
                out.append({"server": srv, "week": week, "id": f"{srv}-w{week}-{dup}"})
    return out


def test_grouped_split_has_no_leakage():
    from app.ml.splits import grouped_time_split, leakage_report
    items = _items()
    train, test = grouped_time_split(items, lambda m: m["server"], lambda m: m["week"])
    assert train and test
    rep = leakage_report(train, test, lambda m: m["server"])
    assert rep["clean"] is True and rep["leaked_groups"] == []
    # test holds the newest groups/weeks only
    assert max(m["week"] for m in test) == 3
    assert min(m["week"] for m in test) >= min(m["week"] for m in train)


def test_random_split_would_leak_same_data():
    """Control: naive row-wise splitting DOES leak — proving the test is real."""
    import random
    items = _items()
    rnd = random.Random(42)
    shuffled = items[:]
    rnd.shuffle(shuffled)
    test = shuffled[: len(shuffled) // 5]
    train = shuffled[len(shuffled) // 5:]
    from app.ml.splits import leakage_report
    rep = leakage_report(train, test, lambda m: m["server"])
    assert rep["clean"] is False  # same servers on both sides


def test_split_five_tuple_contract():
    from app.parsing.reassembly import split_five_tuple, format_five_tuple
    assert split_five_tuple("10.0.0.1:5000-10.0.0.2:25") == ("10.0.0.1", 5000, "10.0.0.2", 25)
    assert split_five_tuple("10.0.0.1:5000->10.0.0.2:25") == ("10.0.0.1", 5000, "10.0.0.2", 25)
    assert split_five_tuple("garbage") == ("", 0, "", 0)
    assert split_five_tuple("") == ("", 0, "", 0)
    # round-trips with the canonical formatter
    assert split_five_tuple(format_five_tuple("b", 2, "a", 1)) == ("a", 1, "b", 2)
