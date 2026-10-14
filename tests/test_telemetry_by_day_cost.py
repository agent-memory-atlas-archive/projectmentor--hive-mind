"""`by_day` rows carry `tokens` (in + out) and `cost` (USD, None when nothing that day is priced) beside `sessions`;
the 21-day cap and the day order are unchanged. An additive read field (hive-mind-dash#18 gap 2)."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent


def _hv(home, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(home))
    loader = importlib.machinery.SourceFileLoader(f"hvmod_byday_{os.urandom(4).hex()}", str(PROJECT / "hv"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _row(when, tin, tout, cost):
    return {"when": when, "project": "p", "agent": "a", "duration_s": 1, "tokens_in": tin, "tokens_out": tout,
            "cost_usd": cost, "models": {}}


def test_by_day_sums_tokens_and_cost_per_day(tmp_path, monkeypatch):
    hv = _hv(tmp_path / "home", monkeypatch)
    rows = [_row("2026-10-01T10:00:00Z", 10, 5, 0.5), _row("2026-10-01T11:00:00Z", 1, 1, None),
            _row("2026-10-02T10:00:00Z", 7, 3, None), _row("2026-10-03T10:00:00Z", 0, 0, 0.0)]
    out = hv._tel_aggregate(rows, 25, 0)["by_day"]
    assert out == [{"day": "2026-10-01", "sessions": 2, "tokens": 17, "cost": 0.5},
                   {"day": "2026-10-02", "sessions": 1, "tokens": 10, "cost": None},       # nothing priced: None, not 0
                   {"day": "2026-10-03", "sessions": 1, "tokens": 0, "cost": 0.0}]          # priced at zero stays 0.0


def test_by_day_keeps_the_21_day_cap(tmp_path, monkeypatch):
    hv = _hv(tmp_path / "home", monkeypatch)
    rows = [_row(f"2026-09-{d:02d}T10:00:00Z", d, 0, 1.0) for d in range(1, 26)]
    out = hv._tel_aggregate(rows, 25, 0)["by_day"]
    assert len(out) == 21 and out[0]["day"] == "2026-09-05" and out[-1] == {"day": "2026-09-25", "sessions": 1, "tokens": 25, "cost": 1.0}
