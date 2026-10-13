"""SN-14: a member whose genesis pin is lost re-pins itself from its OWN journal's genesis, and
`hv doctor` fails loudly until it has. Nothing here reads the network."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_genesis_pin import (T_BACKDATED, T_GENESIS, _device_key, _gov, _loadhv, _on_disk,  # noqa: E402, F401
                              _owner_act, _owner_key, _pin, hv)


def _genesis_here(hv, key=None):
    """A journal whose single genesis was written by THIS device, and its pin."""
    key = key or _owner_key(hv)
    dseed, dpub, hv.NODE_ID = _device_key(hv)                        # this device's own key
    g = _owner_act(hv, key, T_GENESIS, nid=hv.NODE_ID, dev=(dseed, dpub))
    entries = _on_disk(hv, [g])
    return key, g, entries


def _genesis_check(hv):
    return next(c for c in hv._doctor_status() if c["name"] == "genesis")


def test_a_lost_pin_on_the_genesis_device_is_restored_from_the_journal(hv, capsys):
    _, g, entries = _genesis_here(hv)
    want = _pin(hv, g)
    hv.GENESIS_PIN_PATH.unlink()
    assert hv._load_genesis_pin() is None and hv._genesis_pin_lost(entries)
    assert hv._restore_genesis_pin(entries) == want
    assert hv._load_genesis_pin() == want
    assert "re-pinned" in capsys.readouterr().err


def test_a_corrupt_pin_file_counts_as_lost(hv):
    _, g, entries = _genesis_here(hv)
    want = _pin(hv, g)
    hv.GENESIS_PIN_PATH.write_text("{\"owner_id\": ")
    assert hv._restore_genesis_pin(entries) == want


def test_an_admitted_device_is_not_restored(hv):
    key = _owner_key(hv)
    g = _owner_act(hv, key, T_GENESIS)
    admit = _gov(hv, {"action": "admit", "device_id": hv.NODE_ID, "principal": "p"}, key[0], key[1],
                 "2026-01-02T00:00:00Z", seq=2)
    entries = _on_disk(hv, [g, admit])
    assert not hv._genesis_pin_lost(entries) and hv._restore_genesis_pin(entries) is None


def test_network_batch_makes_a_non_member_pin_the_attackers_genesis(hv):
    assert hv._load_genesis_pin() is None
    atk = _owner_key(hv)
    g = _owner_act(hv, atk, T_GENESIS, nid="atkdev")
    admit = _gov(hv, {"action": "admit", "device_id": hv.NODE_ID, "principal": "p"}, atk[0], atk[1],
                 "2026-01-02T00:00:00Z", seq=2, nid="atkdev")
    hv.append_foreign_entries([g, admit])
    hv.append_foreign_entries([])
    assert hv._load_genesis_pin() is None


def test_a_genesis_signed_by_another_device_is_not_ours(hv):
    dseed, dpub, did = _device_key(hv)
    g = _owner_act(hv, _owner_key(hv), T_GENESIS, nid=did, dev=(dseed, dpub))
    entries = _on_disk(hv, [g])
    assert not hv._genesis_pin_lost(entries)


def test_an_unsigned_genesis_claiming_our_node_id_is_not_ours(hv):
    g = _owner_act(hv, _owner_key(hv), T_GENESIS, nid=hv.NODE_ID)       # no device signature: anyone can write this
    entries = _on_disk(hv, [g])
    assert not hv._genesis_pin_lost(entries) and hv._restore_genesis_pin(entries) is None


def test_a_device_that_is_not_a_member_is_never_pinned(hv):
    """A node that only holds a journal (no admit, not the genesis writer) has not been pinned by any
    flow, so its first pin stays the operator's act: no trust on first use."""
    entries = _on_disk(hv, [_owner_act(hv, _owner_key(hv), T_GENESIS)])
    assert not hv._genesis_pin_lost(entries)
    assert hv._restore_genesis_pin(entries) is None and hv._load_genesis_pin() is None


def test_two_candidates_are_left_to_the_operator(hv):
    key = _owner_key(hv)
    entries = _on_disk(hv, [_owner_act(hv, key, T_GENESIS, nid=hv.NODE_ID),
                            _owner_act(hv, _owner_key(hv), T_BACKDATED, nid="rival")])
    assert hv._restore_genesis_pin(entries) is None
    assert hv._load_genesis_pin() is None


def test_ingest_restores_the_pin_from_the_journal_before_judging_the_batch(hv):
    real, attacker = _owner_key(hv), _owner_key(hv)
    _, g, entries = _genesis_here(hv, real)
    _pin(hv, g)
    hv.GENESIS_PIN_PATH.unlink()
    rival = _owner_act(hv, attacker, T_BACKDATED, nid="rival")      # backdated: wins under the legacy rule
    hv.append_foreign_entries([rival])
    assert hv._load_genesis_pin()["genesis_hash"] == hv.compute_hash(g)
    stored = [e for e in hv.merkle.read_all_entries(hv.JOURNAL_DIR) if e["node_id"] == "rival"]
    assert stored == []
    assert hv._governance_state(hv.merkle.read_all_entries(hv.JOURNAL_DIR))["owner_id"] == real[2]


def test_doctor_fails_loudly_on_a_lost_pin_then_passes_after_the_heal(hv):
    _, g, entries = _genesis_here(hv)
    _pin(hv, g)
    hv.GENESIS_PIN_PATH.unlink()
    c = _genesis_check(hv)
    assert c["status"] == "fail" and "LOST" in c["detail"]
    hv._heal_genesis_pin(entries, False)                             # what the 15-minute `doctor --fix` runs
    assert _genesis_check(hv)["status"] == "ok"


def test_a_never_pinned_non_member_stays_a_warning(hv):
    _on_disk(hv, [_owner_act(hv, _owner_key(hv), T_GENESIS)])
    assert _genesis_check(hv)["status"] == "warn"
