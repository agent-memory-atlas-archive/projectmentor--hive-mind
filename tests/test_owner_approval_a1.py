"""Owner approval slice A1 (design: hive-mind-private docs/design/owner_approval_and_hygiene.md sections 4.3 and 6, row A1).

The gated agent signs only what an enrolled approver's passkey approved (a presented ticket, single or batch) or what a
live delegation covers. Policy, the WebAuthn check, the membership rule and the used-ticket set run in-process; the hard
ticket gate, the break-glass path and plan == approved == signed run the real `hive-mind` CLI and a real agent process.
The passkeys are made here (a pure-Python P-256 signer and the bundled Ed25519), so no phone and no extra dependency."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import approvers  # noqa: E402
import ed25519  # noqa: E402
import merkle  # noqa: E402
import owner_agent  # noqa: E402
import p256  # noqa: E402
from hivemind.crypto import signer as sigseam  # noqa: E402
from test_owner_agent import (DEV, DEV2, LINUX, PASS, PUB, SEED, FakeClocks, body, hive, policy, _sock)  # noqa: E402,F401

RP = "owner.example.ts.net"
ORIGIN = f"https://{RP}:8444"
OWNER = sigseam.FileSigner(SEED)


# ---- a passkey made here -----------------------------------------------------------------------------------------------

def _der_int(v):
    raw = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    raw = b"\x00" + raw if raw[0] & 0x80 else raw
    return b"\x02" + bytes([len(raw)]) + raw


def _der(r, s):
    inner = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(inner)]) + inner


class Passkey:
    def __init__(self, name, alg="es256", kind="phone"):
        self.id, self.alg, self.kind, self.count = approvers.b64u(name.encode()), alg, kind, 0
        self.seed = hashlib.sha256(b"passkey " + name.encode()).digest()
        self.d = int.from_bytes(self.seed, "big") % (p256.N - 1) + 1
        if alg == "es256":
            x, y = p256._mul(self.d, p256.G)
            self.pub = x.to_bytes(32, "big") + y.to_bytes(32, "big")
        else:
            self.pub = ed25519.pub_from_seed(self.seed)

    def record(self, label=None, enrolled=None, by="owner"):
        return {"id": self.id, "alg": -7 if self.alg == "es256" else -8, "pub": base64.b64encode(self.pub).decode(),
                "label": label or self.id, "kind": self.kind, "enrolled": enrolled or 5 * 10 ** 8, "by": by}

    def assertion(self, challenge, rp=RP, origin=ORIGIN, flags=0x05, count=None, ctype="webauthn.get", cross=None,
                  tamper=False, extra_auth=b"", cred=None):
        self.count = self.count + 1 if count is None else count
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, "big") + extra_auth
        cd = {"type": ctype, "challenge": approvers.b64u(challenge), "origin": origin}
        if cross is not None:
            cd["crossOrigin"] = cross
        cdj = json.dumps(cd).encode()
        msg = auth + hashlib.sha256(cdj).digest()
        if self.alg == "es256":
            e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
            k = int.from_bytes(hashlib.sha256(self.seed + msg).digest(), "big") % (p256.N - 1) + 1
            r = p256._mul(k, p256.G)[0] % p256.N
            sig = _der(r, pow(k, -1, p256.N) * (e + r * self.d) % p256.N)
        else:
            sig = ed25519.sign(msg, self.seed)
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"credentialId": cred or self.id, "authenticatorData": approvers.b64u(auth),
                "clientDataJSON": approvers.b64u(cdj), "signature": approvers.b64u(sig)}


def ticket_assertion(key, tickets, **kw):
    pairs = [(t["id"], approvers.acts_hash(t["acts"])) for t in tickets]
    return key.assertion(approvers.ticket_challenge(pairs), **kw)


def member_assertion(key, kind, rec, **kw):
    return key.assertion(approvers.member_challenge(kind, rec), **kw)


def h(b):
    return hashlib.sha256(b).hexdigest()


def gated(tmp_path, keys, clk=None, **kw):
    d = tmp_path / "state"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    recs = [approvers.sign_record(k.record(), OWNER) for k in keys]
    (d / "approvers.json").write_text(json.dumps(recs))
    return owner_agent.Agent(SEED, "/nonexistent/x.sock", 900, kw.pop("pol", None) or policy(), clocks=clk or FakeClocks(),
                             gated=True, state_dir=str(d), rp_id=RP, origin=ORIGIN, **kw)


def present(a, key, tickets, **kw):
    return a._handle({"op": "present", "tickets": tickets, "assertion": ticket_assertion(key, tickets, **kw)}, 1)


def sign(a, b, ticket=None):
    req = {"body": base64.b64encode(b).decode()}
    if ticket is not None:
        req["ticket"] = ticket
    return a._sign(req, 1)


def member(a, kind, rec, assertions):
    return a._handle({"op": "member", "kind": kind, "record": rec, "assertions": assertions}, 1)


PHONE, DESKTOP, KEY3 = Passkey("phone"), Passkey("desktop", "eddsa", "desktop"), Passkey("hwkey", kind="key")
SETCFG = body(action="set-config", key="x-demo:poll", value="30")


# ---- P-256 (verify only) ---------------------------------------------------------------------------------------------------

RFC_PUB = bytes.fromhex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
                        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")


@pytest.mark.parametrize("msg,r,s", [
    (b"sample", "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
     "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
    (b"test", "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
     "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
])
def test_p256_verifies_the_rfc6979_vectors_and_refuses_a_changed_message(msg, r, s):
    assert p256.verify(RFC_PUB, msg, int(r, 16), int(s, 16))
    assert not p256.verify(RFC_PUB, msg + b"!", int(r, 16), int(s, 16))


def test_p256_verifies_a_signature_made_by_openssl():
    pub = bytes.fromhex("724a1702ce6fec69a892c6e79d737ee25169c8c59abdd338f20fc496a75c3dd97978ff309350db1a22b65db510c904b4"
                        "b7e8d01abf064db3f111018861f8caa5")
    der = bytes.fromhex("3046022100f9b896b39ddcc3e05b2c90343a5509c5a3a1a18c96f1249f6e8467069c34f236022100f5e863b3b6b7145fb6d2"
                        "cede16d944e05cbfe64b20617463e3f9bc31e6f0aed4")
    rs = p256.parse_der(der)
    assert rs and p256.verify(pub, b"openssl-made message", *rs)
    assert not p256.verify(pub, b"openssl-made messagf", *rs)


def test_p256_refuses_an_off_curve_key_zero_and_out_of_range_values():
    r, s = int("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16), 1
    assert not p256.verify(RFC_PUB[:-1] + b"\x00", b"sample", r, s)
    assert not p256.verify(RFC_PUB, b"sample", 0, s) and not p256.verify(RFC_PUB, b"sample", r, 0)
    assert not p256.verify(RFC_PUB, b"sample", p256.N, s) and not p256.verify(RFC_PUB[:63], b"sample", r, s)


@pytest.mark.parametrize("der", [b"", b"\x30\x00", b"\x30\x06\x02\x01\x01\x02\x01\x01\x00",       # trailing byte
                                 b"\x30\x08\x02\x02\x00\x01\x02\x02\x00\x01",                      # non-minimal integers
                                 b"\x30\x06\x02\x01\x81\x02\x01\x01",                              # negative integer
                                 b"\x31\x06\x02\x01\x01\x02\x01\x01"])
def test_the_der_signature_parser_is_strict(der):
    assert p256.parse_der(der) is None


# ---- the WebAuthn assertion ----------------------------------------------------------------------------------------------

CH = hashlib.sha256(b"challenge").digest()


def _verify(key, allow_synced=False, last=0, **kw):
    rec = approvers.sign_record(key.record(), OWNER)
    return approvers.verify_assertion(rec, key.assertion(CH, **kw), CH, RP, ORIGIN, allow_synced, last)


@pytest.mark.parametrize("key", [PHONE, DESKTOP], ids=["es256", "eddsa"])
def test_a_good_assertion_verifies_for_both_algorithms(key):
    ok, why, count = _verify(key)
    assert ok, why
    assert count == key.count


@pytest.mark.parametrize("why,kw", [
    ("another rpId", dict(rp="evil.example")),
    ("user presence missing", dict(flags=0x04)),
    ("user verification missing", dict(flags=0x01)),
    ("backup-eligible credential", dict(flags=0x0D)),
    ("backup state without eligibility", dict(flags=0x15)),
    ("attested-data flag", dict(flags=0x45)),
    ("another origin", dict(origin="https://owner.example.ts.net:9999")),
    ("cross-origin", dict(cross=True)),
    ("webauthn.create", dict(ctype="webauthn.create")),
    ("a bad signature", dict(tamper=True)),
    ("trailing authenticator data", dict(extra_auth=b"\x00")),
    ("another credential id", dict(cred="b3RoZXI")),
])
def test_an_assertion_that_breaks_a_webauthn_rule_is_refused(why, kw):
    ok, reason, _ = _verify(Passkey("phone"), **kw)
    assert not ok, why


def test_a_synced_credential_passes_only_with_allow_synced():
    assert not _verify(Passkey("phone"), flags=0x0D)[0]
    assert _verify(Passkey("phone"), allow_synced=True, flags=0x0D)[0]


def test_the_challenge_must_be_the_one_being_approved():
    rec = approvers.sign_record(PHONE.record(), OWNER)
    assert not approvers.verify_assertion(rec, PHONE.assertion(hashlib.sha256(b"other").digest()), CH, RP, ORIGIN)[0]


def test_the_sign_count_must_move_forward_but_two_zeros_are_allowed():
    k = Passkey("phone")
    assert not _verify(k, count=5, last=5)[0] and not _verify(k, count=4, last=5)[0] and _verify(k, count=6, last=5)[0]
    assert _verify(k, count=0, last=0)[0] and not _verify(k, count=0, last=3)[0]


# ---- present, sign: the hard ticket gate ----------------------------------------------------------------------------------

def test_a_presented_ticket_signs_exactly_its_bodies_once(tmp_path):
    a = gated(tmp_path, [PHONE])
    t = {"id": "T1", "acts": [h(SETCFG)]}
    assert present(a, PHONE, [t])["ok"]
    r = sign(a, SETCFG, "T1")
    assert r["ok"] and ed25519.verify(SETCFG, base64.b64decode(r["sig"]), ed25519.pub_from_seed(SEED))
    assert "already signed" in sign(a, SETCFG, "T1")["why"]
    other = body(action="set-config", key="x-demo:poll", value="31")
    assert "not one of the ticket" in sign(a, other, "T1")["why"]
    assert "not presented" in sign(a, SETCFG, "T9")["why"]


def test_a_gated_agent_signs_nothing_without_a_ticket_or_delegation(tmp_path):
    a = gated(tmp_path, [PHONE])
    for b in (SETCFG, body(action="admit", device_id=DEV, module="demo", principal="op")):
        assert not sign(a, b)["ok"]


def test_a_ticket_signs_an_arbitrary_revoke_and_a_core_key_but_never_the_passphrase_only_acts(tmp_path):
    a = gated(tmp_path, [PHONE])
    ok = [body(action="revoke", device_id=DEV2), body(action="set-config", key="quorum_m", value=2),
          body(action="admit", device_id=DEV, module="demo", principal="op")]
    never = [body(action="transfer", to="x"), body(action="rotate"), body(retracts_ref="a", reason="r"),
             body(kind="supports", from_ref="a", to_ref="b"), body(action="frobnicate"),
             body(action="admit", device_id=DEV, principal="op"),                       # a voting device
             body(action="set-config", key="x-demo:k", value=5), body(action="set-config", key="not a key", value="1"),
             body(action="admit", device_id=DEV, module="demo", principal="op", extra="1")]
    assert present(a, PHONE, [{"id": "T", "acts": [h(b) for b in ok + never]}])["ok"]
    assert all(sign(a, b, "T")["ok"] for b in ok)
    assert not any(sign(a, b, "T")["ok"] for b in never)


def test_an_admit_of_an_admitted_or_purged_device_is_refused_even_under_a_ticket(tmp_path):
    for n, state in enumerate(("admitted", "purged")):
        a = gated(tmp_path, [PHONE], pol=policy(states={DEV: state}))
        b = body(action="admit", device_id=DEV, module="demo", principal="op")
        assert present(a, PHONE, [{"id": f"T-{state}", "acts": [h(b)]}], count=10 + n)["ok"]
        assert not sign(a, b, f"T-{state}")["ok"]


def test_a_ticket_expires_after_fifteen_minutes(tmp_path):
    clk = FakeClocks()
    a = gated(tmp_path, [PHONE], clk=clk)
    assert present(a, PHONE, [{"id": "T", "acts": [h(SETCFG)]}])["ok"]
    clk.advance(owner_agent.TICKET_LIVE + 1)
    assert not sign(a, SETCFG, "T")["ok"]


def test_a_batch_tap_covers_every_ticket_in_it_and_the_hash_miss_is_refused(tmp_path):
    a = gated(tmp_path, [PHONE])
    b2 = body(action="set-config", key="x-demo:other", value="1")
    ts = [{"id": "A", "acts": [h(SETCFG)]}, {"id": "B", "acts": [h(b2)]}]
    assert present(a, PHONE, ts)["ok"]
    assert sign(a, SETCFG, "A")["ok"] and sign(a, b2, "B")["ok"]
    assert not sign(a, b2, "A")["ok"]                                                  # B's act under A's ticket
    # an assertion over one act set cannot approve another
    forged = [{"id": "C", "acts": [h(SETCFG), h(b2)]}]
    a2 = gated(tmp_path, [PHONE])
    r = a2._handle({"op": "present", "tickets": forged,
                    "assertion": ticket_assertion(PHONE, [{"id": "C", "acts": [h(SETCFG)]}])}, 1)
    assert not r["ok"] and "challenge" in r["why"]


def test_the_batch_size_is_bounded_and_ticket_shapes_are_checked(tmp_path):
    a = gated(tmp_path, [PHONE])
    many = [{"id": f"T{i}", "acts": [h(bytes([i]))]} for i in range(owner_agent.BATCH_MAX + 1)]
    assert not present(a, PHONE, many)["ok"]
    for bad in ([{"id": "x y", "acts": [h(b"a")]}], [{"id": "T", "acts": []}], [{"id": "T", "acts": ["zz"]}],
                [{"id": "T", "acts": [h(b"a"), h(b"a")]}], [{"id": "T", "acts": [h(b"a")]}, {"id": "T", "acts": [h(b"b")]}],
                [{"id": "T", "acts": [h(b"a")], "x": 1}]):
        assert not present(a, PHONE, bad)["ok"]


def test_a_ticket_id_is_single_use_across_agent_restarts(tmp_path):
    a = gated(tmp_path, [PHONE])
    t = [{"id": "T1", "acts": [h(SETCFG)]}]
    assert present(a, PHONE, t)["ok"]
    assert not present(a, PHONE, t)["ok"]
    used = tmp_path / "state" / "used-tickets.json"
    assert used.stat().st_mode & 0o777 == 0o600 and "T1" in json.loads(used.read_text())["used"]
    a2 = gated(tmp_path, [PHONE])                                       # a restart: the same files, no memory
    assert "already used" in present(a2, PHONE, t)["why"]
    assert not sign(a2, SETCFG, "T1")["ok"]                              # and no live ticket survives the restart


def test_the_used_ticket_set_is_written_before_the_first_signature_and_pruned_at_24h(tmp_path):
    clk = FakeClocks()
    a = gated(tmp_path, [PHONE], clk=clk)
    assert present(a, PHONE, [{"id": "T1", "acts": [h(SETCFG)]}])["ok"]
    assert "T1" in json.loads((tmp_path / "state" / "used-tickets.json").read_text())["used"]     # before any sign
    clk.advance(owner_agent.USED_KEEP + 5)
    a2 = gated(tmp_path, [PHONE], clk=clk)
    assert "T1" not in a2.used


def test_an_unenrolled_revoked_or_wrong_credential_cannot_present(tmp_path):
    a = gated(tmp_path, [PHONE])
    stranger = Passkey("stranger")
    assert "enrolled" in present(a, stranger, [{"id": "T", "acts": [h(SETCFG)]}])["why"]
    a.approvers[PHONE.id] = {**a.approvers[PHONE.id], "revoked": 1}
    assert not present(a, PHONE, [{"id": "T", "acts": [h(SETCFG)]}])["ok"]
    a = gated(tmp_path, [PHONE])
    forged = dict(PHONE.record(), pub=base64.b64encode(stranger.pub).decode())             # a record the owner never signed
    (tmp_path / "state" / "approvers.json").write_text(json.dumps([forged]))
    with pytest.raises(ValueError):
        gated_raw = owner_agent.Agent(SEED, "/x", 900, policy(), clocks=FakeClocks(), gated=True,
                                      state_dir=str(tmp_path / "state"), rp_id=RP, origin=ORIGIN)


def test_a_cloned_authenticator_is_refused_by_the_sign_count(tmp_path):
    a = gated(tmp_path, [PHONE])
    assert present(a, PHONE, [{"id": "A", "acts": [h(SETCFG)]}], count=7)["ok"]
    assert "sign count" in present(a, PHONE, [{"id": "B", "acts": [h(SETCFG)]}], count=7)["why"]


def test_an_ungated_agent_refuses_present_and_a_ticketed_sign():
    a = owner_agent.Agent(SEED, "/x", 900, policy(), clocks=FakeClocks())
    assert not a._handle({"op": "present", "tickets": [], "assertion": {}}, 1)["ok"]
    assert "not in gated mode" in sign(a, SETCFG, "T")["why"]
    assert sign(a, SETCFG)["ok"]                                                          # the plain unlock is unchanged


def test_a_gated_agent_starts_only_with_enough_approvers_and_has_no_timer(tmp_path):
    with pytest.raises(ValueError):
        gated(tmp_path, [])
    with pytest.raises(ValueError):
        gated(tmp_path, [PHONE], approvers_min=2)
    clk = FakeClocks()
    a = gated(tmp_path, [PHONE, DESKTOP], clk=clk, approvers_min=2)
    clk.advance(100 * 3600, suspended=3600)                                               # a long uptime and a suspend
    assert a.tick() is None and a.why_locked is None
    st = a.status()
    assert st["gated"] and st["idle_left"] is None and not owner_agent.gate_ok(st, [])


def test_the_chain_signer_under_a_ticket_never_falls_back():
    calls = []

    class Refusing:
        last_act = ""

        def sign(self, message, ticket=None):
            raise owner_agent.AgentError("not in the ticket")

    class Locked(Exception):
        pass

    s = owner_agent.ChainSigner(Refusing(), b"\0" * 32, lambda: calls.append("seed") or sigseam.FileSigner(SEED),
                                ticket="T1", fail=Locked)
    with pytest.raises(Locked, match="no passphrase fallback"):
        s.sign(b"x")
    assert calls == []
    plain = owner_agent.ChainSigner(Refusing(), sigseam.FileSigner(SEED).public_key(), lambda: calls.append("seed") or sigseam.FileSigner(SEED),
                                    say=lambda m: None)
    assert plain.sign(b"x") and calls == ["seed"]                                          # without a ticket it still falls back


# ---- the membership rule ----------------------------------------------------------------------------------------------------

def now_of(a):
    return int(a.clk.wall())


def new_approver(a, key, by):
    return key.record(enrolled=now_of(a), by=by)


def test_with_one_approver_one_tap_adds_an_approver(tmp_path):
    a = gated(tmp_path, [PHONE])
    rec = new_approver(a, DESKTOP, PHONE.id)
    assert not member(a, "approver-add", rec, [])["ok"]
    r = member(a, "approver-add", rec, [member_assertion(PHONE, "approver-add", rec)])
    assert r["ok"] and approvers.verify_record(r["record"], PUB)
    assert DESKTOP.id in a.approvers
    again = member(a, "approver-add", rec, [member_assertion(PHONE, "approver-add", rec)])
    assert not again["ok"]                                                                 # ids are never reused


def test_with_two_approvers_adding_one_needs_two_different_passkeys(tmp_path):
    a = gated(tmp_path, [PHONE, DESKTOP])
    rec = new_approver(a, KEY3, PHONE.id)
    one = [member_assertion(PHONE, "approver-add", rec)]
    assert "needs 2" in member(a, "approver-add", rec, one)["why"]
    twice = one + [member_assertion(PHONE, "approver-add", rec)]
    assert not member(a, "approver-add", rec, twice)["ok"]
    assert member(a, "approver-add", rec, one + [member_assertion(DESKTOP, "approver-add", rec)])["ok"]


def test_an_assertion_for_one_record_cannot_authorise_another(tmp_path):
    a = gated(tmp_path, [PHONE])
    rec, evil = new_approver(a, DESKTOP, PHONE.id), new_approver(a, KEY3, PHONE.id)
    assert not member(a, "approver-add", evil, [member_assertion(PHONE, "approver-add", rec)])["ok"]
    t = [{"id": "T", "acts": [h(SETCFG)]}]
    assert not member(a, "approver-add", rec, [ticket_assertion(PHONE, t)])["ok"]         # an act ticket is not a membership tap
    assert not member(a, "delegate-add", rec, [member_assertion(PHONE, "approver-add", rec)])["ok"]


def test_membership_records_are_checked_for_freshness_and_by(tmp_path):
    a = gated(tmp_path, [PHONE])
    stale = DESKTOP.record(enrolled=now_of(a) - 3600, by=PHONE.id)
    assert "not now" in member(a, "approver-add", stale, [member_assertion(PHONE, "approver-add", stale)])["why"]
    wrong_by = new_approver(a, DESKTOP, "someone")
    assert "`by`" in member(a, "approver-add", wrong_by, [member_assertion(PHONE, "approver-add", wrong_by)])["why"]
    bad = dict(new_approver(a, DESKTOP, PHONE.id), kind="laptop")
    assert not member(a, "approver-add", bad, [member_assertion(PHONE, "approver-add", bad)])["ok"]


def revoke_rec(a, key, at=None):
    return {**{k: v for k, v in a.approvers[key.id].items() if k != "owner_sig"}, "revoked": at or now_of(a)}


def test_revoking_an_approver_takes_one_other_passkey_and_the_only_one_is_break_glass(tmp_path):
    a = gated(tmp_path, [PHONE])
    rec = revoke_rec(a, PHONE)
    r = member(a, "approver-revoke", rec, [member_assertion(PHONE, "approver-revoke", rec)])
    assert not r["ok"] and "break-glass" in r["why"]
    a = gated(tmp_path, [PHONE, DESKTOP])
    rec = revoke_rec(a, PHONE)
    assert not member(a, "approver-revoke", rec, [member_assertion(PHONE, "approver-revoke", rec)])["ok"]   # not by the target
    assert member(a, "approver-revoke", rec, [member_assertion(DESKTOP, "approver-revoke", rec)])["ok"]
    assert "revoked" in a.approvers[PHONE.id]
    assert "enrolled" in present(a, PHONE, [{"id": "T", "acts": [h(SETCFG)]}])["why"]
    assert present(a, DESKTOP, [{"id": "T", "acts": [h(SETCFG)]}])["ok"]


def test_an_approver_revoke_may_not_leave_fewer_than_approvers_min(tmp_path):
    a = gated(tmp_path, [PHONE, DESKTOP], approvers_min=2)
    rec = revoke_rec(a, PHONE)
    assert "approvers.min" in member(a, "approver-revoke", rec, [member_assertion(DESKTOP, "approver-revoke", rec)])["why"]


def test_a_revoke_must_be_the_stored_record_plus_a_current_stamp(tmp_path):
    a = gated(tmp_path, [PHONE, DESKTOP])
    for rec in ({**revoke_rec(a, PHONE), "label": "renamed"}, revoke_rec(a, PHONE, at=now_of(a) - 3600)):
        assert not member(a, "approver-revoke", rec, [member_assertion(DESKTOP, "approver-revoke", rec)])["ok"]


def deleg(a, by, **kw):
    now = now_of(a)
    rec = {"id": "d1", "scope": {"acts": ["set-config"], "keys": ["x-demo:*"]}, "per_day": 3, "expires": now + 7 * 86400,
           "created": now, "by": by}
    rec.update(kw)
    return rec


def add_deleg(a, key, **kw):
    rec = deleg(a, key.id, **kw)
    return member(a, "delegate-add", rec, [member_assertion(key, "delegate-add", rec)])


def test_a_delegation_is_one_tap_with_one_approver_and_obeys_the_ceilings(tmp_path):
    a = gated(tmp_path, [PHONE])
    assert add_deleg(a, PHONE)["ok"]
    assert not add_deleg(a, PHONE)["ok"]                                                   # the id is used
    assert not add_deleg(a, PHONE, id="d2", per_day=201)["ok"]
    assert not add_deleg(a, PHONE, id="d3", expires=now_of(a) + 31 * 86400)["ok"]
    assert not add_deleg(a, PHONE, id="d4", scope={"acts": ["set-config"], "keys": ["quorum_m"]})["ok"]
    assert not add_deleg(a, PHONE, id="d5", scope={"acts": ["revoke"], "keys": ["x-demo:*"]})["ok"]
    assert not add_deleg(a, PHONE, id="d6", scope={"acts": ["set-config", "admit"], "keys": ["x-demo:*"]})["ok"]
    assert not add_deleg(a, PHONE, id="d7", scope={"acts": ["admit"], "admit_modules": []})["ok"]


def test_a_delegation_signs_inside_its_scope_and_cap_and_nowhere_else(tmp_path):
    a = gated(tmp_path, [PHONE])
    assert add_deleg(a, PHONE, per_day=2)["ok"]
    assert sign(a, body(action="set-config", key="x-demo:poll", value="1"))["ok"]
    assert sign(a, body(action="set-config", key="x-demo:poll", value="2"))["ok"]
    capped = sign(a, body(action="set-config", key="x-demo:poll", value="3"))
    assert not capped["ok"] and "cap" in capped["why"]
    for b in (body(action="set-config", key="x-other:k", value="1"),                       # another module
              body(action="set-config", key="quorum_m", value="2"),                        # a core key
              body(action="revoke", device_id=DEV),
              body(action="admit", device_id=DEV, module="demo", principal="op"),
              body(action="transfer", to="x")):
        assert not sign(a, b)["ok"]


def test_an_admit_delegation_names_its_modules_and_the_count_survives_a_restart(tmp_path):
    a = gated(tmp_path, [PHONE])
    sc = {"acts": ["admit"], "admit_modules": ["demo"]}
    assert add_deleg(a, PHONE, id="adm", scope=sc, per_day=1)["ok"]
    assert sign(a, body(action="admit", device_id=DEV, module="demo", principal="op"))["ok"]
    assert not sign(a, body(action="admit", device_id=DEV2, module="other", principal="op"))["ok"]
    a2 = gated(tmp_path, [PHONE])
    assert "adm" in a2.delegations
    r = sign(a2, body(action="admit", device_id=DEV2, module="demo", principal="op"))
    assert not r["ok"] and "cap" in r["why"]                                                # the day's count was kept


def test_an_expired_or_revoked_delegation_signs_nothing_and_an_approver_revoke_clears_all(tmp_path):
    clk = FakeClocks()
    a = gated(tmp_path, [PHONE, DESKTOP], clk=clk)
    rec = deleg(a, PHONE.id)
    assert member(a, "delegate-add", rec, [member_assertion(PHONE, "delegate-add", rec), member_assertion(DESKTOP, "delegate-add", rec)])["ok"]
    b = body(action="set-config", key="x-demo:poll", value="1")
    clk.advance(8 * 86400)
    assert not sign(a, b)["ok"]
    (tmp_path / "b").mkdir()
    a = gated(tmp_path / "b", [PHONE, DESKTOP])
    rec = deleg(a, PHONE.id, id="d9")
    assert member(a, "delegate-add", rec, [member_assertion(PHONE, "delegate-add", rec), member_assertion(DESKTOP, "delegate-add", rec)])["ok"]
    assert sign(a, b)["ok"]
    rv = {**{k: v for k, v in a.delegations["d9"].items() if k != "owner_sig"}, "revoked": now_of(a)}
    assert member(a, "delegate-revoke", rv, [member_assertion(DESKTOP, "delegate-revoke", rv)])["ok"]
    assert not sign(a, b)["ok"]
    rec = deleg(a, PHONE.id, id="d10")
    assert member(a, "delegate-add", rec, [member_assertion(PHONE, "delegate-add", rec), member_assertion(DESKTOP, "delegate-add", rec)])["ok"]
    rr = revoke_rec(a, PHONE)
    assert member(a, "approver-revoke", rr, [member_assertion(DESKTOP, "approver-revoke", rr)])["ok"]
    assert a.delegations == {} and not sign(a, b)["ok"]
    assert json.loads((tmp_path / "b" / "state" / "delegations.json").read_text()) == []


def test_a_record_signature_is_domain_tagged_and_never_verifies_as_governance(tmp_path):
    a = gated(tmp_path, [PHONE])
    rec = new_approver(a, DESKTOP, PHONE.id)
    signed = member(a, "approver-add", rec, [member_assertion(PHONE, "approver-add", rec)])["record"]
    sig = base64.b64decode(signed["owner_sig"])
    pub = ed25519.pub_from_seed(SEED)
    canon = merkle._canonical({k: v for k, v in signed.items() if k != "owner_sig"})
    assert ed25519.verify(approvers.TAG_RECORD + canon, sig, pub) and not ed25519.verify(canon, sig, pub)
    # the sign op can't be asked for a record signature: tagged bytes are not canonical JSON
    assert not sign(a, approvers.TAG_RECORD + canon)["ok"]
    assert not sign(a, approvers.TAG_RECORD + canon, "T")["ok"]


def test_nothing_but_the_member_op_and_the_break_glass_verb_signs_a_record():
    src = (PROJECT / "owner_agent.py").read_text()
    assert src.count("approvers.sign_record(") == 3                                          # _member, and break-glass twice
    agent_src = src[src.index("class Agent:"):src.index("# ---- the client")]
    assert agent_src.count("approvers.sign_record(") == 1 and "def _member" in agent_src


def test_a_restored_file_cannot_unrevoke_an_approver_or_bring_back_a_cleared_delegation(tmp_path):
    a = gated(tmp_path, [PHONE, DESKTOP])
    old = (tmp_path / "state" / "approvers.json").read_text()
    rec = deleg(a, PHONE.id)
    member(a, "delegate-add", rec, [member_assertion(PHONE, "delegate-add", rec), member_assertion(DESKTOP, "delegate-add", rec)])
    saved = (tmp_path / "state" / "delegations.json").read_text()
    rr = revoke_rec(a, PHONE)
    assert member(a, "approver-revoke", rr, [member_assertion(DESKTOP, "approver-revoke", rr)])["ok"]
    (tmp_path / "state" / "approvers.json").write_text(old)                                # same-uid restores the old files
    (tmp_path / "state" / "delegations.json").write_text(saved)
    assert a._reload(1)["ok"]
    assert "revoked" in a.approvers[PHONE.id] and a.delegations == {}


# ---- the #485 follow-up: tests that pin guards no other test reaches -----------------------------------------------------------
# Group 1 (single-layer: nothing else refuses if the guard breaks). Each test below fails on the mutant named in its comment.

def test_an_eddsa_assertion_with_a_bad_or_short_signature_is_refused():
    # mutant: `ok = len(sig) == 64 and ed25519.verify(...)` -> `ok = True` (or without the length check)
    ok, why, _ = _verify(DESKTOP, tamper=True)
    assert not ok and "signature" in why
    rec = approvers.sign_record(DESKTOP.record(), OWNER)
    good = DESKTOP.assertion(CH)
    for sig in (b"", b"\x00" * 63, b"\x00" * 64, base64.urlsafe_b64decode(good["signature"] + "==")[:63]):
        bad = dict(good, signature=approvers.b64u(sig))
        ok, why, _ = approvers.verify_assertion(rec, bad, CH, RP, ORIGIN)
        assert not ok and "signature" in why
    other = Passkey("someone else", "eddsa", "desktop")                                      # a valid signature by another key
    ok, _, _ = approvers.verify_assertion(rec, dict(other.assertion(CH), credentialId=DESKTOP.id), CH, RP, ORIGIN)
    assert not ok


@pytest.mark.parametrize("key,pats,want", [
    ("x-demo:poll", ["x-demo:*"], True),
    ("x-demo:poll", ["x-demo:poll"], True),
    ("x-demo:poll", ["x-demo:other"], False),                                                # exact means exact
    ("x-demo:poll", ["x-demo:p"], False),
    ("x-demo2:poll", ["x-demo:*"], False),                                                   # a wildcard stops at the colon
    ("x-demox:poll", ["x-demo:*"], False),
    ("x-other:poll", ["x-demo:*", "x-demo:poll"], False),
    ("x-demo:poll", [], False),
    ("quorum_m", ["x-demo:*"], False),                                                       # a core key is never in scope
    ("quorum_m", ["quorum_m"], False),
    ("x-demo:*", ["x-demo:poll"], False),
])
def test_key_in_scope_matches_a_listed_key_or_a_module_wildcard_only(key, pats, want):
    # mutant: key_in_scope -> True, or the prefix test loosened, or the split_module_name guard dropped
    assert approvers.key_in_scope(key, pats) is want


def test_a_set_config_delegation_signs_only_the_keys_it_lists(tmp_path):
    # mutant: the `key_in_scope` line in `_delegation_check` removed
    a = gated(tmp_path, [PHONE])
    assert add_deleg(a, PHONE, scope={"acts": ["set-config"], "keys": ["x-demo:poll", "x-demo2:*"]}, per_day=50)["ok"]
    assert sign(a, body(action="set-config", key="x-demo:poll", value="1"))["ok"]
    assert sign(a, body(action="set-config", key="x-demo2:anything", value="1"))["ok"]
    for k in ("x-demo:other", "x-demo:pollx", "x-demo3:poll", "quorum_m", "cap_self"):
        r = sign(a, body(action="set-config", key=k, value="1"))
        assert not r["ok"], k


def test_an_admit_delegation_signs_only_the_modules_it_lists_and_only_its_own_act(tmp_path):
    # mutant: the `admit_modules` line in `_delegation_check` removed, or the act match loosened
    a = gated(tmp_path, [PHONE])
    assert add_deleg(a, PHONE, id="adm", scope={"acts": ["admit"], "admit_modules": ["demo", "other"]}, per_day=50)["ok"]
    assert sign(a, body(action="admit", device_id=DEV, module="demo", principal="op"))["ok"]
    assert sign(a, body(action="admit", device_id=DEV2, module="other", principal="op"))["ok"]
    assert not sign(a, body(action="admit", device_id=DEV, module="third", principal="op"))["ok"]
    assert not sign(a, body(action="set-config", key="x-demo:poll", value="1"))["ok"]       # an admit delegation is not a config one
    (tmp_path / "b").mkdir()
    b = gated(tmp_path / "b", [PHONE])
    assert add_deleg(b, PHONE, per_day=50)["ok"]
    assert not sign(b, body(action="admit", device_id=DEV, module="demo", principal="op"))["ok"]    # nor does a config one sign an admit


def test_a_revoked_approver_id_cannot_be_enrolled_again(tmp_path):
    # mutant: the `rec["id"] in self.approvers` refusal removed (a re-enrol would overwrite the revoked record)
    a = gated(tmp_path, [PHONE, DESKTOP])
    rr = revoke_rec(a, PHONE)
    assert member(a, "approver-revoke", rr, [member_assertion(DESKTOP, "approver-revoke", rr)])["ok"]
    again = new_approver(a, PHONE, DESKTOP.id)
    r = member(a, "approver-add", again, [member_assertion(DESKTOP, "approver-add", again)])
    assert not r["ok"] and "already enrolled" in r["why"]
    assert "revoked" in a.approvers[PHONE.id]
    stored = {x["id"]: x for x in json.loads((tmp_path / "state" / "approvers.json").read_text())}
    assert "revoked" in stored[PHONE.id]
    assert "enrolled" in present(a, PHONE, [{"id": "T", "acts": [h(SETCFG)]}])["why"]


def test_a_break_glass_revoke_clears_every_delegation_on_reload(tmp_path):
    # mutant: `if revoked_new: dead |= set(dels); dels = {}` removed in `_reload`
    a = gated(tmp_path, [PHONE, DESKTOP])
    rec = deleg(a, PHONE.id)
    assert member(a, "delegate-add", rec, [member_assertion(PHONE, "delegate-add", rec), member_assertion(DESKTOP, "delegate-add", rec)])["ok"]
    assert sign(a, body(action="set-config", key="x-demo:poll", value="1"))["ok"]
    # break-glass: the verb writes an owner-signed revoked record into approvers.json, then asks the agent to reload
    revoked = approvers.sign_record({**{k: v for k, v in a.approvers[PHONE.id].items() if k != "owner_sig"}, "revoked": now_of(a)}, OWNER)
    path = tmp_path / "state" / "approvers.json"
    path.write_text(json.dumps([revoked if r["id"] == PHONE.id else r for r in json.loads(path.read_text())]))
    assert a._reload(1)["ok"]
    assert "revoked" in a.approvers[PHONE.id]
    assert a.delegations == {} and "d1" in a.dead_delegations
    assert not sign(a, body(action="set-config", key="x-demo:poll", value="2"))["ok"]


@LINUX
def test_break_glass_approver_add_refuses_an_enrolled_id_and_keeps_the_revoked_record(hive):
    # mutant: the "is already enrolled" refusal in the verb's own break-glass path removed
    run_ctl(hive, *add_flags(PHONE), passphrase_fd=PASS)
    run_ctl(hive, *add_flags(DESKTOP), "--break-glass", passphrase_fd=PASS)
    run_ctl(hive, "owner", "approver", "revoke", "--credential-id", DESKTOP.id, "--break-glass", passphrase_fd=PASS)
    r = run_ctl(hive, *add_flags(DESKTOP), "--break-glass", passphrase_fd=PASS, check=False)
    assert r.returncode == 1 and "already enrolled" in r.stderr
    assert "REVOKED" in run_ctl(hive, "owner", "approver", "list").stdout


# Group 2 (layered: the agent still refuses if one of these breaks, so these pin the inner layer on its own). The functions
# are called in-process with the agent's status faked; no seed is read and no passphrase is asked on any path below.

@pytest.fixture
def ow(monkeypatch):
    import hivemind_owner as o
    monkeypatch.delenv("HIVE_APPROVAL_TICKET", raising=False)
    monkeypatch.setattr(o, "_UNLOCKED_SEED", None, raising=False)
    monkeypatch.setattr(o, "_NON_INTERACTIVE", False, raising=False)
    return o


@pytest.mark.parametrize("bad", ["", "not a ticket!", "a" * 129, "t/../x"])
def test_a_set_but_malformed_ticket_is_a_refusal_never_no_ticket(ow, monkeypatch, bad):
    # mutant: `_approval_ticket` returns None for a malformed value (the id_ok check dropped)
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", bad)
    with pytest.raises(ow.OwnerPromptRefused):
        ow._approval_ticket()


def test_an_unset_ticket_is_none_and_a_good_one_is_returned(ow, monkeypatch):
    assert ow._approval_ticket() is None
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", "T-1.a:b")
    assert ow._approval_ticket() == "T-1.a:b"


def test_the_owner_seed_is_not_read_under_a_ticket_even_when_it_is_already_unlocked(ow, monkeypatch):
    # mutant: the `_approval_ticket() is not None` refusal at the top of `_owner_seed` removed
    monkeypatch.setattr(ow, "_UNLOCKED_SEED", b"s" * 32)
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", "T-1")
    with pytest.raises(ow.OwnerPromptRefused):
        ow._owner_seed()
    monkeypatch.delenv("HIVE_APPROVAL_TICKET")
    assert ow._owner_seed() == b"s" * 32


@pytest.mark.parametrize("status", [None, {"gated": False, "public_key": base64.b64encode(PUB).decode() if isinstance(PUB, bytes) else PUB},
                                    {"public_key": "AAAA"}], ids=["no agent", "ungated agent", "gated flag missing"])
def test_a_ticketed_signer_needs_a_gated_agent_and_never_falls_back_to_the_seed(ow, monkeypatch, status):
    # mutant: the `st is None or not st.get("gated")` check in `_owner_signer` removed or loosened
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", "T-1")
    monkeypatch.setattr(ow, "_agent_status", lambda: status)
    monkeypatch.setattr(ow, "_owner_seed", lambda: pytest.fail("the seed was reached under a ticket"))
    monkeypatch.setattr(ow, "_UNLOCKED_SEED", b"s" * 32)
    with pytest.raises(ow.OwnerPromptRefused):
        ow._owner_signer()


def test_a_ticketed_signer_with_a_gated_agent_is_a_hard_gate(ow, monkeypatch):
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", "T-1")
    pub = base64.b64encode(ed25519.pub_from_seed(SEED)).decode()
    monkeypatch.setattr(ow, "_agent_status", lambda: {"gated": True, "public_key": pub})
    monkeypatch.setattr(ow, "_owner_seed", lambda: pytest.fail("the seed was reached under a ticket"))
    monkeypatch.setattr(ow, "_UNLOCKED_SEED", b"s" * 32)
    monkeypatch.setattr(ow, "HIVE_HOME", "/nonexistent", raising=False)                      # the library's name, set by the loader
    sg = ow._owner_signer()
    assert sg.public_key() == ed25519.pub_from_seed(SEED)
    assert sg._ticket == "T-1" and sg._fallback() is None and sg._fail is ow.OwnerPromptRefused


@pytest.mark.parametrize("status,want", [
    (None, False),
    ({"gated": False, "tickets": ["T-1"]}, False),
    ({"gated": True, "tickets": []}, False),
    ({"gated": True, "tickets": ["T-2"]}, False),
    ({"gated": True}, False),
    ({"gated": True, "tickets": ["T-1"]}, True),
])
def test_the_owner_gate_under_a_ticket_passes_only_when_the_gated_agent_holds_that_ticket(ow, monkeypatch, status, want):
    # mutant: the ticket-live check in `_owner_gate` loosened (no `gated`, no `ticket in tickets`) or falling through to the seed
    monkeypatch.setenv("HIVE_APPROVAL_TICKET", "T-1")
    monkeypatch.setattr(ow, "_agent_status", lambda: status)
    monkeypatch.setattr(ow, "_owner_seed", lambda: pytest.fail("the seed was reached under a ticket"))
    assert ow._owner_gate() is want


# ---- the real CLI and a real agent --------------------------------------------------------------------------------------------

def run_ctl(h, *args, passphrase_fd=None, env=None, check=True):
    e = dict(h.env)
    e.pop("HIVE_OWNER_KEY_PASSPHRASE", None)
    e.update(env or {})
    pass_fds = ()
    if passphrase_fd is not None:
        rfd, wfd = os.pipe()
        os.write(wfd, (passphrase_fd + "\n").encode())
        os.close(wfd)
        args = (*args, "--passphrase-fd", str(rfd))
        pass_fds = (rfd,)
    try:
        r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), *args], env=e, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=pass_fds)
    finally:
        for fd in pass_fds:
            os.close(fd)
    if check:
        assert r.returncode == 0, r.stderr + r.stdout
    return r


def gov_entries(home):
    return [e for e in merkle.read_all_entries(str(home / "journal")) if e.get("type") == "governance"]


def add_flags(key):
    return ["owner", "approver", "add", "--credential-id", key.id, "--alg", key.alg, "--pub",
            base64.b64encode(key.pub).decode(), "--label", key.id, "--kind", key.kind]


@LINUX
def test_the_whole_path_enrol_unlock_gated_plan_present_execute(hive):
    # 1. nothing enrolled: gated mode will not start, and the first enrolment is the passphrase, typed once
    assert "enrol" in run_ctl(hive, "owner", "unlock", "--gated", "--rp-id", RP, passphrase_fd=PASS, check=False).stderr
    assert run_ctl(hive, *add_flags(PHONE), "--break-glass", passphrase_fd=PASS).returncode == 0
    assert PHONE.id in run_ctl(hive, "owner", "approver", "list").stdout
    # 2. gated unlock; ungated flags are refused with it, and a second unlock is not a mode change
    assert run_ctl(hive, "owner", "unlock", "--gated", "--for", "5m", "--rp-id", RP, passphrase_fd=PASS, check=False).returncode == 2
    assert "gated" in run_ctl(hive, "owner", "unlock", "--gated", "--rp-id", RP, passphrase_fd=PASS).stdout
    client = owner_agent.Client(_sock(hive))
    try:
        st = client.status()
        assert st["gated"] and [a["id"] for a in st["approvers"]] == [PHONE.id]
        # 3. enrol a second approver: plan, one tap, then the verb through the agent
        plan = json.loads(run_ctl(hive, *add_flags(DESKTOP), "--plan", "--json").stdout)
        assert plan["assertions_needed"] == 1 and not plan["break_glass"]
        rec = plan["record"]
        assert approvers.b64u(approvers.member_challenge("approver-add", rec)) == plan["challenge"]
        af = hive.tmp / "assert1.json"
        af.write_text(json.dumps(member_assertion(PHONE, "approver-add", rec)))
        run_ctl(hive, *add_flags(DESKTOP), "--at", str(rec["enrolled"]), "--assertion", str(af))
        assert DESKTOP.id in run_ctl(hive, "owner", "approver", "list").stdout
        # 4. a plan, a tap, an execution under the ticket: the signed bytes are the planned bytes
        argv = ["config", "set", "x-demo:poll", "45"]
        before = len(gov_entries(hive.home))
        planned = json.loads(run_ctl(hive, *argv, "--plan", "--json").stdout)["bodies"]
        tickets = [{"id": "T-1", "acts": [b["sha256"] for b in planned]}]
        client.present(tickets, ticket_assertion(DESKTOP, tickets))
        run_ctl(hive, *argv, env={"HIVE_APPROVAL_TICKET": "T-1"})
        signed = gov_entries(hive.home)[before:]
        assert len(signed) == 1
        p = dict(signed[0]["payload"])
        sig = base64.b64decode(p.pop("owner_sig"))
        assert merkle._canonical(p).decode() == planned[0]["canonical"] and ed25519.verify(merkle._canonical(p), sig, ed25519.pub_from_seed(SEED_OF(hive)))
        # 5. the hard gate: another value under that ticket is refused, nothing is signed, and the passphrase in the
        # environment is not used as a fallback
        r = run_ctl(hive, "config", "set", "x-demo:poll", "46", env={"HIVE_APPROVAL_TICKET": "T-1", "HIVE_OWNER_KEY_PASSPHRASE": PASS},
                    check=False)
        assert r.returncode != 0 and "no passphrase fallback" in r.stderr and len(gov_entries(hive.home)) == before + 1
        # a ticket nobody presented, and a run with a ticket and no gated agent for it
        r = run_ctl(hive, "config", "set", "x-demo:poll", "47", env={"HIVE_APPROVAL_TICKET": "T-none", "HIVE_OWNER_KEY_PASSPHRASE": PASS},
                    check=False)
        assert r.returncode != 0 and len(gov_entries(hive.home)) == before + 1
        # no ticket: a gated agent signs nothing for the verb, and the fallback is the passphrase as before
        r = run_ctl(hive, "config", "set", "x-demo:poll", "48", env={"HIVE_OWNER_KEY_PASSPHRASE": PASS}, check=False)
        assert r.returncode == 0 and len(gov_entries(hive.home)) == before + 2
        # 6. a delegation needs two taps now (two approvers); the revoke of the phone clears it
        dplan = json.loads(run_ctl(hive, "owner", "delegate", "add", "--id", "hw", "--act", "set-config", "--key", "x-hwatch:*",
                                   "--per-day", "5", "--days", "7", "--by", PHONE.id, "--plan", "--json").stdout)
        assert dplan["assertions_needed"] == 2
        drec = dplan["record"]
        fa, fb = hive.tmp / "da.json", hive.tmp / "db.json"
        fa.write_text(json.dumps(member_assertion(PHONE, "delegate-add", drec)))
        fb.write_text(json.dumps(member_assertion(DESKTOP, "delegate-add", drec)))
        run_ctl(hive, "owner", "delegate", "add", "--id", "hw", "--act", "set-config", "--key", "x-hwatch:*", "--per-day", "5",
                "--days", "7", "--by", PHONE.id, "--at", str(drec["created"]), "--assertion", str(fa), "--assertion", str(fb))
        assert "hw" in run_ctl(hive, "owner", "delegate", "list").stdout
        n = len(gov_entries(hive.home))
        run_ctl(hive, "config", "set", "x-hwatch:mode", "fast")                           # signed by the delegation, no tap
        assert len(gov_entries(hive.home)) == n + 1 and "delegation hw" in run_ctl(hive, "owner", "status").stdout
        rplan = json.loads(run_ctl(hive, "owner", "approver", "revoke", "--credential-id", PHONE.id, "--plan", "--json").stdout)
        rf = hive.tmp / "rv.json"
        rf.write_text(json.dumps(member_assertion(DESKTOP, "approver-revoke", rplan["record"])))
        run_ctl(hive, "owner", "approver", "revoke", "--credential-id", PHONE.id, "--at", str(rplan["record"]["revoked"]),
                "--assertion", str(rf))
        assert "REVOKED" in run_ctl(hive, "owner", "approver", "list").stdout
        assert client.status()["delegations"] == []
        # the last approver cannot be revoked by a tap: that is break-glass
        last = run_ctl(hive, "owner", "approver", "revoke", "--credential-id", DESKTOP.id, check=False)
        assert last.returncode == 1 and "break-glass" in last.stderr
    finally:
        run_ctl(hive, "owner", "lock", check=False)


def SEED_OF(h):
    out = h.tmp / "export.json"
    run_ctl(h, "owner", "export", "--plaintext", "--out", str(out), env={"HIVE_OWNER_KEY_PASSPHRASE": PASS})
    return base64.b64decode(json.loads(out.read_text())["seed"])


@LINUX
def test_under_a_ticket_with_no_agent_the_seed_and_the_passphrase_are_out_of_reach(hive):
    before = len(gov_entries(hive.home))
    r = run_ctl(hive, "config", "set", "x-demo:poll", "9",
                env={"HIVE_APPROVAL_TICKET": "T-1", "HIVE_OWNER_KEY_PASSPHRASE": PASS}, check=False)
    assert r.returncode == 5 and "ticket" in r.stderr and len(gov_entries(hive.home)) == before
    r = run_ctl(hive, "config", "set", "x-demo:poll", "9", env={"HIVE_APPROVAL_TICKET": "not a ticket!"}, check=False)
    assert r.returncode != 0 and len(gov_entries(hive.home)) == before


@LINUX
def test_break_glass_signs_a_record_with_the_passphrase_only_and_a_wrong_one_signs_nothing(hive):
    r = run_ctl(hive, *add_flags(PHONE), "--break-glass", passphrase_fd="wrong", check=False)
    assert r.returncode == 1 and "Nothing was signed" in r.stderr
    assert "no approvers" not in run_ctl(hive, "owner", "approver", "list").stdout and PHONE.id not in run_ctl(hive, "owner", "approver", "list").stdout
    run_ctl(hive, *add_flags(PHONE), passphrase_fd=PASS)                                     # none enrolled: the passphrase path
    r = run_ctl(hive, *add_flags(DESKTOP), passphrase_fd=PASS, check=False)                  # one enrolled, no agent: not allowed
    assert r.returncode == 1 and "--break-glass" in r.stderr
    run_ctl(hive, *add_flags(DESKTOP), "--break-glass", passphrase_fd=PASS)
    files = list(Path(hive.env["HOME"]).rglob("approvers.json"))                              # the test's sandboxed key dir
    assert files and all(p.stat().st_mode & 0o777 == 0o600 for p in files)
    assert all(p.parent.stat().st_mode & 0o777 == 0o700 for p in files)


# ---- the #478 follow-ups ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argv,verb", [
    (("config", "set", "x-demo:api_token", "s3cret"), "config set"),
    (("config", "confidence", "set", "x-demo:api_token", "s3cret"), "config confidence set"),
    (("config", "quorum", "set", "x-demo:db_password", "s3cret"), "config quorum set"),
])
def test_no_plan_carries_a_secret_value(hive, argv, verb):
    r = run_ctl(hive, *argv, "--plan", "--json", check=False)
    assert r.returncode == 1 and r.stdout == "" and "secret" in r.stderr and "s3cret" not in r.stdout + r.stderr


def test_a_secret_key_is_found_by_its_name_and_not_by_accident():
    import hive_modules
    assert hive_modules.secret_config_key("4.0", "x-vault:api_token")
    assert not hive_modules.secret_config_key("4.0", "quorum_m") and not hive_modules.secret_config_key("4.0", "x-vault:poll")


def test_the_plan_labels_each_config_verb_and_prints_no_success_line(hive):
    for argv, verb in ((("config", "set", "cap_self", "0.52"), "config set"),
                       (("config", "confidence", "set", "cap_self", "0.53"), "config confidence set"),
                       (("config", "quorum", "set", "quorum_m", "2"), "config quorum set")):
        r = run_ctl(hive, *argv, "--plan", "--json")
        assert json.loads(r.stdout)["verb"] == verb
        assert "set " not in r.stderr and r.stderr.strip() == "", r.stderr
    r = run_ctl(hive, "config", "set", "no_such_key", "1", "--plan", "--json", check=False)         # a refusal still says why
    assert r.returncode == 1 and "unknown config key" in r.stderr and r.stdout == ""
