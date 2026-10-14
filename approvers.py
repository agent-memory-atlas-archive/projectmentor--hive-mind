"""Owner approval slice A1 (design: hive-mind-private docs/design/owner_approval_and_hygiene.md section 4.3).

The pieces the gated agent and the membership verbs share, on the control plane only (`hv` never imports this file):

* **Approver and delegation records**: node-local, owner-signed under the domain tag `hive-approver-v1`. A governance
  body is canonical JSON (it starts with `{`), a record signature covers `tag || canonical(record)`, so one can never
  verify as the other. The files hold no secret.
* **Challenges**: what an approver's passkey signs, bound to the exact act hashes (`ticket_challenge`) or to the exact
  record (`member_challenge`).
* **`verify_assertion`**: the WebAuthn get-assertion check (ES256 or EdDSA, `rpId`, origin, UP/UV, `BE`, sign count).

This file produces no signature of its own: `sign_record` is handed a `Signer` and is called only by the agent's
`member` op and by the membership verbs' break-glass path (the owner passphrase, typed at a terminal).
"""

import base64
import hashlib
import json
import os
import re

import ed25519
import merkle
import p256
import vocabulary

TAG_RECORD = b"hive-approver-v1"
TAG_TICKET = b"hive-approval-v1"
TAG_MEMBER = b"hive-approver-member-v1"

ALG_ES256, ALG_EDDSA = -7, -8
KINDS = ("phone", "key", "desktop")
DELEGATION_ACTS = ("set-config", "admit")
MAX_DELEGATION_DAYS, MAX_DELEGATION_PER_DAY = 30, 200
FRESH = 900                       # a membership record's own timestamp must be this close to the agent's clock

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64u(text):
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def id_ok(value):
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def hex64_ok(value):
    return isinstance(value, str) and bool(_HEX64.fullmatch(value))


# ---- records ---------------------------------------------------------------------------------------------------------

def record_bytes(record):
    """The bytes a record signature covers: the domain tag, then the canonical record without `owner_sig`."""
    return TAG_RECORD + merkle._canonical({k: v for k, v in record.items() if k != "owner_sig"})


def sign_record(record, signer):
    out = {k: v for k, v in record.items() if k != "owner_sig"}
    out["owner_sig"] = base64.b64encode(signer.sign(record_bytes(out))).decode()
    return out


def verify_record(record, owner_pub_b64):
    try:
        sig = base64.b64decode(record["owner_sig"], validate=True)
        return ed25519.verify(record_bytes(record), sig, base64.b64decode(owner_pub_b64, validate=True))
    except Exception:
        return False


def approver_ok(rec):
    """The shape of an approver record: `{id, alg, pub, label, kind, enrolled, by[, revoked], owner_sig}`."""
    if not isinstance(rec, dict):
        return "not an object"
    want = {"id", "alg", "pub", "label", "kind", "enrolled", "by", "owner_sig"} | ({"revoked"} & set(rec))
    if set(rec) != want and set(rec) != want - {"owner_sig"}:
        return "wrong key set"
    if not id_ok(rec.get("id")) or not id_ok(rec.get("by")):      # `by` is an approver's id, or "owner" (break-glass)
        return "bad id"
    if rec.get("alg") not in (ALG_ES256, ALG_EDDSA) or isinstance(rec.get("alg"), bool):
        return "alg must be -7 (ES256) or -8 (EdDSA)"
    try:
        raw = base64.b64decode(rec.get("pub", ""), validate=True)
    except Exception:
        return "bad pub"
    if rec["alg"] == ALG_ES256 and not (len(raw) == 64 and p256.on_curve((int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")))):
        return "pub is not a P-256 point (64 raw bytes x||y)"
    if rec["alg"] == ALG_EDDSA and len(raw) != 32:
        return "pub is not an Ed25519 key (32 raw bytes)"
    if not isinstance(rec.get("label"), str) or not 0 < len(rec["label"]) <= 64 or not rec["label"].isprintable():
        return "bad label"
    if rec.get("kind") not in KINDS:
        return "kind must be phone, key or desktop"
    for f in ("enrolled", "revoked"):
        if f in rec and (not isinstance(rec[f], int) or isinstance(rec[f], bool) or rec[f] <= 0):
            return f"bad {f}"
    return None


def delegation_ok(rec, now, new=True):
    """The shape of a delegation record: `{id, scope, per_day, expires, created, by[, revoked], owner_sig}`. A NEW one
    must also respect the ceilings (30 days, 200 a day) and not be expired already."""
    if not isinstance(rec, dict):
        return "not an object"
    want = {"id", "scope", "per_day", "expires", "created", "by", "owner_sig"} | ({"revoked"} & set(rec))
    if set(rec) != want and set(rec) != want - {"owner_sig"}:
        return "wrong key set"
    if not id_ok(rec.get("id")) or not id_ok(rec.get("by")):
        return "bad id"
    for f in ("per_day", "expires", "created") + (("revoked",) if "revoked" in rec else ()):
        if not isinstance(rec[f], int) or isinstance(rec[f], bool) or rec[f] <= 0:
            return f"bad {f}"
    scope = rec.get("scope")
    if not isinstance(scope, dict) or not isinstance(scope.get("acts"), list) or len(scope["acts"]) != 1:
        return "scope.acts must name exactly one act"
    act = scope["acts"][0]
    if act == "set-config" and set(scope) == {"acts", "keys"}:
        keys = scope["keys"]
        if not isinstance(keys, list) or not 0 < len(keys) <= 32 or not all(_key_pattern_ok(k) for k in keys):
            return "scope.keys must be x-<module>:* or exact x-<module>:<key> entries"
    elif act == "admit" and set(scope) == {"acts", "admit_modules"}:
        mods = scope["admit_modules"]
        if not isinstance(mods, list) or not 0 < len(mods) <= 32 or not all(vocabulary.valid_module_name(m) for m in mods):
            return "scope.admit_modules must be valid module names"
    else:
        return "scope must be {acts:[set-config], keys} or {acts:[admit], admit_modules}"
    if new:
        if not 0 < rec["per_day"] <= MAX_DELEGATION_PER_DAY:
            return f"per_day must be 1 to {MAX_DELEGATION_PER_DAY}"
        if not now < rec["expires"] <= now + MAX_DELEGATION_DAYS * 86400:
            return f"expires must be within {MAX_DELEGATION_DAYS} days from now"
        if abs(rec["created"] - now) > FRESH:
            return "created is not now"
    return None


def _key_pattern_ok(k):
    if not isinstance(k, str):
        return False
    if k.endswith(":*"):
        return vocabulary.valid_module_name(k[2:-2]) and k.startswith("x-")
    return vocabulary.split_module_name(k) is not None


def key_in_scope(key, patterns):
    """A set-config key is in scope when it equals a listed key or sits under a listed `x-<module>:*`. A key that is not
    `x-<module>:<name>` (every core key) is never in scope."""
    if vocabulary.split_module_name(key) is None:
        return False
    return any(key == p or (p.endswith(":*") and key.startswith(p[:-1])) for p in patterns)


def load_records(path, owner_pub_b64, check):
    """The records of a JSON list file whose owner signature verifies and whose shape `check` accepts. A missing,
    unreadable or malformed file is an empty list; a bad record is dropped, never trusted."""
    try:
        data = json.loads(open(path, "rb").read().decode())
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    out, seen = [], set()
    for rec in data:
        if isinstance(rec, dict) and rec.get("id") not in seen and verify_record(rec, owner_pub_b64) and check(rec) is None:
            seen.add(rec["id"])
            out.append(rec)
    return out


def write_json_0600(path, obj):
    """Atomically write `obj` as JSON at mode 0600 (a temp file in the same directory, then a rename)."""
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def live_approvers(records):
    return [r for r in records if "revoked" not in r]


# ---- challenges ------------------------------------------------------------------------------------------------------

def acts_hash(act_hexes):
    """sha256 of the sorted act hashes (hex) joined by newlines: the one value a ticket's acts reduce to."""
    return hashlib.sha256("\n".join(sorted(act_hexes)).encode()).hexdigest()


def ticket_challenge(pairs):
    """`sha256("hive-approval-v1" || sha256(canonical(sorted [ticket id, act-set hash] pairs)))`. One ticket is the
    one-pair case of the same rule, so a single tap and a batch tap are checked by one function."""
    canon = merkle._canonical(sorted([i, h] for i, h in pairs))
    return hashlib.sha256(TAG_TICKET + hashlib.sha256(canon).digest()).digest()


def member_challenge(kind, record):
    """What an approver signs to authorise a membership change: the change's kind and the exact new record."""
    canon = merkle._canonical({"kind": kind, "record": {k: v for k, v in record.items() if k != "owner_sig"}})
    return hashlib.sha256(TAG_MEMBER + canon).digest()


# ---- the WebAuthn assertion --------------------------------------------------------------------------------------------

def verify_assertion(approver, assertion, challenge, rp_id, origin, allow_synced=False, last_count=0):
    """(ok, why, sign_count) for one get-assertion `{credentialId, authenticatorData, clientDataJSON, signature}`
    (base64url strings) made by the enrolled `approver` over `challenge` (bytes). Checks, in order: the credential is the
    approver's, `rpIdHash`, UP and UV set, `BE` clear unless `allow_synced`, `type`, `challenge`, `origin`,
    `crossOrigin`, the signature (ES256 or EdDSA over `authenticatorData || sha256(clientDataJSON)`), and a sign count
    that moved forward (two zeros are allowed: some authenticators never count)."""
    try:
        if assertion.get("credentialId") != approver["id"]:
            return False, "not this approver's credential", last_count
        auth = unb64u(assertion["authenticatorData"])
        cdj_raw = unb64u(assertion["clientDataJSON"])
        sig = unb64u(assertion["signature"])
    except (ValueError, KeyError, TypeError, AttributeError):
        return False, "malformed assertion", last_count
    if len(auth) != 37:
        return False, "authenticatorData must be exactly 37 bytes (no attested data, no extensions)", last_count
    if auth[:32] != hashlib.sha256(rp_id.encode()).digest():
        return False, "rpIdHash does not match", last_count
    flags = auth[32]
    if not flags & 0x01 or not flags & 0x04:
        return False, "user presence and verification are both required", last_count
    if flags & 0x40 or flags & 0x80:
        return False, "unexpected attested-data or extension flags", last_count
    if flags & 0x08 and not allow_synced:
        return False, "backup-eligible (synced) credential refused", last_count
    if flags & 0x10 and not flags & 0x08:
        return False, "backup state without backup eligibility", last_count
    try:
        cdj = json.loads(cdj_raw.decode())
    except (ValueError, UnicodeDecodeError):
        return False, "clientDataJSON is not JSON", last_count
    if not isinstance(cdj, dict) or cdj.get("type") != "webauthn.get":
        return False, "not a webauthn.get assertion", last_count
    if cdj.get("challenge") != b64u(challenge):
        return False, "challenge does not match what is being approved", last_count
    if cdj.get("origin") != origin:
        return False, "origin does not match", last_count
    if cdj.get("crossOrigin") not in (None, False):
        return False, "cross-origin assertion", last_count
    signed = auth + hashlib.sha256(cdj_raw).digest()
    pub = base64.b64decode(approver["pub"])
    if approver["alg"] == ALG_ES256:
        rs = p256.parse_der(sig)
        ok = rs is not None and p256.verify(pub, signed, *rs)
    else:
        ok = len(sig) == 64 and ed25519.verify(signed, sig, pub)
    if not ok:
        return False, "signature does not verify", last_count
    count = int.from_bytes(auth[33:37], "big")
    if (count or last_count) and count <= last_count:
        return False, "sign count did not move forward (a cloned authenticator?)", last_count
    return True, "", count
