# ── Capsules: encrypt-to-device secrets (Phase 2) ────────────────────────────────────────────────
_CAPSULE_ALG = "x25519-hkdf-chacha20poly1305-v1"


def _recipient_pubkeys(entries, gov):
    """{device_id: curve_pub bytes} for the current authorized set (admitted − purged). A device's
    Ed25519 pubkey is harvested from its OWN signed entries (pub bound to node_id via the
    fingerprint) and converted to Curve25519 — this identity-derived key is the ONLY trusted key
    source, since it is cryptographically bound to the device's signing identity. A curve_pub
    merely *carried* on a join-request/admit payload has NO proof-of-possession, so it is never
    used as a key; it is only checked for disagreement with the derived value (a tamper signal).
    Returns (recipients, missing, suspect): `missing` = admitted device_ids with no derivable key
    yet; `suspect` = device_ids that carried a curve_pub absent-or-unequal to the derived one."""
    if _x25519 is None:
        return {}, sorted(gov.get("admitted", set()) - gov.get("purged", set())), set()
    admitted = gov.get("admitted", set()) - gov.get("purged", set())
    ed_pub_by_dev, carried = {}, {}
    for e in entries:
        pub_b64, nid = e.get("pub"), e.get("node_id")
        if pub_b64 and nid and nid not in ed_pub_by_dev:
            try:
                pub = base64.b64decode(pub_b64)
                if len(pub) == 32 and _device_id_for_pub(pub) == nid:
                    ed_pub_by_dev[nid] = pub
            except Exception:
                pass
        if e.get("type") == "governance":
            p = e.get("payload", {})
            if p.get("action") in ("join-request", "admit") and p.get("curve_pub") and p.get("device_id"):
                carried[p["device_id"]] = p["curve_pub"]
    recips, missing, suspect = {}, [], set()
    for dev in sorted(admitted):
        cp = None
        if dev in ed_pub_by_dev:
            try:
                cp = _x25519.ed_pub_to_curve_pub(ed_pub_by_dev[dev])
            except Exception:
                cp = None
        if dev in carried:
            # A carried curve_pub is never a key source (no proof-of-possession). Flag it as
            # suspect unless it exactly matches the identity-derived key — a planted, contradictory
            # value is the signal that someone tried to redirect this device's capsules.
            try:
                raw = base64.b64decode(carried[dev])
            except Exception:
                raw = None
            if cp is None or raw != cp:
                suspect.add(dev)
        (recips.__setitem__(dev, cp) if cp is not None else missing.append(dev))
    return recips, missing, suspect


def _capsule_build(name, kind, value, recipients, version, hive_id, signer):
    """Seal `value` (bytes) so only `recipients` (device_id→curve_pub) can open it. A random CEK
    keys ONE ChaCha20-Poly1305 (RFC 8439) seal of the payload; the CEK is wrapped per recipient via an
    EPHEMERAL X25519 ECDH (forward-secret per capsule), the ECDH output run through HKDF-SHA256 to a
    clean wrap key. name+version+hive_id+alg are bound as the payload AAD (no replay under another
    name); eph_pub is bound as the wrap AAD. Every key here is used for exactly one encryption, so the
    fixed-size random nonce can never collide under a repeated key."""
    if _x25519 is None or _chacha is None:
        raise RuntimeError("x25519/chacha20poly1305 module unavailable")
    cek, nonce = os.urandom(32), os.urandom(12)
    aad = f"{_CAPSULE_ALG}|{hive_id}|{name}|{version}".encode()
    ct, tag = _chacha.encrypt(cek, nonce, value, aad)
    wraps = []
    for dev, cpub in sorted(recipients.items()):
        # Per-recipient isolation: a single bad/low-order recipient key must NOT deny the secret to
        # everyone else. Skip that recipient; the caller diffs `recipients` against the produced wraps
        # to report which devices were unsealable (folded into the missing/suspect reporting).
        try:
            if not isinstance(cpub, (bytes, bytearray)) or len(cpub) != 32:
                raise ValueError("recipient curve_pub is not 32 bytes")
            eph = os.urandom(32)
            eph_pub = _x25519.scalarmult_base(eph)
            shared = _x25519.shared_secret(eph, cpub)            # raises on a low-order recipient key
        except Exception:
            continue
        wk = _hkdf_sha256(shared, eph_pub + cpub, b"hive-capsule-wrap", 32)
        wnonce = os.urandom(12)
        wct, wtag = _chacha.encrypt(wk, wnonce, cek, _CAPSULE_ALG.encode() + b"|wrap|" + eph_pub)
        wraps.append({"device_id": dev, "eph_pub": base64.b64encode(eph_pub).decode(),
                      "wrap_nonce": base64.b64encode(wnonce).decode(),
                      "wrapped_cek": base64.b64encode(wct).decode(),
                      "wrap_tag": base64.b64encode(wtag).decode()})
    return {"capsule_id": hashlib.sha256(name.encode()).hexdigest()[:16], "name": name, "kind": kind,
            "version": version, "alg": _CAPSULE_ALG, "hive_id": hive_id,
            "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(tag).decode(), "wraps": wraps, "signer": signer}


def _capsule_open(cap, my_scalar, my_device_id):
    """Open a capsule on this device. Whitelists `alg`, then ChaCha20-Poly1305 authenticates the wrap
    (releasing the CEK) and the payload BEFORE any plaintext is returned. Raises ValueError otherwise."""
    if cap.get("alg") != _CAPSULE_ALG:
        raise ValueError(f"unsupported capsule alg {cap.get('alg')!r} — refusing")
    if _x25519 is None or _chacha is None:
        raise RuntimeError("x25519/chacha20poly1305 module unavailable")
    mine = next((w for w in cap.get("wraps", []) if w.get("device_id") == my_device_id), None)
    if not mine:
        raise ValueError("this device is not a recipient (ask the owner to rotate after admitting it)")
    eph_pub = base64.b64decode(mine["eph_pub"])
    wnonce = base64.b64decode(mine["wrap_nonce"])
    wct = base64.b64decode(mine["wrapped_cek"])
    wtag = base64.b64decode(mine["wrap_tag"])
    shared = _x25519.shared_secret(my_scalar, eph_pub)
    my_pub = _x25519.scalarmult_base(my_scalar)
    wk = _hkdf_sha256(shared, eph_pub + my_pub, b"hive-capsule-wrap", 32)
    try:
        cek = _chacha.decrypt(wk, wnonce, wct, wtag, _CAPSULE_ALG.encode() + b"|wrap|" + eph_pub)
    except ValueError:
        raise ValueError("wrap auth failed (this capsule is tampered or corrupt) — re-sync from a "
                         "healthy peer (`hv sync now`); if it persists, the owner should rotate it")
    nonce, ct, tag = (base64.b64decode(cap[k]) for k in ("nonce", "ct", "tag"))
    aad = f"{_CAPSULE_ALG}|{cap.get('hive_id','')}|{cap.get('name','')}|{cap.get('version',0)}".encode()
    try:
        return _chacha.decrypt(cek, nonce, ct, tag, aad)
    except ValueError:
        raise ValueError("payload auth failed (this capsule is tampered or corrupt) — re-sync from a "
                         "healthy peer (`hv sync now`); if it persists, the owner should rotate it")


def _read_secret_value(args, name):
    """Resolve a secret value for `hv capsule put` WITHOUT it transiting argv/chat: --stdin, --file,
    --env-file [--name VAR] (default ~/.claude/.env), else an interactive getpass. bytes or None."""
    if getattr(args, "stdin", False):
        data = sys.stdin.buffer.read()
        return data.rstrip(b"\n") if data else None
    if getattr(args, "file", None):
        try:
            return Path(args.file).expanduser().read_bytes()
        except Exception as e:
            print(f"could not read {args.file}: {e}"); return None
    if getattr(args, "env_file", None) is not None or getattr(args, "var", None):
        ef = getattr(args, "env_file", None) or "~/.claude/.env"
        var = getattr(args, "var", None) or name
        val = _load_env_file(ef).get(var)
        if val is None:
            print(f"{var} not found in {ef}"); return None
        return val.encode()
    import getpass
    try:
        v = getpass.getpass(f"Enter value for {name} (hidden): ")
    except (EOFError, KeyboardInterrupt):
        print(); return None
    return v.encode() if v else None


def _my_curve_scalar():
    seed = _device_seed()
    if seed is None or _x25519 is None:
        return None
    return _x25519.ed_seed_to_curve_scalar(seed)


def _holds_owner_key(what):
    """Placeholder: can this device owner-sign `what` (a capsule or cell write under an owner policy)?
    `hv` cannot answer by reading the seed (2.0 S2), so it refuses and points at `hive-mind`, which
    replaces this with the real check (`hivemind_owner.py`)."""
    raise NotOnDataPlane(what)


def _authorize_content_payload(payload):
    """On the data plane an authority-bearing content write (capsule, cell, comb) is DEVICE-signed only
    (2.0 S2): under a `fertile` policy that is all it needs, since device admission authorizes it. Under
    an `owner` policy the write is refused before it gets here (`_holds_owner_key`) and runs through
    `hive-mind`, whose replacement of this function attaches the owner signature — outside the capsule
    AAD, so it never affects sealing or opening. Returns `payload` unchanged."""
    return payload


def capsule_cmd(args):
    """Encrypt-to-device secrets: `hv capsule put|get|ls|rm|rotate`. A capsule is sealed to the
    current authorized device set; only those devices can open it. Secrets enter via file/stdin/env/
    getpass — never argv/chat."""
    action = getattr(args, "capsule_action", None)
    entries = merkle.read_all_entries(JOURNAL_DIR)
    gov = _governance_state(entries)
    caps = _capsule_state(entries, gov)
    live = {n: c for n, c in caps.items() if c.get("alg") != "tombstone-v1"}

    if action == "ls":
        if not live:
            print("(no capsules)"); return 0
        for name, c in sorted(live.items()):
            mine = any(w.get("device_id") == NODE_ID for w in c.get("wraps", []))
            print(f"  {name:<28} v{c.get('version')}  recipients={len(c.get('wraps', []))}  "
                  f"openable_here={'yes' if mine else 'no'}")
        return 0

    if action == "get":
        c = live.get(args.name)
        if not c:
            print(f"No capsule named {args.name!r}."); return 1
        if c.get("hive_id") and gov.get("hive_id") and c["hive_id"] != gov["hive_id"]:
            print("This capsule belongs to a different hive — refusing."); return 1
        sc = _my_curve_scalar()
        if sc is None:
            print("No device key on this node — cannot open capsules (`hv config identity init`)."); return 1
        try:
            val = _capsule_open(c, sc, NODE_ID)
        except ValueError as e:
            print(f"{args.name}: {e}"); return 1
        sys.stdout.buffer.write(val if getattr(args, "raw", False) else val + b"\n")
        return 0

    if action == "rm":
        putters = gov.get("config", {}).get("capsule_putters", "owner")
        if gov.get("owner_id"):
            if putters == "owner" and not _holds_owner_key("capsule rm (capsule_putters=owner)"):
                print("Tombstoning capsules is owner-only here (config capsule_putters=owner) — the "
                      "projection would decline a non-owner tombstone. Run on the owner device."); return 1
            if putters == "fertile" and NODE_ID not in gov.get("admitted", set()):
                print("Only admitted devices may tombstone capsules on this hive."); return 1
        cur = caps.get(args.name)
        nextv = (int(cur.get("version", 0)) + 1) if cur else 1
        append_journal("capsule", _authorize_content_payload(
            {"capsule_id": hashlib.sha256(args.name.encode()).hexdigest()[:16],
             "name": args.name, "kind": "tombstone", "version": nextv,
             "alg": "tombstone-v1", "wraps": []}))
        print(f"Tombstoned capsule {args.name!r} (v{nextv}). The OLD ciphertext stays in the "
              f"append-only journal — ROTATE THE UPSTREAM SECRET to truly cut access.")
        return 0

    if action in ("put", "rotate"):
        putters = gov.get("config", {}).get("capsule_putters", "owner")
        if gov.get("owner_id"):
            if putters == "owner" and not _holds_owner_key(f"capsule {action} (capsule_putters=owner)"):
                print("Storing capsules is owner-only here (config capsule_putters=owner). Run on the "
                      "owner device, or `hive-mind config set capsule_putters fertile`."); return 1
            if putters == "fertile" and NODE_ID not in gov.get("admitted", set()):
                print("Only admitted devices may store capsules on this hive."); return 1
        recips, missing, suspect = _recipient_pubkeys(entries, gov)
        if not recips:                                  # pre-owner / solo: seal to THIS device
            sc = _my_curve_scalar()
            if sc is None and _ensure_device_key():     # fresh node: mint a key so solo capsules work
                print(f"Minted this device's key (device_id: {NODE_ID}).")
                sc = _my_curve_scalar()
            if sc is not None:
                recips = {NODE_ID: _x25519.scalarmult_base(sc)}
        if not recips:
            print("No recipient device key available — run `hv config identity init` first."); return 1

        if action == "rotate":
            names = [args.name] if getattr(args, "name", None) else list(live)
            sc = _my_curve_scalar()
            for nm in names:
                cur = live.get(nm)
                if not cur:
                    continue
                try:
                    val = _capsule_open(cur, sc, NODE_ID)
                except Exception as e:
                    print(f"{nm}: cannot rotate (this device can't open it: {e})"); continue
                nextv = int(cur.get("version", 0)) + 1
                cap = _capsule_build(nm, cur.get("kind", "credential"), val,
                                     recips, nextv, gov.get("hive_id", ""), NODE_ID)
                append_journal("capsule", _authorize_content_payload(cap))
                sealed = {w["device_id"] for w in cap.get("wraps", [])}
                unsealable = sorted(set(recips) - sealed)
                line = f"Rotated {nm!r} → v{nextv} ({len(sealed)} recipient(s))."
                if unsealable:
                    line += (f" SKIPPED {len(unsealable)} device(s) with an unusable key: "
                             f"{', '.join(unsealable)}.")
                print(line)
            print("Reminder: rotation does NOT revoke a removed device's access to OLD ciphertext it "
                  "already synced — rotate the upstream token to truly cut access.")
            return 0

        val = _read_secret_value(args, args.name)
        if val is None:
            print("No value provided (cancelled)."); return 1
        cur = caps.get(args.name)
        nextv = (int(cur.get("version", 0)) + 1) if cur else 1
        cap = _capsule_build(args.name, "credential", val, recips, nextv,
                             gov.get("hive_id", ""), NODE_ID)
        append_journal("capsule", _authorize_content_payload(cap))
        sealed = {w["device_id"] for w in cap.get("wraps", [])}
        unsealable = sorted(set(recips) - sealed)
        msg = f"Sealed capsule {args.name!r} v{nextv} to {len(sealed)} device(s)."
        if missing:
            msg += (f" WARNING: {len(missing)} admitted device(s) have no published pubkey yet and "
                    f"cannot open it until you rotate after they sync.")
        if unsealable:
            msg += (f" SKIPPED {len(unsealable)} device(s) with an unusable key (not sealed to): "
                    f"{', '.join(unsealable)}.")
        if suspect:
            msg += (f" SECURITY: {len(suspect)} device(s) carried a curve_pub that disagrees with "
                    f"their identity-derived key — IGNORED (not trusted): {', '.join(sorted(suspect))}.")
        print(msg)
        print("Note: a device removed later can still open an OLD version it already synced — rotate "
              "the upstream secret to truly cut access.")
        return 0

    print("usage: hv capsule put|get|ls|rm|rotate <name>")


def _secret_key_files():
    """The raw private-key files this device may hold (device + owner seeds), in the key directory and at
    the legacy root of the working tree (2.0 PR 3a). Stash copies live elsewhere; these are what identity
    and governance read."""
    out = []
    for label, new, legacy in (("device-key", KEY_DIR / "device-key", LEGACY_DEVICE_KEY_PATH),
                               ("owner-key", KEY_DIR / "owner-key", LEGACY_OWNER_KEY_PATH)):
        out.append((label, new))
        if legacy != new:
            out.append((label, legacy))
    out.append(("owner-key", OWNER_SEALED_PATH))     # sealed (2.0 PR 3b): ciphertext, but still 0600
    return out


def _legacy_key_files():
    """Key files still in the working tree: [(label, legacy_path, key_dir_path)] (2.0 PR 3a)."""
    out = []
    for label, legacy, name in (("device-key", LEGACY_DEVICE_KEY_PATH, "device-key"),
                                ("owner-key", LEGACY_OWNER_KEY_PATH, "owner-key"),
                                ("owner-pub", LEGACY_OWNER_PUB_PATH, "owner-pub")):
        try:
            if legacy.exists():
                out.append((label, legacy, KEY_DIR / name))
        except OSError:
            pass
    return out


def _relocate_legacy_keys(dry):
    """Move this plane's key files out of the working tree into the key directory (0700; files 0600, the
    public owner-pub 0644). Only the labels `_fixable_key_files` allows here: `hv` moves the device key,
    `hive-mind` the owner key and its public half. Never overwrites a key already in the key directory:
    a clash is reported and left for the operator, unless the two copies are identical (a move that was
    interrupted after the copy), when the legacy one is dropped. Returns (moved, other_plane, problems).

    Repoints the path global as each file moves: the rest of this run (the key announce below it in
    `doctor --fix`) must read the key where it now is. A stale DEVICE_KEY_PATH would read as "no device
    key", which `_ensure_device_key` answers by minting a NEW identity."""
    global DEVICE_KEY_PATH, OWNER_KEY_PATH, OWNER_PUB_PATH
    fixable = {lbl for lbl, _p in _fixable_key_files()}
    mine = fixable | ({"owner-pub"} if "owner-key" in fixable else set())
    moved, other_plane, problems = [], [], []
    for label, legacy, target in _legacy_key_files():
        if label not in mine:
            other_plane.append(label)
            continue
        try:
            if target.exists():
                if target.read_bytes() != legacy.read_bytes():
                    problems.append(f"{label} (both copies exist; not overwriting {target})")
                    continue
                if not dry:
                    legacy.unlink()
            elif not dry:
                _ensure_key_dir()
                shutil.copy2(legacy, target)
                os.chmod(target, 0o644 if label == "owner-pub" else 0o600)
                legacy.unlink()
        except OSError as e:
            problems.append(f"{label} ({e})")
            continue
        moved.append(label)
        if not dry:
            if label == "device-key":
                DEVICE_KEY_PATH = target
            elif label == "owner-key":
                OWNER_KEY_PATH = target
            else:
                OWNER_PUB_PATH = target
    return moved, other_plane, problems


def _fixable_key_files():
    """The key files `hv doctor --fix` may re-tighten: the DEVICE key only (2.0 PR 2b). The owner key is
    operator state, re-tightened by `hive-mind doctor --fix`, which replaces this. The device key stays
    here so an agent-only node's 15-minute `hv doctor --fix` timer still repairs a leaky one."""
    return [(lbl, p) for lbl, p in _secret_key_files() if lbl == "device-key"]


def _leaky_key_files(files=None):
    """Existing secret key files whose POSIX mode grants ANY group/other access. Returns
    [(label, path, mode)]; empty when all are 0600-or-tighter (or absent). POSIX-only. `files` defaults
    to every secret key file; stat only, never a read."""
    out = []
    for label, pth in (files if files is not None else _secret_key_files()):
        try:
            if pth.exists():
                mode = pth.stat().st_mode & 0o777
                if mode & 0o077:
                    out.append((label, pth, mode))
        except Exception:
            pass
    return out


def _fix_key_perms():
    """Re-tighten any leaky secret key file to 0600. Returns (fixed, failed): a chmod that FAILS must
    NOT be swallowed — a private key left group/other-readable collapses the whole threat model, so
    the caller surfaces `failed` loudly rather than reporting a clean fix."""
    fixed, failed = [], []
    for label, pth, _mode in _leaky_key_files(_fixable_key_files()):
        try:
            os.chmod(pth, 0o600)
            fixed.append(label)
        except Exception as e:
            failed.append(f"{label} ({e})")
    return fixed, failed


def _owner_copies():
    """Paths (never contents) of owner-key copies: `hive-owner-*.key` exports in HIVE_HOME, the current
    directory, the home directory and the identity stash, plus the stash's plaintext `.owner-key`. The
    exports are found by name and never opened: the default export is sealed, `--plaintext` is not, and both
    write the same basename."""
    stash = Path(os.environ.get("HIVE_IDENTITY_STASH", Path.home() / ".config" / "hive-mind" / "identity"))
    found = []
    for d in (HIVE_HOME, Path.cwd(), Path.home(), stash):
        try:
            hits = sorted(d.glob("hive-owner-*.key"))
        except OSError:
            continue
        found.extend(str(p) for p in hits if p.is_file() and str(p) not in found)
    p = stash / ".owner-key"
    if p.is_file() and str(p) not in found:
        found.append(str(p))
    return found


