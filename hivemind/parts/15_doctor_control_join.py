def _hv_namespace():
    """This file's globals as an object, for a helper module that reads `hv`'s paths and functions. It is not
    `sys.modules[__name__]`: a test (or a tool) may load `hv` under a name nothing registered."""
    import types
    return types.SimpleNamespace(**globals())


def doctor_cmd(args):
    """Aggregate local health check: authenticity, journal integrity, the derived DB, corpus
    hygiene, the sync daemon, peer reachability, and the Claude Code agent integration. Read-only by
    default. `--fix` takes the safe remedial actions: kill orphan sync daemons (a stale process holding
    :9876 outside systemd) + restart the managed unit, and re-assert any missing Claude Code hooks +
    the skill symlink (the 15-min `hive-doctor.timer` runs `--fix`, so a node that drifted self-heals
    unattended). Exits non-zero if any check FAILED; warnings keep a zero exit (so cron/monitors alert
    only on real breakage). Subcommands fold in the rarely-used device maintenance ops: `hv doctor
    merkle` (sync diagnostic) and `hv doctor rebuild` (reconstruct store.db from the journal)."""
    action = getattr(args, "doctor_action", None)
    if action == "rebuild":
        rebuild(args)
        return
    if action == "merkle":
        merkle_cmd(args)
        return
    checks = _doctor_status()
    fails = [c for c in checks if c["status"] == "fail"]
    warns = [c for c in checks if c["status"] == "warn"]

    if getattr(args, "format", "text") == "json":
        verdict = "fail" if fails else ("warn" if warns else "ok")
        print(json.dumps({"verdict": verdict, "node": NODE_ID, "checks": checks}, indent=2))
    else:
        glyph = {"ok": "✓", "warn": "•", "fail": "✗"}
        print(f"hive doctor — {NODE_ID}")
        for c in checks:
            print(f"  {glyph.get(c['status'], '?')} {c['name']:<13} {c['detail']}")
        if fails:
            print(f"\n{len(fails)} check(s) FAILED — see above.")
        elif warns:
            print(f"\nhealthy, with {len(warns)} advisory warning(s).")
        else:
            print("\nall checks passed.")

    if getattr(args, "fix", False):
        # --dry-run previews EVERY mutating action (chmod, kill-by-cmdline, systemd restart, foreign
        # Claude-config rewrite) without performing it — so an operator can see the blast radius of
        # doctor's broad self-heal before letting it touch processes or another tool's config.
        dry = getattr(args, "dry_run", False)
        if dry:
            print("\n--fix --dry-run: PREVIEW only — nothing below will actually be changed.")
        if os.name != "nt":
            if dry:
                leaky = _leaky_key_files()
                if leaky:
                    print(f"  would re-tighten to 0600: {', '.join(lbl for lbl, _p, _m in leaky)}")
            else:
                fixed, failed = _fix_key_perms()
                if fixed:
                    print(f"\n--fix: re-tightened {', '.join(fixed)} to 0600.")
                if failed:
                    print(f"\n--fix: FAILED to tighten {', '.join(failed)} — these private key(s) are "
                          f"STILL group/other-readable; fix manually (`chmod 600`) NOW.")
                left = [lbl for lbl, _p, _m in _leaky_key_files()
                        if lbl not in {f for f, _q in _fixable_key_files()}]
                if left:
                    print(f"\n--fix: {', '.join(left)} is STILL group/other-readable. It is operator state: "
                          "run `hive-mind doctor --fix` to re-tighten it (2.0).")
        # Keys out of the working tree (2.0 PR 3a, private #27): this plane's keys move into the key dir.
        try:
            moved, other_plane, problems = _relocate_legacy_keys(dry)
            if moved:
                print(f"\n{'  would move' if dry else '--fix: moved'} {', '.join(moved)} out of the working tree "
                      f"into {KEY_DIR} (0700).")
            if other_plane:
                print(f"\n--fix: {', '.join(other_plane)} {'is' if len(other_plane) == 1 else 'are'} still in the "
                      "working tree. It is operator state: `hive-mind doctor --fix` moves it.")
            if problems:
                print(f"\n--fix: could NOT move: {'; '.join(problems)}")
        except Exception as e:
            print(f"\n--fix: key relocation error: {e}")

        # Self-announce this device's signing key: a device admitted directly by the owner that
        # never authored an entry has no harvestable pub (the device-keys advisory above), so it
        # can never receive capsules. One authority-less `announce` (kind:key) fixes that, and the
        # 15-min doctor timer makes it unattended fleet-wide. Gated on an established owner so a
        # standalone / pre-owner node never auto-appends governance noise (`hv config identity announce`
        # covers deliberate pre-owner use).
        try:
            _es = merkle.read_all_entries(JOURNAL_DIR)
            if _announce_needed(_es) and _governance_state(_es)["owner_id"]:
                if dry:
                    print("\n  would announce this device's signing key (one `announce` journal entry).")
                else:
                    _emit_key_announce()
                    print(f"\n--fix: announced this device's signing key ({NODE_ID}) — "
                          f"propagates on the next sync.")
        except Exception as e:
            print(f"\n--fix: key-announce heal error: {e}")

        # Pin the genesis when there is exactly one candidate. A plain `hv doctor` stays read-only and
        # only warns; pinning is operator state, so it is `hive-mind doctor --fix` (2.0 PR 2b), and this
        # plane's placeholder only says so. Never guesses: two candidates mean a rival is stored.
        try:
            _heal_genesis_pin(merkle.read_all_entries(JOURNAL_DIR), dry)
        except Exception as e:
            print(f"\n--fix: genesis-pin heal error: {e}")

        # Close the pre-genesis forget grandfather (4c). It is an owner-signed act, so on this plane the
        # placeholder only points at `hive-mind doctor --fix`; the 15-minute timer never sets the policy.
        try:
            _heal_forget_authz(merkle.read_all_entries(JOURNAL_DIR), dry)
        except Exception as e:
            print(f"\n--fix: forget-authz heal error: {e}")

        restarted = False
        orphans = [p for c in checks for p in (c.get("orphans") or [])]
        if not orphans:
            print("\n--fix: no orphan daemons to clear.")
        elif dry:
            print(f"\n  would kill {len(orphans)} orphan daemon(s): {', '.join(map(str, orphans))}"
                  f" and restart the managed hive-sync service (if present)")
        else:
            print(f"\n--fix: killing {len(orphans)} orphan daemon(s): {', '.join(map(str, orphans))}")
            _kill_orphans(orphans)
            # Restart the supervisor-managed daemon so the just-cleared port is reclaimed by the
            # canonical instance.
            msg = _restart_managed_daemon()
            restarted = True
            if msg:
                print(f"  {msg}")
            after = next((c for c in _doctor_status() if c["name"] == "sync-daemon"), None)
            print(f"  sync-daemon now: {after['detail'] if after else 'unknown'}")

        # sync-bind (#47): the daemon is serving, but not on the address resolve_bind picks now (it
        # started before tailscaled, or the tailnet IP changed). A restart rebinds it.
        sb = next((c for c in checks if c["name"] == "sync-bind"), None)
        if sb and sb["status"] == "warn" and not restarted:
            restarted = True                           # one restart per --fix, whichever branch asks (#112)
            if dry:
                print("\n  would restart the managed hive-sync service to rebind it (sync-bind)")
            else:
                msg = _restart_managed_daemon()
                print(f"\n--fix: {msg or 'no managed hive-sync service found to restart'} (sync-bind: {sb['detail']})")

        # daemon-code (#112): the daemon runs code that no longer matches its own checkout (a bare `git
        # pull`). A restart loads the current code; the 15-min hive-doctor.timer makes this self-healing.
        dcc = next((c for c in checks if c["name"] == "daemon-code"), None)
        if dcc and dcc.get("stale") and not restarted:
            restarted = True
            if dry:
                print("\n  would restart the managed hive-sync service to load the current code (daemon-code)")
            else:
                msg = _restart_managed_daemon()
                print(f"\n--fix: {msg or 'no managed hive-sync service found to restart'} (daemon-code: {dcc['detail']})")

        # peer-address (#7): a peer's stored address failed and its device has since verified itself at
        # another one. Repoint that entry's URL host in .peers.json; the daemon reads the file each round,
        # so no restart. An address that answered is never in `moves`.
        pa = next((c for c in checks if c["name"] == "peer-address"), None)
        moves = (pa or {}).get("moves") or []
        if moves and dry:
            for m in moves:
                print(f"\n  would repoint peer {m['device'][:11]}… in .peers.json: {m['url']} -> {m['to']} (peer-address)")
        elif moves:
            try:
                import sync_common
                done = _repoint_peers(sync_common.peers_path(), moves)
                for m in done:
                    print(f"\n--fix: repointed peer {m['device'][:11]}… in .peers.json: {m['url']} -> {m['to']} (peer-address)")
                if len(done) < len(moves):
                    print(f"\n--fix: left {len(moves) - len(done)} peer-address entr(y/ies) alone: "
                          f".peers.json changed since the check")
            except Exception as e:
                print(f"\n--fix: peer-address heal error: {e}")

        # Self-heal the agent integration. The 15-min systemd timer runs `hv doctor --fix`, so THIS
        # is where Claude Code hooks that drifted (or never wired on a pre-nudge install) get
        # re-asserted with no one re-running the installer — the self-heal promise, extended to the
        # one component that lives outside the daemon's control.
        try:
            w = _wire_agent(_builtin_claude_cell(), write=not dry)   # dry-run → preview the diff without writing config
            if dry:
                if w["applicable"] and (w["missing"] or w["stale"] or not w["skill_ok"]):
                    acts = []
                    if w["missing"]:
                        acts.append(f"wire {len(w['missing'])} dispatch shim(s)")
                    if w["stale"]:
                        acts.append(f"migrate {len(w['stale'])} legacy hook(s) to the shim")
                    if not w["skill_ok"]:
                        acts.append("relink the hive-memory skill")
                    print("\n  would rewrite ~/.claude/settings.json to: " + "; ".join(acts) + ".")
            elif not w["applicable"]:
                pass  # no Claude Code on this node — nothing to wire
            elif w["wrote"] or w["skill_fixed"]:
                acts = []
                if w["missing"]:
                    acts.append(f"wired {len(w['missing'])} dispatch shim(s)")
                if w["stale"]:
                    acts.append(f"migrated {len(w['stale'])} legacy hook(s) to the shim")
                if w["skill_fixed"]:
                    acts.append("relinked the hive-memory skill")
                print("\n--fix: " + "; ".join(acts) + ".")
            elif not w["skill_ok"]:
                print("\n--fix: hive-memory skill could not be relinked (skill source missing?)")
            else:
                print("\n--fix: Claude Code integration already wired.")
        except Exception as e:
            print(f"\n--fix: agent-hooks heal error: {e}")

        # Modules (2.1, M7): re-render a unit that differs from its verified manifest, start a stopped one.
        # Never admits, revokes or signs anything.
        try:
            import hive_module_doctor
            fixes = hive_module_doctor.fix(_hv_namespace(), dry)
            if fixes:
                print("\n--fix: modules")
                print("\n".join(fixes))
        except Exception as e:
            print(f"\n--fix: modules heal error: {e}")

        # The forget grandfather is the one failing check `--fix` can settle in place (on the control plane,
        # 4c), so re-read it: a hive closed just now exits clean instead of on the pre-fix verdict.
        if not dry and any(c["name"] == "forget-authz" for c in fails):
            _es = merkle.read_all_entries(JOURNAL_DIR)
            now = _forget_authz_check(_es, _governance_state(_es))
            if now is None or now["status"] != "fail":
                fails = [c for c in fails if c["name"] != "forget-authz"]
                print(f"\n  forget-authz now: {now['detail'] if now else 'nothing to check'}")

    sys.exit(1 if fails else 0)


def _heal_genesis_pin(entries, dry):
    """Placeholder for the genesis-pin repair (2.0 PR 2b). Pinning is operator state, so the repair is
    `hive-mind doctor --fix` (`hivemind_owner.py` replaces this); `hv doctor --fix` only points at it."""
    if _load_genesis_pin() is None and len(_self_signed_owner_acts(entries)) == 1:
        print("\n--fix: this hive's single genesis declaration is not pinned on this device. Pinning is "
              "operator state: run `hive-mind doctor --fix` (or `hive-mind owner pin --set`).")


def _heal_forget_authz(entries, dry):
    """Placeholder for settling the migration set (4c, 3.0). Re-signing the forgets is owner-signed, so it is
    `hive-mind migrate forget` or `hive-mind doctor --fix` (`hivemind_owner.py` replaces this). Here it only says
    so, and `hv doctor` keeps failing `forget-authz` until it is done."""
    c = _forget_authz_check(entries, _governance_state(entries))
    if c is not None and c.get("open"):
        print("\n--fix: facts depend on a pre-genesis unsigned forget (forget-authz). Re-signing them is an owner act: "
              "run `hive-mind migrate forget` on the owner machine.")


def _append_governance(action_payload):
    """Placeholder: owner-sign and append a governance entry. Every owner-signed governance act is on the
    control plane (2.0 S2, `hivemind_owner.py`); here it refuses."""
    raise NotOnDataPlane(("owner",))


def _append_governance_device(action_payload):
    """Append a DEVICE-signed governance entry (no owner_sig), then rebuild. For acts whose authority
    is the signer's hive membership rather than the owner key — election proposals and votes. Any
    device can run these; `_governance_state` counts them only from admitted devices. `append_journal`
    already attaches this device's signature. $HIVE_NOW dates the entry (test hook; see above)."""
    entry = append_journal("governance", action_payload, timestamp=os.environ.get("HIVE_NOW") or None)
    rebuild_db()
    return entry


def _announce_needed(entries):
    """True iff this device has a key but the journal holds NO entry whose `pub` is identity-BOUND
    to NODE_ID — i.e. _recipient_pubkeys cannot harvest this device yet. Mirrors the harvest check
    exactly: _verify_entry grandfathers UNSIGNED entries, so a spoofed unsigned entry with
    node_id=us and a planted pub could otherwise land in the journal — but a planted pub can never
    fingerprint-match NODE_ID, so it can't suppress the announcement (only the real key holder can
    mint a binding entry, and then suppression == already-harvestable, which is correct)."""
    if _ed25519 is None or _device_seed() is None:
        return False
    for e in entries:
        if e.get("node_id") == NODE_ID and e.get("pub"):
            try:
                pub = base64.b64decode(e["pub"])
                if len(pub) == 32 and _device_id_for_pub(pub) == NODE_ID:
                    return False   # already harvestable — one announce ever
            except Exception:
                pass
    return True


def _emit_key_announce():
    """Author the kind:key announce — a device-signed governance no-op whose whole value is to
    exist as a signed entry carrying `pub` (the capsule key source _recipient_pubkeys harvests).
    Fixed envelope (action, kind); kind-specific fields ride under `data` so future announce
    kinds never collide. The payload itself is advisory and NEVER trusted as a key source."""
    return _append_governance_device({"action": "announce", "kind": "key",
                                      "data": {"device_id": NODE_ID, "label": _wire_label(NODE_LABEL)}})


def _grandfather_remedy(sids):
    """The two remedies `_config_set`'s #122 guard prints, for the facts a failed close left behind."""
    for sid in sids:
        print(f"    {sid}   keep it forgotten: hive-mind retract {sid} --owner   |   "
              f"let it back: hive-mind unforget {sid} --reason …")
    print("    Then record the close for 2.x peers:  hive-mind migrate forget")


# `_close_grandfather_at_genesis` (#135 part 1) moved with `owner init` to the control plane
# (`hivemind_owner.py`, 2.0 PR 2b).


def owner_cmd(args):
    """`hv owner …`: the read-only and DEVICE-signed owner actions — show, elections, propose-election
    --pub and vote — so dead-man recovery works on a node that has only `hv`. Every action that reads the
    owner seed, writes owner-key material or owner-signs is `hive-mind owner …` (2.0 S2)."""
    action = getattr(args, "owner_action", None) or "show"
    entries = merkle.read_all_entries(JOURNAL_DIR)
    gov = _governance_state(entries)
    if action == "show":
        if not gov["owner_id"]:
            print("No owner established. Run `hive-mind owner init` to mint the owner key and claim it.")
            return
        key = _owner_key_state(gov)                 # 2.0 S2: decided without reading the seed
        held = key == "held"
        print(f"owner: {gov['owner_id']}" + ("  (this device holds the owner key)" if held else
                                             "  (an owner key is on this device, not verified from `hv`)"
                                             if key == "present" else
                                             "  (whether this device holds the owner key cannot be told)"
                                             if key == "unknown" else ""))
        print(f"  hive_id: {gov['hive_id']}")
        g = gov.get("genesis") or {}
        fp = _genesis_fingerprint(entries, gov)
        print(f"  genesis: {g.get('ref') or '?'}" + (f"  fingerprint {fp}" if fp else "")
              + ("  (pinned)" if g.get("pinned") else "  (NOT PINNED — `hive-mind owner pin --set`)"))
        if g.get("candidates", 0) > 1:
            print(f"  WARNING: {g['candidates']} self-signed owner declarations in this journal "
                  "— see `hv doctor genesis`")
        print(f"  admitted devices: {len(gov['admitted'])}; principals tagged: {len(gov['principals'])}; "
              f"pending: {len(_pending_admissions(entries, gov))}; "
              f"denied: {len(gov['denied'])}; purged: {len(gov['purged'])}")
        print(f"  config: same_device_lambda={gov['config']['same_device_lambda']}, "
              f"cap_self={gov['config']['cap_self']}")
        qm = int(gov["config"].get("quorum_m", 0) or 0)
        if qm > 0:
            print(f"  quorum: {qm} {gov['config'].get('quorum_by')}(s) elect a new owner after "
                  f"{gov['config'].get('dead_man_days')}d of owner silence")
        if gov["elections"]:
            print(f"  open elections ({len(gov['elections'])}): "
                  + ", ".join(f"{e['proposal_id']}->{e['new_owner_id']} ({e['votes']}/{e['quorum_m']}"
                              + (", armed" if e['armed'] else "") + ")" for e in gov["elections"]))
        if gov["standbys"]:
            print(f"  standbys ({len(gov['standbys'])}): {', '.join(sorted(gov['standbys']))}")
        if gov["owner_term"]:
            print(f"  handoffs: {gov['owner_term']} (ownership succeeded from the genesis owner)")
        if gov["nominations"]:
            sids = sorted(_owner_id_for_pub(base64.b64decode(c)) for c in gov["nominations"])
            print(f"  open nominations ({len(sids)}): {', '.join(sids)}")
        if gov["escrows"]:
            print(f"  live escrows: {len(gov['escrows'])} (recover with `hive-mind owner restore`)")
        if not held:
            print("  This is a member node; membership and config changes run on the owner device.")
        return
    if action == "propose-election":
        if not gov["owner_id"]:
            print("No owner established — nothing to elect.")
            return
        if int(gov["config"].get("quorum_m", 0) or 0) <= 0:
            print("Quorum elections are OFF (quorum_m=0). The owner must enable them first:")
            print("  hive-mind config set quorum_m <N>")
            return
        if NODE_ID not in gov["admitted"]:
            print("Only an ADMITTED device can propose an election (you are not admitted here).")
            return
        if _ed25519 is None:
            print("ed25519 unavailable; cannot propose an election.")
            return
        new_pub = _canon_pub(getattr(args, "pub", "") or "")
        if not new_pub:
            print("Provide the proposed owner key: `--pub <base64>` (mint one with `hive-mind owner mint`).")
            return
        basis_ts = os.environ.get("HIVE_NOW") or _now_iso()
        pid = _election_id(new_pub, basis_ts)
        new_oid = _owner_id_for_pub(base64.b64decode(new_pub))
        if _append_governance_device({"action": "propose-election", "proposal_id": pid,
                                      "new_owner_pub": new_pub, "basis_ts": basis_ts}):
            qm = int(gov["config"].get("quorum_m"))
            dmd = gov["config"].get("dead_man_days")
            print(f"Proposed election {pid}: new owner {new_oid} (basis {basis_ts}).")
            print(f"  Other admitted devices vote with:  hv owner vote {pid}")
            print(f"  Installs once {qm} device(s) endorse it AND the owner is silent for {dmd} day(s).")
        return
    if action == "vote":
        if NODE_ID not in gov["admitted"]:
            print("Only an ADMITTED device can vote.")
            return
        pid = args.proposal_id
        match = next((e for e in gov["elections"] if e["proposal_id"] == pid), None)
        if not match:
            print(f"No known election {pid}. List open elections with `hv owner elections` (sync first).")
            return
        if _append_governance_device({"action": "vote-election", "proposal_id": pid}):
            print(f"Voted for election {pid} (would install owner {match['new_owner_id']}).")
            tail = "dead-man armed" if match["armed"] else "owner still active — will not install yet"
            print(f"  ~{match['votes'] + 1}/{match['quorum_m']} votes after sync; {tail}.")
        return
    if action == "elections":
        qm = int(gov["config"].get("quorum_m", 0) or 0)
        if not gov["elections"]:
            print("No open elections." + ("" if qm > 0 else "  (Quorum is OFF — quorum_m=0.)"))
            return
        print(f"Elections (quorum_m={qm}, dead_man_days={gov['config'].get('dead_man_days')}, "
              f"by={gov['config'].get('quorum_by')}):")
        for e in gov["elections"]:
            flags = (["INSTALLED"] if e["installed"]
                     else (["quorum-reached"] if e["crossed"] else [f"{e['votes']}/{e['quorum_m']} votes"]))
            if not e["installed"]:
                flags.append("dead-man armed" if e["armed"] else "owner active")
            print(f"  {e['proposal_id']}  ->  {e['new_owner_id']}   [{', '.join(flags)}]")
        return
    # Every other action reads the owner seed, writes owner-key material or owner-signs: control plane.
    raise NotOnDataPlane(("owner", action))


def _self_tailnet_ip():
    """This device's Tailscale IPv4, best-effort (''). The `tailscale` CLI is authoritative, so try
    it FIRST — the 100.64.0.0/10 range is shared with carrier-grade NAT and some WSL/virtual
    interfaces, so a bare interface grep can return a non-tailnet 100.x. The interface scan is the
    Android/Termux fallback (no CLI there), preferring a tailscale-looking interface."""
    import re
    pat = re.compile(r"\b(100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3})\b")
    try:
        out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=3).stdout
        ip = (out.strip().splitlines() or [""])[0].strip()
        if pat.fullmatch(ip):
            return ip
    except Exception:
        pass
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=2).stdout
        fallback = ""
        for line in out.splitlines():
            m = pat.search(line)
            if not m:
                continue
            if re.search(r"\b(tailscale\d*|ts\d+|tun\d*|utun\d*)\b", line):
                return m.group(1)
            fallback = fallback or m.group(1)
        if fallback:
            return fallback
    except Exception:
        pass
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=2).stdout
        m = pat.search(out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _self_sync_port():
    try:
        import sync_common
        return sync_common.load_peers().get("port", 9876)
    except Exception:
        return 9876


def _self_address():
    """'ip:port' this device is reachable at on the tailnet, or '' if unknown. For display
    (whoami/stats/peers) and as the basis of the join-request URL."""
    ip = _self_tailnet_ip()
    return f"{ip}:{_self_sync_port()}" if ip else ""


def _self_sync_url():
    """This device's reachable sync URL (Tailscale IPv4 : configured port) — carried in a
    join-request so the owner can peer back on admit. Best-effort; '' if the IP is unknown.
    Resolves the IP CLI-first with an interface fallback, so it also works on Android/Termux
    (where `tailscale ip` does not exist)."""
    addr = _self_address()
    return f"http://{addr}" if addr else ""


def _join_request_urls(ended_at=None):
    """{device_id: url} each device advertised in its join-request (last one wins). `ended_at` ({device: journal
    position of the revoke or purge that ended it}) stops a device's join-requests at that act: a join-request
    written after the device was ended leaves the URL where it was. Where this node has an arrival record
    (`.arrivals.jsonl`) for the join-request it decides alone: received after the act's stamp leaves the URL,
    received at or before it counts whatever stamp it carries; with no arrival record the stamp rule applies
    (SECREV B6)."""
    urls = {}
    arrived = _read_arrivals() if ended_at else {}
    for e in merkle.read_all_entries(JOURNAL_DIR):
        if e.get("type") == "governance":
            p = e.get("payload", {})
            if p.get("action") == "join-request" and _peer_url_ok(p.get("url")):
                cut = (ended_at or {}).get(p.get("device_id"))
                if cut:
                    got, act = _ts_instant(arrived.get((e.get("node_id"), e.get("seq")))), _ts_instant(cut[0])
                    if got is not None and act is not None:
                        if got > act:
                            continue
                    elif (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0)) > tuple(cut):
                        continue
                urls[p.get("device_id")] = p["url"]
    return urls


def _join_request_url(device_id):
    """The reachable URL a device advertised in its join-request (last one wins), or '' if none."""
    return _join_request_urls().get(device_id, "")


def _add_peer(url, label):
    """Idempotently add {url} to this node's .peers.json (skips self + duplicates). Returns True if
    added. This is how admission SEEDS reciprocal peering — connectivity stays a separate concern
    from the trust grant (admit confers no governance), and the peer list remains editable."""
    if not _peer_url_ok(url) or url.rstrip("/") == _self_sync_url().rstrip("/"):
        return False
    label = label if _plain_text(label, _PEER_LABEL_MAX) else None     # a bad label falls back to the url
    path = HIVE_HOME / ".peers.json"
    try:
        cfg = json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        cfg = {}
    peers = cfg.get("peers") or []
    if any(str(p.get("url", "")).rstrip("/") == url.rstrip("/") for p in peers):
        return False
    peers.append({"url": url, "id": label or url})
    cfg["peers"] = peers
    cfg.setdefault("self", NODE_ID)
    cfg.setdefault("bind", "0.0.0.0")
    cfg.setdefault("port", 9876)
    try:
        path.write_text(json.dumps(cfg, indent=2) + "\n")
    except Exception:
        return False
    return True


def _group_change(action, device_id, principal=None):
    """Placeholder: revoke / deny / change / purge are owner-signed — `hive-mind group …` (2.0 S2)."""
    raise NotOnDataPlane(("group", action))


def _group_retire(device_id, through=None, confirm=False):
    """Placeholder: retire is an owner-signed purge that keeps the device's past content — `hive-mind group retire` (#260)."""
    raise NotOnDataPlane(("group", "retire"))


def _group_list():
    """Print the full membership roster: owner, admitted (+principals), pending, denied, purged."""
    entries = merkle.read_all_entries(JOURNAL_DIR)
    gov = _governance_state(entries)
    if not gov["owner_id"]:
        print("No owner established yet — no membership to list. Run `hive-mind owner init`.")
        return
    print(f"hive {gov['hive_id']} — owner {gov['owner_id']}")
    print(f"admitted ({len(gov['admitted'])}):")
    for d in sorted(gov["admitted"]):
        prin = gov["principals"].get(d)
        print(f"  {d}" + (f"  (principal: {prin})" if prin else ""))
    pend = _pending_admissions(entries, gov)
    if pend:
        print(f"pending ({len(pend)}):")
        for r in pend:
            print(f"  {r['device_id']}  ({r['label'] or '?'})  →  hive-mind group admit {r['device_id']} --principal <name>")
    if gov["denied"]:
        print(f"denied ({len(gov['denied'])}):")
        for d in sorted(gov["denied"]):
            print(f"  {d}")
    if gov["purged"]:
        print(f"purged ({len(gov['purged'])}):")
        for d in sorted(gov["purged"]):
            print(f"  {d}" + (f"  (retired: seq 1..{gov['keep'][d][0]} still counts)" if d in gov["keep"] else ""))
    if _x25519 is None:
        print("device keys: n/a (crypto lib absent)")
    else:
        _, missing, suspect = _recipient_pubkeys(entries, gov)
        if missing:
            print(f"missing keys ({len(missing)}):  # admitted but no synced device key yet — can't receive capsules")
            for d in missing:
                print(f"  {d}")
        if suspect:
            print(f"SECURITY — carried curve_pub disagrees with identity-derived key, ignored ({len(suspect)}):")
            for d in sorted(suspect):
                print(f"  {d}")


def group_retire_cmd(args):
    """`hive-mind group retire <device> [--through SEQ] [--confirm]` (#260): the owner's purge that keeps the device's
    chain through a signed seq. Owner-signed, so the step lives on the control plane (`_group_retire`)."""
    _group_retire(args.device_id, args.through, args.confirm)


def group_cmd(args):
    """Membership lifecycle (owner-only): admit / revoke / deny / change / purge / retire / list.
    admit reuses admit_cmd (no arg → pending list, + reciprocal-peer seeding)."""
    action = getattr(args, "group_action", None)
    if action in (None, "list"):
        _group_list()
        return
    if action == "admit":
        admit_cmd(args)
        return
    gov = _governance_state(merkle.read_all_entries(JOURNAL_DIR))
    dev = args.device_id
    if action in ("revoke", "change") and dev not in gov["admitted"]:
        print(f"{dev} is not an admitted device — nothing to {action}.")
        return
    if action == "change":
        _group_change("change", dev, args.principal)
    else:
        _group_change(action, dev)


def _config_set(key, value):
    """Placeholder: setting a governed parameter is owner-signed — `hive-mind config set` (2.0 S2,
    `hivemind_owner.py`)."""
    raise NotOnDataPlane(("config", "set"))


def config_cmd(args):
    """Settings: `hv config identity show|init` (this device's key) and
    `hive-mind config set <param> <value>` (owner-signed hive params).
    `hive-mind config set …` is kept as a silent alias for `config confidence set`."""
    action = getattr(args, "config_action", None)
    if action == "identity":
        sub = getattr(args, "config_identity_action", None) or "show"
        if sub == "init":
            _identity_init(getattr(args, "force", False))
        elif sub == "announce":
            _key_announce()
        else:
            _identity_show()
    elif action == "confidence":
        if getattr(args, "config_confidence_action", None) == "set":
            _config_set(args.key, args.value)
        else:
            print("usage: hive-mind config set <same_device_lambda|cap_self> <value>")
    elif action == "quorum":
        if getattr(args, "config_quorum_action", None) == "set":
            _config_set(args.key, args.value)
        else:
            print("usage: hive-mind config set <quorum_m|quorum_by|dead_man_days> <value>")
    elif action == "set":            # silent back-compat alias for `config confidence set`
        _config_set(args.key, args.value)
    else:
        print("usage: hv config identity show|init  |  hive-mind config set <key> <value>  |  "
              "hive-mind config set <key> <value>")


def _peer_status(url, local_root):
    """Probe a peer's reachability + sync state via /sync/merkle-root. Returns a short label."""
    if not url:
        return "no advertised address"
    try:
        import requests
    except Exception:
        return "unknown (no 'requests')"
    try:
        rr = requests.get(url.rstrip("/") + "/sync/merkle-root", timeout=5)
        rr.raise_for_status()
        return "reachable · in sync" if rr.json().get("root_hash") == local_root else "reachable · diverged"
    except Exception:
        return "unreachable"


def _join_request_label(device_id):
    """The human-readable label a device advertised in its join-request (last one wins), or '' if
    none — the device-NAME source for `hv peers`, mirroring _join_request_url."""
    label = ""
    for e in merkle.read_all_entries(JOURNAL_DIR):
        if e.get("type") == "governance":
            p = e.get("payload", {})
            if p.get("action") == "join-request" and p.get("device_id") == device_id and _peer_label_ok(p.get("label")):
                label = p["label"]
    return label


def peers_cmd(args):
    """List hive MEMBERS by name + device + principal + address + last-seen + reachability.
    Authoritative roster from the governance journal (admitted device_ids + principals). NAME is the
    device's advertised join-request label. ADDRESS is resolved from a LIVE probe of the local
    .peers.json peers (/sync/hello -> node_id) first, then the advertised join-request URL — so a
    reachable peer (e.g. gregorius) shows its address even if it never advertised one. LAST SEEN is
    the date of the device's newest journal entry, so dormant/dead devices are obvious; a footer
    surfaces ready `hive-mind group purge` commands for devices idle >14 days. Read-only."""
    entries = merkle.read_all_entries(JOURNAL_DIR)
    gov = _governance_state(entries)
    if not gov["owner_id"]:
        print("No owner established yet — no hive members to list. (`hive-mind owner init`, or sync a hive then `hv join`.)")
        return
    local_root = merkle.merkle_root(merkle.chunk_hashes(entries))

    # newest journal-entry timestamp per device (the staleness signal)
    last_seen = {}
    for e in entries:
        d = e.get("node_id"); ts = e.get("timestamp", "")
        if d and ts > last_seen.get(d, ""):
            last_seen[d] = ts

    # Probe local .peers.json peers ONCE: /sync/hello -> node_id, so an admitted device maps to a
    # live address even when it never recorded a join-request URL (the gregorius gap).
    probed = {}   # node_id -> (address, status, label) from a live probe of the local peer list
    try:
        import requests
        import sync_common
        peerlist = sync_common.load_peers().get("peers", [])
    except Exception:
        requests, peerlist = None, []
    for peer in (peerlist or []):
        url = str(peer.get("url", "")).rstrip("/")
        if not url or requests is None:
            continue
        try:
            # node_id + label from /hive/info (open discovery); /sync/hello is now read-gated.
            info = requests.get(url + "/hive/info", timeout=5).json()
            nid = info.get("node_id")
            if not nid:
                continue
            try:
                root = requests.get(url + "/sync/merkle-root", timeout=5).json().get("root_hash")
                st = "reachable · in sync" if root == local_root else "reachable · diverged"
            except Exception:
                st = "reachable"
            probed[nid] = (url.replace("http://", "").replace("https://", ""), st, info.get("label", ""))
        except Exception:
            continue

    def _short(d):
        return (d[:11] + "…") if len(d) > 12 else d

    velocity = {}
    try:
        velocity = _trust_velocity(entries, gov, os.environ.get("HIVE_NOW") or _now_iso())
    except Exception:
        velocity = {}

    def _drift(d):
        v = velocity.get(d) or {}
        return f"{v['delta']:+.2f}" if v.get("delta") is not None else "—"

    rows, stale = [], []
    for d in sorted(gov["admitted"]):
        pr = probed.get(d)
        prin = gov["principals"].get(d) or "?"
        if d == NODE_ID:
            name, addr, status = NODE_LABEL, (_self_address() or "—"), "this device"
        elif pr:                                           # live .peers.json resolution (addr, status, label)
            name = pr[2] or _join_request_label(d) or "?"
            addr, status = pr[0], pr[1]
        else:
            name = _join_request_label(d) or "?"
            url = _join_request_url(d)
            if url:
                addr, status = url.rstrip("/").replace("http://", ""), _peer_status(url, local_root)
            else:
                addr, status = "—", "no address"
        seen = (last_seen.get(d, "")[:10]) or "—"
        rows.append((name, _short(d), prin, addr, seen, _drift(d), status))
        if d != NODE_ID:
            age = _age_days(last_seen.get(d, ""))
            if age is not None and age > 14:
                stale.append((d, name, seen, age))

    wn = max([len(str(r[0])) for r in rows] + [len("NAME")])
    wd = max([len(str(r[1])) for r in rows] + [len("DEVICE")])
    wp = max([len(str(r[2])) for r in rows] + [len("PRINCIPAL")])
    wa = max([len(str(r[3])) for r in rows] + [len("ADDRESS")])
    ws = max([len(str(r[4])) for r in rows] + [len("LAST SEEN")])
    wv = max([len(str(r[5])) for r in rows] + [len("DRIFT")])
    print(f"hive {gov['hive_id']} — owner {gov['owner_id']}  ({len(rows)} admitted device(s))")
    print(f"  {'NAME'.ljust(wn)}  {'DEVICE'.ljust(wd)}  {'PRINCIPAL'.ljust(wp)}  {'ADDRESS'.ljust(wa)}  {'LAST SEEN'.ljust(ws)}  {'DRIFT'.ljust(wv)}  STATUS")
    for name, dev, prin, addr, seen, drift, status in rows:
        print(f"  {str(name).ljust(wn)}  {dev.ljust(wd)}  {str(prin).ljust(wp)}  {str(addr).ljust(wa)}  {seen.ljust(ws)}  {drift.ljust(wv)}  {status}")
    if any(r[5] != "—" for r in rows):
        print("  (DRIFT = short-window minus long-window reliability, design §8; advisory — see `hv doctor` trust-drift)")
    if stale:
        print("\n  Stale candidate(s) — no activity in >14 days. To remove (owner only):")
        for d, name, seen, age in stale:
            print(f"    hive-mind group purge {d}    # {name}, last seen {seen} ({age}d ago)")
    else:
        print("\n  Stale/dead device? Owner: hive-mind group purge <device_id>  (tombstone; entries stay in the journal but stop counting)")


def discover_cmd(args):
    """Scan the tailnet (via `tailscale status`) for hives — every device running a hive daemon.
    Tailscale is the device directory; a `/hive/info` probe identifies which devices run a hive."""
    try:
        out = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=10).stdout
        status = json.loads(out)
    except Exception as e:
        print(f"Could not read `tailscale status`: {e}")
        return
    ips = list(status.get("Self", {}).get("TailscaleIPs", []) or [])
    for p in (status.get("Peer") or {}).values():
        ips += p.get("TailscaleIPs", []) or []
    ips = [ip for ip in ips if ":" not in ip]   # IPv4 only for the probe
    try:
        import sync_common
        port = sync_common.load_peers().get("port", 9876)
    except Exception:
        port = 9876
    # Probe every (device, port) concurrently so the scan is bounded by one short timeout, not the
    # sum — otherwise each offline tailnet device costs a full timeout and the scan appears to hang.
    import concurrent.futures
    candidates = [(ip, p) for ip in ips for p in range(port, port + 5)]
    found = {}
    if candidates:
        if getattr(args, "format", "text") != "json":   # keep --format json clean for scripts
            print(f"  probing {len(ips)} tailnet device(s)…", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(candidates))) as ex:
            for ip, p, info in ex.map(lambda c: (c[0], c[1], _probe_hive(c[0], c[1], timeout=3)), candidates):
                if info and info["hive_id"] not in found:
                    found[info["hive_id"]] = {
                        "hive_id": info["hive_id"], "owner_id": info.get("owner_id"),
                        "label": info.get("label"), "node_count": info.get("node_count"),
                        "ip": ip, "port": p}
    hives = list(found.values())
    if getattr(args, "format", "text") == "json":
        print(json.dumps(hives))
        return
    if not hives:
        print(f"No hives found on this tailnet (probed {len(ips)} device(s) on :{port}).")
        return
    print(f"Hives on this tailnet ({len(hives)}):")
    local = _local_hive_id()
    for h in hives:
        mine = "  (this hive)" if h["hive_id"] == local else ""
        print(f"  {h['label'] or '?'} — hive {h['hive_id']}, owner {h['owner_id']}, "
              f"{h['node_count']} node(s), at {h['ip']}:{h['port']}{mine}")


def join_cmd(args):
    """Request to join this device's hive: emit a self-signed join-request the owner can admit.
    Non-blocking — you're already syncing the hive; your writes simply do not count toward
    confidence until the owner admits you. The request is device-signed (not owner-signed), so it
    carries no authority — it's only a visible, pending ask."""
    if _ensure_device_key():
        print(f"Minted this device's key first (device_id: {NODE_ID}) — needed to join and receive capsules.")
    entries = merkle.read_all_entries(JOURNAL_DIR)
    gov = _governance_state(entries)
    if not gov["owner_id"]:
        print("No owner is established in this hive yet (have you synced it?). Nothing to join.")
        return
    if NODE_ID in gov["admitted"]:
        print(f"This device ({NODE_ID}) is already admitted.")
        return
    # Idempotent: don't pile up duplicate join-requests (journal hygiene, and it denies an
    # attacker the ability to churn fresh payloads pre-admission). A DENIED device is excluded
    # from _pending_admissions, so it can still re-ask after a denial.
    if any(r["device_id"] == NODE_ID for r in _pending_admissions(entries, gov)):
        print(f"Join request for {NODE_ID} is already pending — ask the owner to `hive-mind group admit {NODE_ID}`.")
        return
    payload = {"action": "join-request", "device_id": NODE_ID, "label": _wire_label(NODE_LABEL)}
    if args.principal:
        payload["requested_principal"] = args.principal
    _url = _self_sync_url()                  # advertise where we're reachable so the owner can peer back
    if _url:
        payload["url"] = _url
    append_journal("governance", payload)   # device-signed by append_journal; NOT owner-signed
    rebuild_db()
    print(f"Join request sent for {NODE_ID}. Ask the hive owner to admit you:")
    print(f"  hive-mind group admit {NODE_ID}" + (f" --principal {args.principal}" if args.principal else ""))


