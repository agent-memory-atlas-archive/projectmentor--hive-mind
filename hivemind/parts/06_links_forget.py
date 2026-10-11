# --------------------------------------------------------------------------
# 1.19: generic `link` entries — one journal type, an open `kind` vocabulary, one pass-2 resolver.
# Payload: {kind, from_ref: [node_id, seq], to_ref: [node_id, seq], data: {...}, source, channel?,
# owner_sig?/owner_pub? (hard links only)}. Links are EVIDENCE, not commands (design §5): a link
# hides/replaces its target only when its authority is `hard`; from any other admitted device it is
# downgraded to weigh-only. Ingest is unchanged — content is gated by admission, not type — and a
# pre-1.19 node lands a `link` and ignores it (converged journals, no version skew).
# --------------------------------------------------------------------------

def _index_row(conn, ref):
    """(kind, local_id) for a journal-identity ref [node_id, seq] via journal_index, or None."""
    if not _valid_ref(ref):
        return None
    r = conn.execute("SELECT kind, local_id FROM journal_index WHERE node_id = ? AND seq = ?",
                     (ref[0], ref[1])).fetchone()
    return (r["kind"], r["local_id"]) if r else None


def _link_authority(entry, target_entry, gov):
    """§5: does this link COMMAND (`hard`) or merely WEIGH (`evidence`)? Hard iff the payload proves
    owner-key possession by the owner AS OF this position — `_is_authorized_writer` under the `owner`
    policy, the very check capsules (1.16) and cells (1.17) use; a device key is never the owner key —
    or the (verified) signer is the target entry's author (self-correction is always allowed; device-
    level, like `retract`). Pre-owner or crypto-less, the owner branch cannot apply, so only the author
    rule grants hard — in a one-device bootstrap hive that is every link. Pure over (entry, target, gov):
    every node reaches the same verdict."""
    signer = entry.get("node_id") if "sig" in entry else None
    if gov.get("owner_id") and _ed25519 is not None:
        pos = (entry.get("timestamp", ""), str(entry.get("node_id", "")), entry.get("seq", 0))
        if _is_authorized_writer(signer, pos, entry.get("payload", {}) or {}, gov, "owner"):
            return "hard"
    elif not gov.get("owner_id") and signer is None:
        # 1.19 PR2b: PRE-OWNER grandfathering, mirroring `_verify_entry` (which accepts unsigned entries
        # from a key-less node). Before governance exists there is no admission and no authority to
        # protect, and the legacy verbs these links replace never needed a signature — so the author
        # rule reads the unsigned entry's node_id. Once an owner exists an unsigned link stays evidence.
        signer = entry.get("node_id")
    if target_entry is not None and signer is not None and signer == target_entry.get("node_id"):
        return "hard"
    return "evidence"


def _link_supersedes(conn, from_kind, from_id, to_kind, to_id, p, authority):
    """decision → decision, HARD only: the target is replaced (decisions.superseded_by). Downgraded
    (evidence) → nothing here; the edge row records `authority = evidence` for `doctor link-authz`."""
    if authority == "hard" and from_kind == "decision" and to_kind == "decision":
        conn.execute("UPDATE decisions SET superseded_by = ? WHERE id = ?", (from_id, to_id))


def _link_resolves(conn, from_kind, from_id, to_kind, to_id, p, authority):
    """fact → fact, HARD only: provenance on the SOURCE row (facts.resolves = target), exactly what
    `--resolves` writes today. The retract-equivalent confidence effect on the target is folded by
    `_content_evidence` for hard AND downgraded links alike (a downgrade weighs; it just can't command)."""
    if authority == "hard" and from_kind == "fact" and to_kind == "fact":
        conn.execute("UPDATE facts SET resolves = ? WHERE id = ?", (to_id, from_id))


def _link_data_number(p, key, default):
    """`data[key]` of a link payload when it is a finite number, else `default`: pass 2 never binds or
    computes on a value of the wrong shape (#205)."""
    data = p.get("data")
    v = data.get(key) if isinstance(data, dict) else None
    return v if _is_number(v) else default


def _link_entity(conn, from_kind, from_id, to_kind, to_id, p, authority):
    """entity → fact: an entity_facts row (data.confidence, default 1.0). Evidence-class: never hides."""
    if from_kind == "entity" and to_kind == "fact":
        conn.execute("INSERT OR REPLACE INTO entity_facts (entity_id, fact_id, confidence) VALUES (?, ?, ?)",
                     (from_id, to_id, _link_data_number(p, "confidence", 1.0)))


# kind -> command handler (None = edge row only). supports/contradicts move confidence in
# `_content_evidence`; informed/outcome-of are projected by their own passes (contract 1.19 PR3/PR4).
# extends (1.22, #115) is an edge row and nothing else: "builds on", never evidence on any channel.
_LINK_RESOLVERS = {
    "supersedes": _link_supersedes,
    "resolves": _link_resolves,
    "entity": _link_entity,
    "supports": None,
    "contradicts": None,
    "informed": None,
    "outcome-of": None,
    "extends": None,
    "same-as": None,     # 2.1 (#208): a core join, `x-<module>:` entity → unprefixed entity; `_same_as_live` decides which count
}


def _link_payload(kind, from_ref, to_ref, source, data=None, channel=None):
    """The ONE builder for every `link` the CLI writes (1.19 PR2b; #114: all eight kinds, `outcome-of`
    and `informed` included). On the data plane every link is DEVICE-signed by `append_journal`, whatever
    its source (2.0 S2): `hard` only where this device authored the target, `evidence` elsewhere.

    Owner authority over a link is an explicit act (decision h:34cc1dbcd3): the same verb run through
    `hive-mind remember|decide|entity` owner-signs the link when the source is `manual` (#114, D-5),
    which the control plane does by wrapping this builder. Never dual-emitted: the verb writes this link
    INSTEAD of its legacy field/entry."""
    lp = {"kind": kind, "from_ref": list(from_ref), "to_ref": list(to_ref), "data": dict(data or {}),
          "source": source}
    if channel:
        lp["channel"] = channel
    return lp


def _signing_note(link_entry):
    """#114: say on the confirmation line how a link was signed and why, so an agent that forgot its
    --source (and so wrote as `manual`, with owner authority) sees it at once."""
    p = (link_entry or {}).get("payload") or {}
    return (f"(owner-signed: source {p.get('source')})" if p.get("owner_sig")
            else f"(device-signed: source {p.get('source')})")


def _same_as_pair(p, by_ref):
    """(from_name, to_name) of a `same-as` payload when it has the join's shape: `from_ref` an `x-<module>:`
    entity entry, `to_ref` an unprefixed entity entry. None otherwise (such a link is never a join)."""
    ends = []
    for k in ("from_ref", "to_ref"):
        ref = p.get(k)
        e = by_ref.get(tuple(ref)) if _valid_ref(ref) else None
        ends.append(_entity_name(e) if e is not None and e.get("type") == "entity" else None)
    frm, to = ends
    if frm is None or to is None or vocabulary.split_module_name(frm) is None or vocabulary.split_module_name(to) is not None:
        return None
    return frm, to


def _same_as_live(entries, gov, by_ref=None):
    """2.1 (#208): the `same-as` link entries that are a join now, as a set of (node_id, seq).

    A join is written by a non-module device or the owner (a module's `same-as` never counts) and withdrawn by a
    `retract` whose `retracts_ref` names the `same-as` entry. Joins and withdrawals are judged together, in governance order `(timestamp, node_id, seq)`: a join stands until a later withdrawal of THAT entry,
    and a later `same-as` re-joins. Honoured acts: a `same-as` by a non-module device; a withdrawal of an honoured
    join signed by that `same-as` entry's node_id; a withdrawal the owner signed as of its position (`_owner_at`,
    the forget rule). Pure over (entries, gov): every node reaches the same set. A withdrawal is not fact evidence: `_content_evidence`
    reads only retracts of facts."""
    if by_ref is None:
        by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    modules = gov.get("modules") or {}
    timeline = gov.get("owner_timeline") or []
    joins = {}                                 # ref -> pos, every honoured `same-as` join
    withdrawals = []                           # (pos, target_ref) of every honoured withdrawal
    for e in entries:
        t, p = e.get("type"), e.get("payload") or {}
        if "sig" in e and not _verify_entry(e):
            continue
        pos = (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0))
        ref = (e.get("node_id"), e.get("seq"))
        if t == "link" and p.get("kind") == "same-as":
            if _same_as_pair(p, by_ref) is not None and e.get("node_id") not in modules:
                joins[ref] = pos
        elif t == "retract" and _valid_ref(p.get("retracts_ref")):
            target = by_ref.get(tuple(p["retracts_ref"]))
            if target is None or target.get("type") != "link" or (target.get("payload") or {}).get("kind") != "same-as":
                continue
            owner = False
            if "owner_sig" in p:
                oid = _verify_governance(p)
                owner = _owner_signed_at(oid, pos, gov)
            if e.get("node_id") == target.get("node_id") or owner:
                withdrawals.append((pos, tuple(p["retracts_ref"])))
    # Each join stands until a withdrawal that follows it names it: a withdrawal of a `same-as` that was never an
    # honoured join does nothing, and one join's withdrawal never removes another writer's join of the same pair.
    live = set(joins)
    for wpos, target in withdrawals:
        if target in joins and wpos > joins[target]:
            live.discard(target)
    return live


def _module_of(gov, entry):
    return (gov.get("modules") or {}).get(entry.get("node_id"))


def _shared_entity_end(conn, module, kind, local_id):
    """True when an end of a module's link is an entity the module may not link to: an unprefixed name, or
    another module's `x-<other>:` name (#208). Its own `x-<module>:` entities, and every non-entity end, are fine."""
    if kind != "entity":
        return False
    row = conn.execute("SELECT name FROM entities WHERE id = ?", (local_id,)).fetchone()
    split = vocabulary.split_module_name(row["name"]) if row else None
    return not (split is not None and split[0] == module)


def resolve_link(conn, entry, gov, by_ref, live_joins=None):
    """Pass 2 (1.19): fold ONE `link` entry. Unknown `kind` → no row, no error. A link whose from_ref or
    to_ref does not resolve through journal_index is skipped deterministically (no dangling edges).
    Known kinds write an edge row in `links` carrying the §5 authority verdict; hard kinds also command
    via their handler. `by_ref` maps (node_id, seq) → entry (for the author rule).

    2.1 (#208): a link a MODULE signed is skipped, with no `links` row and no `entity_facts` row, when either end
    is an entity other than its own `x-<module>:` ones (the core makes that join); and a `same-as` is written
    only when `_same_as_live` counts it (`live_joins`, computed from `by_ref` when not passed)."""
    if "sig" in entry and not _verify_entry(entry):
        return
    p = entry.get("payload", {}) or {}
    kind = p.get("kind")
    if kind not in _LINK_RESOLVERS:
        return
    src, dst = _index_row(conn, p.get("from_ref")), _index_row(conn, p.get("to_ref"))
    if src is None or dst is None:
        return
    (from_kind, from_id), (to_kind, to_id) = src, dst
    module = _module_of(gov, entry)
    if module is not None and (_shared_entity_end(conn, module, from_kind, from_id)
                               or _shared_entity_end(conn, module, to_kind, to_id)):
        return
    if kind == "same-as":
        if live_joins is None:
            live_joins = _same_as_live(list(by_ref.values()), gov, by_ref)
        if (entry.get("node_id"), entry.get("seq")) not in live_joins:
            return
    authority = _link_authority(entry, by_ref.get(tuple(p.get("to_ref"))), gov)
    handler = _LINK_RESOLVERS[kind]
    if handler is not None:
        handler(conn, from_kind, from_id, to_kind, to_id, p, authority)
    conn.execute(
        "INSERT OR REPLACE INTO links (kind, from_kind, from_id, to_kind, to_id, signer, authority, "
        "channel, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (kind, from_kind, from_id, to_kind, to_id, str(entry.get("node_id", "")), authority,
         p.get("channel") if isinstance(p.get("channel"), str) and p.get("channel") else "sense",
         entry.get("timestamp")),
    )


def _forgets_grandfathered(entries, gov):
    """Migration and check only; the projection does not read this (3.0 removed the grandfather arm).
    #122 step 1: owner-source forgets the last 2.x honoured ONLY by the pre-genesis grandfather in
    `_content_evidence` under `forget_writers=legacy` (this answers for that policy whatever the current
    setting), which needed no owner signature there; ingest does not check timestamps, so an admitted device can backdate
    one. Returns (hides, dangling) as 'forget <entry>→<target>' labels. `hides`: the forget is the latest
    honoured owner act on its fact's content, so it is what keeps that fact forgotten now. `dangling`: its
    target is not a fact in the journal, so it hides nothing. Pure over the journal and the same rules as
    `_content_evidence` (point-in-time `_owner_at`, latest honoured act wins); [] before any owner exists."""
    if not gov.get("owner_id"):
        return [], []
    timeline = gov.get("owner_timeline") or []
    seq_content = {(e.get("node_id"), e.get("seq")): (e.get("payload") or {}).get("content")
                   for e in entries if e.get("type") == "fact"
                   and isinstance((e.get("payload") or {}).get("content"), str)}
    acts, dangling = {}, []          # content -> [(pos, is_forget, honored, label if grandfathered)]
    for e in entries:
        if e.get("type") != "retract":
            continue
        p = e.get("payload", {}) or {}
        ref = p.get("retracts_ref")
        unforget = ref is None and p.get("unretracts_ref") is not None
        if unforget:
            ref = p.get("unretracts_ref")
        if not _valid_ref(ref):
            continue
        app, ctx, _inst, _sess = _parse_source(p.get("source", "manual"))
        if not (app in OWNER_APPS or ctx == "owner"):
            continue
        pos = (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0))
        signer = _verify_governance(p) if "owner_sig" in p else None
        at = _owner_at(timeline, pos)
        grandfathered = not unforget and at is None
        honored = _owner_signed_at(signer, pos, gov) or grandfathered
        label = f"forget {e.get('node_id')}:{e.get('seq')}→{ref[0]}:{ref[1]}"
        content = seq_content.get(tuple(ref))
        if content is None:
            if grandfathered:
                dangling.append(label)
            continue
        acts.setdefault(content, []).append((pos, not unforget, honored, label if grandfathered else None))
    hides = []
    for lst in acts.values():
        last = None
        for act in sorted(lst, key=lambda a: a[0]):
            if act[2]:
                last = act
        if last is not None and last[1] and last[3] is not None:
            hides.append(last[3])
    return hides, dangling


def _grandfather_facts(entries, hides):
    """Migration and check only; the projection does not read this. The facts behind
    `_forgets_grandfathered`'s `hides`, one per label, in its order:
    `{"sid", "ref": [node_id, seq], "content"}`. `sid` is the `h:` id, the one form `hive-mind retract
    --owner` and `hive-mind unforget` accept (2.0 refuses local ids), so every list and remedy that names
    these facts names them the same way (4c). Pure over the journal."""
    content_of = {(e.get("node_id"), e.get("seq")): (e.get("payload") or {}).get("content")
                  for e in entries if e.get("type") == "fact"}
    out = []
    for label in hides:                            # 'forget <entry>→<node_id>:<seq>' (the target fact)
        node, seq = label.split("→", 1)[1].rsplit(":", 1)
        out.append({"sid": _short_id(node, int(seq)), "ref": [node, int(seq)],
                    "content": content_of.get((node, int(seq))) or ""})
    return out


def _forget_authz_check(entries, gov):
    """`hv doctor`'s `forget-authz` check, or None when it has nothing to say (no owner yet: nothing is
    grandfathered before genesis). Shared with `hive-mind update`, which ends on it.

    3.0 (plan 3.4): the projection no longer honours an unsigned pre-genesis owner forget, so the check is
    about the MIGRATION SET (`_forget_migration`): the facts the last 2.x still hid by such a forget, which
    3.0 would show until the owner re-issues them. ok iff the set is empty, stated as a list and never as
    silence; fail iff it is not, naming each fact by its `h:` id (the form `retract --owner` and `unforget`
    accept) and `hive-mind migrate forget`. `forget_writers` is not read here: a hive with the key unset or
    `legacy` and nothing dependent passes. The data plane cannot sign, so it only points there."""
    m = _forget_migration(entries, gov)
    if not m["owner"]:
        return None
    n_dangling = (f"; dangling: {len(m['dangling'])} pre-genesis owner forget(s) target nothing in this journal "
                  f"({', '.join(m['dangling'][:10])})" if m["dangling"] else "")
    facts = m["facts"]
    if not facts:
        return {"name": "forget-authz", "status": "ok",
                "detail": f"closed: 0 facts depend on a pre-genesis unsigned forget{n_dangling}"}
    where = ("here (this device keeps an owner key)" if _owner_key_state(gov) in ("held", "present")
             else "on the owner machine")
    sids = [f["sid"] for f in facts]
    more = f" and {len(sids) - 10} more" if len(sids) > 10 else ""
    detail = (f"open: {len(facts)} fact(s) are hidden only by an unsigned pre-genesis owner forget, which an "
              f"admitted device could also have written (#122), and would show again without a migration: "
              f"{', '.join(sids[:10])}{more}. Run `hive-mind migrate forget` {where}: it lists them, and on "
              f"`y` re-signs those forgets so the facts stay hidden. Or decide each: keep it forgotten "
              f"`hive-mind retract <h:id> --owner`, let it back `hive-mind unforget <h:id> --reason …`"
              f"{n_dangling}")
    return {"name": "forget-authz", "status": "fail", "detail": detail, "open": True, "facts": facts}


def _forget_migration(entries, gov):
    """3.0 (plan 3.2, 3.4): what `hive-mind migrate forget` has to re-issue, and what its check reports.

    The MIGRATION SET is the facts the last 2.x projection hides that this one shows: the content whose latest
    honoured owner act, under the 2.x rule, was an unsigned forget positioned before the genesis owner. 2.x
    applied that rule only while `forget_writers` was not `owner` (`_forgets_grandfathered` counts such a
    forget whatever the key says), so on a hive whose key is `owner` the set is empty by construction and the
    migration neither lists nor re-signs forgets 2.x already ignored. A purged device's content is dropped
    first, as the projection drops it (`_purge_unkept`): a forget by a since-purged writer hid nothing.
    The differential against the frozen 2.4 oracle (tests/oracles) proves this equals what 2.4 hid and 3.0
    shows, on every corpus journal.

    Returns {"facts": [{"sid", "ref", "content"}], "hides": [labels, narrowed to the set], "dangling": [...],
    "key": the live `forget_writers`, "owner": bool}. `owner` is False before any owner exists, when nothing
    is grandfathered and the set is empty."""
    if not gov.get("owner_id"):
        return {"facts": [], "hides": [], "dangling": [], "key": None, "owner": False}
    key = (gov.get("config") or {}).get("forget_writers", "legacy")
    kept = _purge_unkept(entries, gov)
    hides, dangling = _forgets_grandfathered(kept, gov)
    shown = hides if key != "owner" else []
    return {"facts": _grandfather_facts(kept, shown), "hides": shown, "dangling": dangling,
            "key": key, "owner": True}


def _forget_migration_lines(m):
    """The explicit positive-check text: an empty set is printed as a list, never as silence."""
    n = len(m["facts"])
    out = [f"closed: {n} facts depend on a pre-genesis unsigned forget" if not n else
           f"open: {n} fact(s) depend on a pre-genesis unsigned forget and would show again without a "
           f"migration:"]
    for f in m["facts"]:
        text = " ".join(f["content"].split())
        out.append(f"  {f['sid']}  {text[:100]}" + ("…" if len(text) > 100 else ""))
    if m["dangling"]:
        out.append(f"dangling: {len(m['dangling'])} pre-genesis owner forget(s) target nothing in this journal "
                   f"(not re-issued): {', '.join(m['dangling'][:10])}")
    return out


def _forget_migration_open_count():
    """How many facts the migration would re-issue, for the node-local notices; 0 when none, unknown or on
    any error. Cached against the journal files' (name, size, mtime) so a read verb does not re-project the
    journal each time. Never raises."""
    try:
        fp = [(f.name, f.stat().st_size, f.stat().st_mtime_ns) for f in sorted(JOURNAL_DIR.glob("*.jsonl"))]
        cache = HIVE_HOME / ".nudge_state" / "forget-migration.json"
        try:
            c = json.loads(cache.read_text())
            if c.get("fp") == json.loads(json.dumps(fp)):
                return int(c.get("n", 0))
        except Exception:
            pass
        entries = merkle.read_all_entries(JOURNAL_DIR)
        n = len(_forget_migration(entries, _governance_state(entries))["facts"])
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"fp": fp, "n": n}))
        return n
    except Exception:
        return 0


def _forget_migration_stderr_notice():
    """The read verbs' node-local notice (stderr, so stdout stays machine-readable). Never raises."""
    try:
        line = _forget_migration_notice()
        if line:
            print(line, file=sys.stderr)
    except Exception:
        pass


def _forget_migration_notice():
    """One line for `hv search` / `hv feed` (stderr) and the session-start nudge, or ''. Silent unless a
    migration is owed."""
    n = _forget_migration_open_count()
    if not n:
        return ""
    return (f"[hive] NOTICE: {n} forgotten fact(s) depend on an unsigned pre-genesis forget that release 3.0 "
            f"no longer honours, so 3.0 would show them again. On the owner machine run: "
            f"hive-mind migrate forget  (hive-mind migrate forget --check lists them)")


def _links_unauthorized(entries, gov):
    """`supersedes`/`resolves` links the projection DOWNGRADED to evidence (signer neither the owner-at-
    position nor the target's author) — surfaced by `hv doctor` (`link-authz`) so the owner can ratify
    by re-issuing the link owner-signed. Pure over the journal. Returns ['supersedes a:1→b:2 by k1:…']."""
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    out = []
    for e in entries:
        if e.get("type") in ("decision", "fact"):
            # #204: a pre-1.19 payload field is read as a link from the entry to its target, under the same
            # rule. Only the journal-identity forms can be judged from the journal alone: a legacy local id
            # (`supersedes`) names a row, not an entry, and projects only where that row's author is known.
            lp = e.get("payload", {}) or {}
            field, tkind = (("supersedes_ref", "decision") if e["type"] == "decision" else ("resolves_ref", "fact"))
            lref, lkind = lp.get(field), "supersedes" if e["type"] == "decision" else "resolves"
            tgt = by_ref.get(tuple(lref)) if _valid_ref(lref) else None
            if tgt is not None and tgt.get("type") == tkind and not ("sig" in e and not _verify_entry(e)) \
                    and _link_authority(e, tgt, gov) == "evidence":
                out.append(f"{lkind} (legacy {field}) {e.get('node_id', '?')}:{e.get('seq', '?')}"
                           f"→{lref[0]}:{lref[1]} by {e.get('node_id', '?')}")
            continue
        if e.get("type") != "link" or ("sig" in e and not _verify_entry(e)):
            continue
        p = e.get("payload", {}) or {}
        if p.get("kind") not in ("supersedes", "resolves"):
            continue
        to_ref = p.get("to_ref") if _valid_ref(p.get("to_ref")) else None
        if to_ref is None:
            continue
        if _link_authority(e, by_ref.get(tuple(to_ref)), gov) == "evidence":
            fr = p.get("from_ref") if _valid_ref(p.get("from_ref")) else ["?", "?"]
            out.append(f"{p['kind']} {fr[0]}:{fr[1]}→{to_ref[0]}:{to_ref[1]} by {e.get('node_id', '?')}")
    return out


def _index_lookup(conn, kind, local_id):
    """Reverse map: local row id -> its journal identity [node_id, seq]. An entity's is the ref of its creating
    entry, which the row holds (3.0): the lowest entry mapped to it would move when an update from a lower node_id
    arrives."""
    if kind == "entity":
        e = conn.execute("SELECT ref_node, ref_seq FROM entities WHERE id = ?", (local_id,)).fetchone()
        if e is not None and e["ref_node"] is not None:
            return [e["ref_node"], e["ref_seq"]]
    r = conn.execute(
        "SELECT node_id, seq FROM journal_index WHERE kind = ? AND local_id = ? ORDER BY node_id, seq LIMIT 1",
        (kind, local_id),
    ).fetchone()
    return [r["node_id"], r["seq"]] if r else None


# 1.19 PR3: identity references at the CLI/MCP boundary. The STABLE forms are the short id `h:` + 10 hex
# and the journal identity written `node_id:seq` (e.g. `k1:597b3e0f5fb92d37:401`): neither changes across
# rebuilds or nodes, and `hv search --format json` returns both (`sid`, `ref`). Bare local ids (`118`,
# `d17`, `i5`) are SQLite rowids reassigned on every rebuild (after every write and sync), so an id read
# before a sync could name a different row by the time it was used. 1.x accepted them with a warning; 2.0
# REJECTS them (#59, #64; promised in contract §7), and every caller aborts before anything is journaled.
# Journal READS are unaffected: entries written with the older identity forms still resolve, through the
# legacy resolvers.
_SID_RE = re.compile(r"^h:[0-9a-f]{10}$")
_LOCAL_ID_RE = re.compile(r"^[di]?\d+$")


class KindMismatch(ValueError):
    """A reference that resolves, but to the wrong kind (a decision where a fact is required)."""


class LocalIdRejected(ValueError):
    """A bare or kind-prefixed local id (`118`, `d17`, `i5`), which 2.0 no longer accepts (#59, #64). A
    ValueError, so every caller's existing `<option>: <message>`, exit 1 path reports it; `--resolves`,
    which downgrades an unresolvable target to a warning, aborts on this one instead."""


def _ref_str(ref):
    """`[node_id, seq]` -> `node_id:seq` (the form agents should carry around)."""
    return f"{ref[0]}:{ref[1]}" if ref else None


def _write_source(args):
    """A write's source: `--source`, else `manual` (a person). 2.0 dropped the $HERMES_AGENT fallback (#119),
    so no write can arrive labelled with an identity it did not pass. One definition, because the control
    plane decides from it whether a link will be owner-signed (only `manual` is)."""
    return getattr(args, "source", None) or "manual"


def _parse_ref_arg(conn, token, default_kind="fact"):
    """Resolve one CLI/MCP identity token to (kind, [node_id, seq]) or raise ValueError.
    Accepts the short id `h:` + 10 hex (1.19 PR3b; exact lookup on journal_index.sid — the preferred
    form) or `node_id:seq` (stable; must exist in journal_index). A local id (`118`, `d17`, `i5`) raises
    `LocalIdRejected` (2.0, #59/#64)."""
    t = str(token).strip()
    if not t:
        raise ValueError("empty reference")
    if t.startswith("h:"):
        # 1.19 PR3b: the short stable id — an EXACT equality lookup on the projection-written column.
        if not _SID_RE.match(t):
            raise ValueError(f"{t!r} is not a short id (`h:` + 10 hex chars, as shown by `hv search`)")
        r = conn.execute("SELECT kind, node_id, seq FROM journal_index WHERE sid = ?", (t,)).fetchone()
        if r is None:
            raise ValueError(f"{t!r} does not resolve to any fact/decision/idea in this node's index")
        return r["kind"], [r["node_id"], r["seq"]]
    if ":" in t and not t.isdigit():
        node_id, _, seq = t.rpartition(":")
        if not node_id or not seq.isdigit():
            raise ValueError(f"{t!r} is not a `node_id:seq` reference")
        row = _index_row(conn, [node_id, int(seq)])
        if row is None:
            raise ValueError(f"{t!r} does not resolve to any fact/decision/idea in this node's index")
        return row[0], [node_id, int(seq)]
    if _LOCAL_ID_RE.match(t):
        raise LocalIdRejected(f"{t!r} is a local id, which 2.0 no longer accepts: local ids change on every "
                              f"rebuild (#59). Pass the sid (`h:…`) or ref (`node_id:seq`) that `hv search` "
                              f"shows.")
    raise ValueError(f"{t!r}: expected a sid (`h:` + 10 hex, as `hv search` shows) or `node_id:seq`")


def _id_label(token):
    """How a user-supplied identity token reads back in a message: `#4` for a bare rowid, else as given."""
    t = str(token).strip()
    return f"#{t}" if t.isdigit() else t


def _resolve_id_arg(conn, token, kind, what):
    """Resolve a CLI identity token that MUST be of `kind` (fact|decision|idea) to [node_id, seq].
    Accepts `h:<sid>` or `node_id:seq`; a local id raises `LocalIdRejected` (2.0). Raises ValueError on
    any failure — callers abort before writing anything."""
    k, ref = _parse_ref_arg(conn, str(token).strip(), default_kind=kind)
    if k != kind:
        raise KindMismatch(f"{token!r} is a {k}, not a {kind}")
    return ref


def _ids_for(conn, kind, local_ids):
    """{local_id: {'ref': 'node_id:seq', 'sid': 'h:…'}} for rows of `kind` — the stable identities shown
    beside each rowid in output. A corroborated fact maps SEVERAL journal entries to one row; its
    canonical name is the FIRST by (node_id, seq) — the same on every node — while every entry's own
    sid still resolves to the row."""
    ids = [int(i) for i in local_ids if i is not None]
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    out = {}
    for r in conn.execute(f"SELECT local_id, node_id, seq, sid FROM journal_index WHERE kind = ? "
                          f"AND local_id IN ({q}) ORDER BY node_id, seq", (kind, *ids)):
        out.setdefault(r["local_id"], {"ref": f"{r['node_id']}:{r['seq']}",
                                       "sid": r["sid"] or _short_id(r["node_id"], r["seq"])})
    return out


def _supersede_info(conn, decision_ids):
    """#157: {decision rowid: {...}} naming WHO superseded each decision, by stable identity (additive to the
    node-local `superseded_by` rowid, which stays). `superseded_by_sid` / `superseded_by_ref` / `superseded_by_authority`
    are set only when the supersede is IN EFFECT (`decisions.superseded_by`, which only a `hard` link writes);
    `supersede_evidence` lists `supersedes` links recorded as evidence only, which do NOT supersede (`hv doctor`
    link-authz), each `{sid, ref, authority: "evidence"}`. Rows with neither get no entry."""
    ids = [int(i) for i in decision_ids if i is not None]
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    out = {}
    by = {r["id"]: r["superseded_by"] for r in conn.execute(
        f"SELECT id, superseded_by FROM decisions WHERE id IN ({q}) AND superseded_by IS NOT NULL", ids)}
    links = conn.execute(f"SELECT from_id, to_id, authority FROM links WHERE kind = 'supersedes' "
                         f"AND from_kind = 'decision' AND to_kind = 'decision' AND to_id IN ({q}) "
                         f"ORDER BY from_id", ids).fetchall()
    names = _ids_for(conn, "decision", list(by.values()) + [r["from_id"] for r in links])
    for did, sup in by.items():
        n = names.get(sup) or {}
        auth = next((r["authority"] for r in links if r["to_id"] == did and r["from_id"] == sup), "hard")
        out[did] = {"superseded_by_sid": n.get("sid"), "superseded_by_ref": n.get("ref"),
                    "superseded_by_authority": auth, "supersede_evidence": []}
    for r in links:
        if r["authority"] != "evidence" or by.get(r["to_id"]) == r["from_id"]:
            continue
        n = names.get(r["from_id"]) or {}
        e = out.setdefault(r["to_id"], {"superseded_by_sid": None, "superseded_by_ref": None,
                                        "superseded_by_authority": None, "supersede_evidence": []})
        e["supersede_evidence"].append({"sid": n.get("sid"), "ref": n.get("ref"), "authority": "evidence"})
    return out


_NOT_SUPERSEDED = {"superseded_by_sid": None, "superseded_by_ref": None, "superseded_by_authority": None,
                   "supersede_evidence": []}


def _supersede_text(info):
    """The text-output suffix for one decision's `_supersede_info` entry ('' when it has none)."""
    if not info:
        return ""
    ev = ", ".join(e["sid"] or "?" for e in info["supersede_evidence"])
    s = ""
    if info["superseded_by_sid"]:
        s = f"  ⚠ SUPERSEDED by {info['superseded_by_sid']} ({info['superseded_by_authority']})"
    if ev:
        s += f"  (supersede by {ev} is evidence only, not in effect)"
    return s


def _refs_for(conn, kind, local_ids):
    """{local_id: 'node_id:seq'} — see _ids_for."""
    return {k: v["ref"] for k, v in _ids_for(conn, kind, local_ids).items()}


def _sid_of(conn, kind, local_id):
    """The canonical short id of one row (or None)."""
    return (_ids_for(conn, kind, [local_id]).get(local_id) or {}).get("sid")


def _local_ids_for_refs(conn, refs):
    """[{'ref': 'node:seq', 'kind': k, 'id': local_id|None}] for stored refs — local id is THIS node's
    current rowid (rebuild-unstable, display only) and None if the target has not landed here yet."""
    out = []
    for ref in refs or []:
        if not _valid_ref(ref):
            continue                         # a malformed ref is skipped, not shown (#205)
        row = _index_row(conn, ref)
        out.append({"ref": _ref_str(ref), "sid": _short_id(ref[0], ref[1]),
                    "kind": row[0] if row else None, "id": row[1] if row else None})
    return out


