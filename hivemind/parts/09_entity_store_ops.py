def _entity_facts(conn, entity_id, hide_forgotten):
    rows = conn.execute("""
        SELECT f.id, f.content, ef.confidence AS link_confidence, f.confidence AS fact_confidence
        FROM entity_facts ef JOIN facts f ON f.id = ef.fact_id
        WHERE ef.entity_id = ? ORDER BY ef.confidence DESC
    """, (entity_id,)).fetchall()
    if hide_forgotten:
        rows = [r for r in rows if r["fact_confidence"] > FORGET_FLOOR]
    sids = _ids_for(conn, "fact", [r["id"] for r in rows]) if rows else {}
    return [{"id": r["id"], "sid": (sids.get(r["id"]) or {}).get("sid"), "content": r["content"],
             "confidence": r["link_confidence"]} for r in rows]


def entity_view(conn, name, joins=True, hide_forgotten=False, entity_id=None):
    """One entity and its linked facts, and (2.1, #208) with `joins` each `x-<module>:` entity a core `same-as`
    joins to it, under its own name with the join's ref (`node_id:seq`) and signer and that entity's own facts.
    Only a join `_same_as_live` counts is listed, so a withdrawn or module-written one is absent on every node.
    None when there is no such entity. `entity_id` (a local row id, from `_pick_entity`) names one entity when several
    share `name`; by name alone the view is the first of them, by identity."""
    if entity_id is not None:
        row = conn.execute("SELECT id, name, type, attributes, first_seen, last_updated FROM entities WHERE id = ?",
                           (entity_id,)).fetchone()
    else:
        row = conn.execute("SELECT id, name, type, attributes, first_seen, last_updated FROM entities WHERE name = ? "
                           "ORDER BY id LIMIT 1", (name,)).fetchone()
    if not row:
        return None
    view = {"id": row["id"], "name": row["name"], "type": row["type"], "attributes": row["attributes"],
            "first_seen": row["first_seen"], "last_updated": row["last_updated"],
            "facts": _entity_facts(conn, row["id"], hide_forgotten), "joined": []}
    if not joins:
        return view
    entries = merkle.read_all_entries(JOURNAL_DIR)
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    for ref in sorted(_same_as_live(entries, _governance_state(entries), by_ref)):
        p = by_ref[ref]["payload"]
        src, dst = _index_row(conn, p.get("from_ref")), _index_row(conn, p.get("to_ref"))
        if not src or not dst or src[0] != "entity" or dst != ("entity", row["id"]):
            continue
        if not conn.execute("SELECT 1 FROM links WHERE kind = 'same-as' AND from_id = ? AND to_id = ? AND signer = ?",
                            (src[1], row["id"], str(ref[0]))).fetchone():
            continue
        other = conn.execute("SELECT name, type, attributes FROM entities WHERE id = ?", (src[1],)).fetchone()
        view["joined"].append({"name": other["name"], "type": other["type"], "attributes": other["attributes"],
                               "ref": f"{ref[0]}:{ref[1]}", "signer": ref[0],
                               "facts": _entity_facts(conn, src[1], hide_forgotten)})
    view["joined"].sort(key=lambda j: (j["name"], j["ref"]))
    return view


def _print_entity_facts(facts, indent):
    print(f"{indent}Linked facts ({len(facts)}):")
    for lf in facts:
        print(f"{indent}  [{lf['sid']} · {lf['id']}] {lf['content'][:60]} (conf={lf['confidence']:.2f})")


def _shared_entity_names(conn):
    """The names more than one entity holds (3.0, §4.2). A unique name is shown bare, a repeated one with its id."""
    return {r[0] for r in conn.execute("SELECT name FROM entities GROUP BY name HAVING count(*) > 1")}


def _entity_identity_check(conn, entries):
    """`hv doctor`'s `entity-identity` check (3.0, §4.4). Fails when the store is not at the current schema, or an
    entity has no identity ref, or one legacy name group (the entries that carry neither `identity_ref` nor
    `new_identity`) maps to more than one entity: the split must change nothing for a hive that never created a
    second same-named entity. Otherwise `ok: N entities, M names shared by more than one`."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    have = row[0] if row else None
    if have != STORE_SCHEMA_VERSION:
        return {"name": "entity-identity", "status": "fail",
                "detail": f"the store is at schema {have or 'none'}, 3.0 reads {STORE_SCHEMA_VERSION}: run `hv doctor rebuild`"}
    n = conn.execute("SELECT count(*) FROM entities").fetchone()[0]
    bare = conn.execute("SELECT count(*) FROM entities WHERE ref_node IS NULL OR ref_seq IS NULL").fetchone()[0]
    if bare:
        return {"name": "entity-identity", "status": "fail",
                "detail": f"{bare} of {n} entities have no identity ref: run `hv doctor rebuild`"}
    groups = {}
    for e in _projection_entries(entries):
        if e.get("type") != "entity" or _entity_form(e)[0] != "legacy":
            continue
        r = conn.execute("SELECT local_id FROM journal_index WHERE kind = 'entity' AND node_id = ? AND seq = ?",
                         (e.get("node_id"), e.get("seq"))).fetchone()
        if r is not None:
            groups.setdefault(e["payload"]["name"], set()).add(r[0])
    split = sorted(name for name, ids in groups.items() if len(ids) > 1)
    if split:
        return {"name": "entity-identity", "status": "fail",
                "detail": f"{len(split)} legacy name group(s) map to more than one entity ({', '.join(split[:3])}): "
                          f"run `hv doctor rebuild`"}
    shared = len(_shared_entity_names(conn))
    return {"name": "entity-identity", "status": "ok",
            "detail": f"{n} entit{'y' if n == 1 else 'ies'}, {shared} name{'' if shared == 1 else 's'} shared by more than one"}


def api_entities():
    """Dashboard Entities panel: every entity with its `h:` id, and `label`, which carries the id suffix only for
    a name more than one entity holds (the CLI's `_entity_label`)."""
    conn = get_conn()
    try:
        shared = _shared_entity_names(conn)
        rows = conn.execute("SELECT e.id, e.name, e.type, e.ref_node, e.ref_seq, "
                            "(SELECT count(*) FROM entity_facts f WHERE f.entity_id = e.id) AS facts "
                            "FROM entities e ORDER BY e.name, e.ref_node, e.ref_seq").fetchall()
        return {"entities": [{"id": r["id"], "name": r["name"], "type": r["type"], "label": _entity_label(r, shared),
                              "shared": r["name"] in shared, "ref": _ref_str([r["ref_node"], r["ref_seq"]]),
                              "sid": _short_id(r["ref_node"], r["ref_seq"]), "facts": r["facts"]} for r in rows],
                "shared_names": len(shared)}
    finally:
        conn.close()


def _entity_label(row, shared):
    """`David` for a unique name, `David · h:1f3a…` (the entity's `h:` id, which `--entity` takes) for a repeated one."""
    return f"{row['name']} · {_short_id(row['ref_node'], row['ref_seq'])}" if row["name"] in shared else row["name"]


def _entity_row_by_token(conn, token):
    """The entity an `h:` id or `node_id:seq` names: the entity that entry was written for, whether it created it or
    updated it. ValueError when it names nothing, or something that is not an entity."""
    kind, ref = _parse_ref_arg(conn, token)
    if kind != "entity":
        raise KindMismatch(f"{token!r} is a {kind}, not an entity")
    return conn.execute("SELECT e.* FROM journal_index j JOIN entities e ON e.id = j.local_id "
                        "WHERE j.kind = 'entity' AND j.node_id = ? AND j.seq = ?", ref).fetchone()


def _pick_entity(conn, name, token, action, flag="--entity"):
    """The one entity a command names (3.0, §4.2). `token` (an `h:` id or `node_id:seq`) always names one. A bare `name`
    names one when exactly one entity holds it; with none, None; with more than one it is an error that lists them,
    exit 1, and writes nothing. A `token` and a `name` that disagree are an error too."""
    if token:
        try:
            row = _entity_row_by_token(conn, token)
        except ValueError as e:
            print(f"entity {action}: {flag}: {e}", file=sys.stderr)
            sys.exit(1)
        if row is None:
            print(f"entity {action}: {flag}: {token!r} names no entity in this node's store", file=sys.stderr)
            sys.exit(1)
        if name and row["name"] != name:
            print(f"entity {action}: {flag} {token} is '{row['name']}', not '{name}'", file=sys.stderr)
            sys.exit(1)
        return row
    rows = conn.execute("SELECT * FROM entities WHERE name = ? ORDER BY ref_node, ref_seq", (name,)).fetchall()
    if len(rows) > 1:
        print(f"entity {action}: '{name}' names {len(rows)} entities; pick one with {flag}:", file=sys.stderr)
        for r in rows:
            print(f"  {_short_id(r['ref_node'], r['ref_seq'])}  {r['name']} ({r['type']})  "
                  f"ref {r['ref_node']}:{r['ref_seq']}  since {r['first_seen']}", file=sys.stderr)
        sys.exit(1)
    return rows[0] if rows else None


def _entity_ref_of(row):
    return [row["ref_node"], row["ref_seq"]]


def _join_ids(conn, p):
    """(from entity id, to entity id) of a `same-as` payload, or None when an end is not a projected entity."""
    src, dst = _index_row(conn, p.get("from_ref")), _index_row(conn, p.get("to_ref"))
    return (src[1], dst[1]) if src and dst and src[0] == dst[0] == "entity" else None


def _entity_join(conn, args, withdraw):
    """`entity join|unjoin --name x-<module>:<n> --to <n>`: write a core `same-as` (2.1, #208), or withdraw it:
    plain `unjoin` withdraws every live join this device wrote, `--owner` every live join (the owner's withdrawal,
    on the control plane). Either end is named by its name, or by `--entity` / `--to-entity` (an `h:` id or ref),
    which is the only way to name one of several entities that share a name (3.0)."""
    to_name, entity_tok, to_tok = getattr(args, "to", None), getattr(args, "entity", None), getattr(args, "to_entity", None)
    if not (args.name or entity_tok) or not (to_name or to_tok):
        print(f"entity {args.action}: --name or --entity (the `x-<module>:` entity) and --to or --to-entity "
              f"(the unprefixed one) are required", file=sys.stderr)
        sys.exit(1)
    rows = []
    for n, tok, flag in ((args.name, entity_tok, "--entity"), (to_name, to_tok, "--to-entity")):
        row = _pick_entity(conn, n, tok, args.action, flag=flag)
        if row is None:
            print(f"entity {args.action}: no entity named '{n}'", file=sys.stderr)
            sys.exit(1)
        rows.append(row)
    refs = [_entity_ref_of(r) for r in rows]
    frm, to = rows[0]["name"], rows[1]["name"]
    entries = merkle.read_all_entries(JOURNAL_DIR)
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    if _same_as_pair({"from_ref": refs[0], "to_ref": refs[1]}, by_ref) is None:
        print(f"entity {args.action}: the first entity must be an `x-<module>:` entity and the second an unprefixed one",
              file=sys.stderr)
        sys.exit(1)
    shared = _shared_entity_names(conn)
    frm_l, to_l = _entity_label(rows[0], shared), _entity_label(rows[1], shared)
    if not withdraw:
        entry = append_journal("link", _link_payload("same-as", refs[0], refs[1], _write_source(args)))
        print(f"Joined '{frm_l}' to '{to_l}' {_signing_note(entry)}")
        rebuild_db()
        return
    gov = _governance_state(entries)
    ends = (rows[0]["id"], rows[1]["id"])
    live = [r for r in sorted(_same_as_live(entries, gov, by_ref))
            if _same_as_pair(by_ref[r]["payload"], by_ref) is not None and _join_ids(conn, by_ref[r]["payload"]) == ends]
    if not live:
        print(f"entity unjoin: '{frm_l}' is not joined to '{to_l}'", file=sys.stderr)
        sys.exit(1)
    owner = getattr(args, "owner", False)
    if not owner:                                    # a device withdraws only the joins it wrote
        mine = _resolve_node_id()
        live = [r for r in live if r[0] == mine]
        if not live:
            print(f"entity unjoin: this device wrote no live join of '{frm_l}' to '{to_l}'; "
                  f"another device's join is withdrawn by its writer, or by the owner with --owner", file=sys.stderr)
            sys.exit(1)
    for r in live:                                   # one retract per entry: each join is judged on its own
        target = list(r)
        if owner:
            rentry = _owner_forget(target, "withdraw same-as")
            if rentry is None:
                return
        else:
            append_journal("retract", {"retracts_ref": target, "reason": "withdraw same-as",
                                       "source": _write_source(args)})
    rebuild_db()
    refs_ = ", ".join(f"{r[0]}:{r[1]}" for r in live)
    print(f"Withdrew {len(live)} join{'s' if len(live) != 1 else ''} of '{frm_l}' to '{to_l}' ({refs_}); "
          f"it holds only if this device wrote the join, or the owner signed the withdrawal.")


def entity(args):
    """Register or query an entity."""
    action = args.action
    name, token = args.name, getattr(args, "entity", None)
    if action in ("add", "show", "link") and not (name or token):
        print(f"entity {action}: --name or --entity is required", file=sys.stderr)
        sys.exit(1)
    if action == "add":
        try:
            attrs = json.loads(args.attr) if args.attr else {}
        except ValueError:
            print(f"entity add: --attr must be a JSON object, e.g. --attr '{{\"k\": \"v\"}}' (got {args.attr!r})",
                  file=sys.stderr)
            sys.exit(2)
        if not isinstance(attrs, dict):
            print("Error: --attr must be a JSON object", file=sys.stderr)
            sys.exit(2)
        if getattr(args, "new", False) and token:
            print("entity add: --new makes a new entity and --entity updates an existing one; use one", file=sys.stderr)
            sys.exit(2)
        if getattr(args, "new", False) and not name:
            print("entity add: --new needs --name", file=sys.stderr)
            sys.exit(1)
        # 3.0 (§4.2): the write says which entity it is. `--new` creates one even when the name is taken (the two-Davids
        # case); otherwise one entity of that name is updated by its identity, none is created, and several are an error.
        conn = get_conn()
        try:
            row = None if getattr(args, "new", False) else _pick_entity(conn, name, token, "add")
        finally:
            conn.close()
        name = name or row["name"]
        payload = {"name": name, "type": args.type or "unknown", "attributes": attrs}
        if row is not None:
            payload["identity_ref"] = _entity_ref_of(row)
        else:
            payload["new_identity"] = True
        entry = append_journal("entity", payload)
        key = (entry["node_id"], entry["seq"])
        pentries = _projection_entries(merkle.read_all_entries(JOURNAL_DIR))
        declined, weigh_only, identity_of = _entity_resolution(pentries, _governance_state(pentries))
        if key in weigh_only:
            # Weigh-only (#51): the same verdict `rebuild_db` reaches. The entry is journaled (permanent) and stays so.
            print(f"Entity '{name}' was created by another device: this write is journaled but does not replace "
                  f"it. Only its creator, or the owner, rewrites an entity.", file=sys.stderr)
            sys.exit(1)
        if key in declined:
            print(f"Entity '{name}': this write is journaled but the projection does not apply it.", file=sys.stderr)
            sys.exit(1)
        try:
            conn = get_conn()
            with _entity_identities(identity_of):
                res = persist_entity(conn, entry)
            label = _entity_label({"name": name, "ref_node": identity_of[key][0], "ref_seq": identity_of[key][1]},
                                  _shared_entity_names(conn))
            _mark_projected(conn, merkle.read_all_entries(JOURNAL_DIR), [entry])
            conn.commit()
            conn.close()
        except sqlite3.OperationalError as e:            # after the append: never report failure (#70)
            _store_deferred(entry, e, "Entity")
        print(f"Entity #{res['id']}: {label} ({res['type']})")
        return

    if action in ("join", "unjoin"):
        conn = get_conn()
        try:
            _entity_join(conn, args, action == "unjoin")
        finally:
            conn.close()
        return

    if action == "link":
        # Link a fact to this entity: hv entity link --name X --fact-id N
        conn = get_conn()
        erow = _pick_entity(conn, name, token, "link")
        if not erow:
            print(f"No entity named '{name}'")
            conn.close()
            return
        entity_ref = _entity_ref_of(erow)
        label = _entity_label(erow, _shared_entity_names(conn))
        try:
            fact_ref = _resolve_id_arg(conn, args.fact_id, "fact", "--fact-id")
        except ValueError as e:
            conn.close()
            print(f"--fact-id: {e}", file=sys.stderr)
            sys.exit(1)
        # 1.19 PR2b (write-path switch): ONE `entity` link (evidence-class: `_link_entity` writes the
        # entity_facts row regardless of authority) instead of the legacy `entity_fact` entry.
        entry = append_journal("link", _link_payload(
            "entity", entity_ref, fact_ref,
            _write_source(args),   # #114 (D-6)
            data={"confidence": args.confidence if args.confidence is not None else 1.0}))
        try:
            journal = merkle.read_all_entries(JOURNAL_DIR)
            all_entries = _projection_entries(journal)
            resolve_link(conn, entry, _governance_state(all_entries),
                         {(e.get("node_id"), e.get("seq")): e for e in all_entries})
            _mark_projected(conn, journal, [entry])
            conn.commit()
            conn.close()
        except sqlite3.OperationalError as e:            # after the append: never report failure (#70)
            _store_deferred(entry, e, "Link")
        print(f"Linked fact {_short_id(*fact_ref)} → entity '{label}' {_signing_note(entry)}")
        return

    # Read-only actions
    conn = get_conn()
    if action == "list":
        rows = conn.execute(
            "SELECT id, name, type, attributes, first_seen, ref_node, ref_seq FROM entities "
            "ORDER BY name, ref_node, ref_seq"
        ).fetchall()
        if not rows:
            print("No entities registered.")
        shared = _shared_entity_names(conn)
        for r in rows:
            print(f"  [{r['id']}] {_entity_label(r, shared)} ({r['type']})  since {r['first_seen']}")
        conn.close()

    elif action == "show":
        erow = _pick_entity(conn, name, token, "show")
        view = entity_view(conn, erow["name"], joins=not getattr(args, "no_joins", False),
                           entity_id=erow["id"]) if erow else None
        if not view:
            print(f"No entity named '{name}'")
            conn.close()
            return
        print(f"Entity #{view['id']}: {_entity_label(erow, _shared_entity_names(conn))} ({view['type']})")
        print(f"  Attributes: {view['attributes']}")
        print(f"  First seen: {view['first_seen']}  Last updated: {view['last_updated']}")
        if view["facts"]:
            _print_entity_facts(view["facts"], "  ")
        for j in view["joined"]:
            print(f"  Joined: {j['name']} ({j['type']})  same-as {j['ref']}, signed by {j['signer']}")
            print(f"    Attributes: {j['attributes']}")
            if j["facts"]:
                _print_entity_facts(j["facts"], "    ")
        conn.close()


def _rebuild_fresh():
    """Build store.db from the journal into a new file and swap it in, whatever the old file holds (any
    `schema_version`, any table shape). The old file is read by nothing, so a store a newer `hv` wrote, or one
    that is damaged, rebuilds. A crash before the swap leaves the old file as it was."""
    global DB_PATH
    live = DB_PATH
    tmp = live.with_name(live.name + ".rebuild")
    sidecars = ("-wal", "-shm")
    for suffix in ("",) + sidecars:
        tmp.with_name(tmp.name + suffix).unlink(missing_ok=True)
    lock = None
    if live.exists():           # take the live store's write lock for the whole swap: a busy store fails as before
        try:
            lock = sqlite3.connect(live, timeout=_BUSY_TIMEOUT_S, isolation_level=None)
            lock.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as e:
            lock.close()
            if "locked" in str(e) or "busy" in str(e):
                raise
            lock = None
        except sqlite3.DatabaseError:       # not a database at all: nothing to lock, nothing to keep
            lock.close()
            lock = None
    DB_PATH = tmp
    try:
        counts = rebuild_db()
        conn = get_conn()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    except BaseException:
        DB_PATH = live
        if lock:
            lock.close()
        for suffix in ("",) + sidecars:
            tmp.with_name(tmp.name + suffix).unlink(missing_ok=True)
        raise
    DB_PATH = live
    for suffix in sidecars:                      # the old file's log must not be replayed onto the new one
        live.with_name(live.name + suffix).unlink(missing_ok=True)
    os.replace(tmp, live)
    if lock:
        lock.close()
    for suffix in sidecars:
        tmp.with_name(tmp.name + suffix).unlink(missing_ok=True)
    return counts


def rebuild_db(fresh=False):
    """Rebuild SQLite entirely from the journal. Two-pass so cross-row links
    resolve regardless of journal order. Returns a counts dict. `fresh` builds a new file and swaps it in,
    so it needs nothing from the old one (`hv doctor rebuild`)."""
    if fresh:
        return _rebuild_fresh()
    init_db()
    conn = get_conn()
    try:
        counts = _rebuild_in_transaction(conn)
        conn.commit()
        _prune_ended_peers_after_rebuild()
        return counts
    except BaseException:
        conn.rollback()      # the previous projection stays queryable (#206)
        raise
    finally:
        conn.close()


def _rebuild_in_transaction(conn, begun=False):
    """The body of `rebuild_db`: ONE transaction from the first delete to the last insert, and no commit
    inside (#206). Statements run one by one because `executescript` commits."""
    if not begun:
        conn.execute("BEGIN IMMEDIATE")
    # Drop the FTS index + triggers first: deleting every content row through
    # the external-content delete triggers can desync FTS5 ("disk image is
    # malformed"). We recreate and backfill the index after replay instead.
    for stmt in ("DROP TRIGGER IF EXISTS facts_ai", "DROP TRIGGER IF EXISTS facts_ad",
                 "DROP TRIGGER IF EXISTS facts_au", "DROP TABLE IF EXISTS facts_fts",
                 "DELETE FROM entity_facts", "DELETE FROM links", "DELETE FROM ideas", "DELETE FROM facts",
                 "DELETE FROM decisions", "DELETE FROM entities", "DELETE FROM journal_index"):
        conn.execute(stmt)

    journal = merkle.read_all_entries(JOURNAL_DIR)
    _PROJECTION_NOTES.clear()
    # One filter for every pass and reader: an entry of a shaped type with no object payload, a non-string
    # required field or a hostile number projects to nothing, so no later pass sees it (#205). The marker still covers the journal.
    entries = _projection_entries(journal, note=True)
    # Governance is pure over the entries, so it is read before pass 1: an entity write by a module is judged
    # against the module marker and the name's creator (#208).
    gov = _governance_state(entries)
    entity_declined, entity_weigh_only, identity_of = _entity_resolution(entries, gov)
    declined = entity_declined | entity_weigh_only
    # Pass 1: row-producing entries (records journal_index).
    with _entity_identities(identity_of):
        for entry in entries:
            if entry["type"] in _PASS1 and (entry["node_id"], entry["seq"]) not in declined:
                persist_entry(conn, entry)
    # Pass 2: cross-row links. The three legacy mechanisms keep their resolvers forever (append-only
    # journal, nothing is migrated); 1.19 `link` entries go through the one generic resolver.
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    live_joins = _same_as_live(entries, gov, by_ref)
    for entry in entries:
        if entry["type"] == "entity_fact":
            resolve_entity_fact(conn, entry, gov)
        elif entry["type"] == "decision" and (
            entry["payload"].get("supersedes_ref") or entry["payload"].get("supersedes")
        ):
            resolve_supersedes(conn, entry, gov, by_ref)
        elif entry["type"] == "fact" and entry["payload"].get("resolves_ref"):
            resolve_resolves(conn, entry, gov, by_ref)
        elif entry["type"] == "link":
            resolve_link(conn, entry, gov, by_ref, live_joins)

    # Phase A: confidence is a derived projection over the journal — recompute it
    # here so every node converges to identical values over the same journal.
    _recompute_confidence(conn, entries)
    _recompute_decision_outcome(conn, entries)      # 1.19 PR4: decisions.outcome_score (vindication)
    _recompute_idea_confidence(conn, entries)       # 1.20 PR5: ideas.confidence (earned from links only)
    _recompute_importance(conn, entries)            # 1.19 PR6: salience L3 — learned, never asserted
    _recompute_utility(conn, entries)               # 1.19 PR6: what recorded decisions relied on

    _init_fts(conn)  # recreate FTS table + triggers and backfill from facts
    _mark_projected(conn, journal)   # #70: the store now holds exactly this journal

    counts = {
        "entries": len(journal),
        "facts": conn.execute("SELECT count(*) FROM facts").fetchone()[0],
        "decisions": conn.execute("SELECT count(*) FROM decisions").fetchone()[0],
        "entities": conn.execute("SELECT count(*) FROM entities").fetchone()[0],
        "links": conn.execute("SELECT count(*) FROM entity_facts").fetchone()[0],
        "edges": conn.execute("SELECT count(*) FROM links").fetchone()[0],
        "ideas": conn.execute("SELECT count(*) FROM ideas").fetchone()[0],
        "malformed": len(_PROJECTION_NOTES),      # entries or fields projected by default or skipped (#205)
        "skipped_lines": merkle.corrupt_lines(JOURNAL_DIR)[0],   # lines the reader dropped for a bad envelope (SECREV A1)
    }
    return counts


def rebuild(args):
    c = rebuild_db(fresh=True)
    print(f"Rebuilt from {c['entries']} journal entries:")
    print(f"  Facts: {c['facts']}  Decisions: {c['decisions']}  "
          f"Entities: {c['entities']}  Links: {c['links']}  Edges: {c['edges']}")
    if c["skipped_lines"]:
        print(f"  {c['skipped_lines']} journal line(s) with a malformed envelope skipped; `hv doctor` lists the files")
    if c["malformed"]:
        print(f"  {c['malformed']} malformed payload field(s) projected by default or skipped; "
              f"`hv doctor` lists the entries (payload-shape)")


def merkle_cmd(args):
    """Show the Merkle index over the journal (root + per-chunk hashes)."""
    entries = merkle.read_all_entries(JOURNAL_DIR)
    chunks = merkle.chunk_hashes(entries)
    root = merkle.merkle_root(chunks)
    print(f"Entries: {len(entries)}")
    print(f"Chunks:  {len(chunks)} (size {merkle.CHUNK_SIZE})")
    print(f"Root:    {root}")
    for i, h in enumerate(chunks):
        print(f"  chunk {i}: {h}")


def stats(args):
    """Show memory usage stats."""
    conn = get_conn()
    total_facts = conn.execute("SELECT count(*) FROM facts").fetchone()[0]
    # Average + headline count over LIVE facts only. Owner-forgotten facts sit at FORGET_FLOOR
    # (-1.0); counting them would drag the average down as the corpus gets *cleaner* — backwards.
    # This mirrors the audit, which already excludes base <= FORGET_FLOOR.
    live_facts = conn.execute(
        "SELECT count(*) FROM facts WHERE confidence > ?", (FORGET_FLOOR,)).fetchone()[0]
    forgotten_facts = total_facts - live_facts
    decisions = conn.execute("SELECT count(*) FROM decisions").fetchone()[0]
    active_decisions = conn.execute(
        "SELECT count(*) FROM decisions WHERE superseded_by IS NULL"
    ).fetchone()[0]
    entities = conn.execute("SELECT count(*) FROM entities").fetchone()[0]
    links = conn.execute("SELECT count(*) FROM entity_facts").fetchone()[0]
    try:
        ideas_n = conn.execute("SELECT count(*) FROM ideas").fetchone()[0]
        ideas_earned = conn.execute("SELECT count(*) FROM ideas WHERE confidence > 0").fetchone()[0]
    except sqlite3.OperationalError:
        ideas_n = ideas_earned = 0
    avg_conf = conn.execute(
        "SELECT round(avg(confidence), 2) FROM facts WHERE confidence > ?", (FORGET_FLOOR,)).fetchone()[0] or 0
    top_tags = conn.execute("""
        SELECT tags, count(*) as cnt FROM facts WHERE tags IS NOT NULL
        GROUP BY tags ORDER BY cnt DESC LIMIT 5
    """).fetchall()
    conn.close()

    entries = merkle.read_all_entries(JOURNAL_DIR)
    by_node = {}
    for e in entries:
        by_node[e["node_id"]] = by_node.get(e["node_id"], 0) + 1

    print(f"Hive Mind Stats — {HIVE_HOME}")
    _self_addr = _self_address()
    print(f"  Device:             {NODE_ID}" + (f"  @ {_self_addr}" if _self_addr else ""))
    facts_line = f"{live_facts} live  (avg confidence: {avg_conf})"
    if forgotten_facts:
        facts_line += f"  +{forgotten_facts} forgotten"
    print(f"  Facts:              {facts_line}")
    print(f"  Decisions:          {decisions}  ({active_decisions} active)")
    print(f"  Entities:           {entities}  ({links} fact-links)")
    if ideas_n:
        print(f"  Ideas:              {ideas_n}  ({ideas_earned} with earned confidence)")
    print(f"  Journal entries:    {len(entries)}  ({', '.join(f'{k}={v}' for k, v in sorted(by_node.items())) or 'empty'})")
    if top_tags:
        print(f"  Top tag groups:")
        for t in top_tags:
            print(f"    ({t['tags']}) x {t['cnt']}")


def sync_cmd(args):
    """Sync with peers (Phase 2 — implemented in sync_client / hive_sync_daemon)."""
    if args.sync_action == "now":
        import sync_client
        sync_client.sync_now()
    elif args.sync_action == "daemon":
        import hive_sync_daemon
        hive_sync_daemon.run_daemon()
    elif args.sync_action == "auth":
        import sync_common
        cfg_path = sync_common.hive_home() / ".peers.json"
        mode, outbound = getattr(args, "mode", None), getattr(args, "outbound", None)
        if not mode and not outbound:
            for label, var, get in (("read-auth", "HIVE_SYNC_AUTH", sync_common.sync_auth_mode),
                                    ("outbound-auth", "HIVE_SYNC_AUTH_OUTBOUND", sync_common.sync_auth_outbound_mode)):
                env = os.environ.get(var, "").strip().lower()
                src = f"{var} env" if env in ("off", "permissive", "enforce") else ".peers.json (default permissive)"
                print(f"sync {label} mode: {get()}  (from {src})")
            return
        sync_common.update_peers_file({**({"sync_auth": mode} if mode else {}),
                                       **({"sync_auth_outbound": outbound} if outbound else {})})   # #107: outbound
        if mode:
            print(f"sync read-auth mode set to '{mode}' in {cfg_path}.")
            if os.environ.get("HIVE_SYNC_AUTH"):
                print("  note: HIVE_SYNC_AUTH is set in the environment and OVERRIDES this file.")
            print("  restart the daemon to apply:  systemctl --user restart hive-sync")
            if mode == "enforce":
                print("  first confirm every peer reports protocol_version 2 or higher: `hv doctor` (peer-identity), or  "
                      "curl <peer>/hive/info | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"protocol_version\"])'")
        if outbound:
            print(f"sync outbound-auth mode set to '{outbound}' in {cfg_path}; it applies from the next sync round.")
            if os.environ.get("HIVE_SYNC_AUTH_OUTBOUND"):
                print("  note: HIVE_SYNC_AUTH_OUTBOUND is set in the environment and OVERRIDES this file.")
            if outbound == "enforce":
                print("  first confirm every peer answers verified at protocol_version 3: `hv doctor` (peer-identity). "
                      "Under enforce an unverified peer is pulled from but not pushed to.")
    else:
        print("usage: hv sync {now|daemon|auth [off|permissive|enforce] [--outbound off|permissive|enforce]}")


