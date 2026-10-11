# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

# Salience L2 — the structural ADMISSION gate. "Salience" names a three-layer subsystem:
#   L1  agent rubric (Hermes hook / Claude Code skill): "should I say this" — structure of
#       the SITUATION (decision+rationale, correction, outcome, constraint, first-hand result)
#   L2  this function: "is this even a statement" — structure of the TEXT only
#   L3  importance: "did it turn out to matter" — a learned projection over the journal (planned)
# L1/L2 decide what ENTERS the journal; L3 exists only for what got in. Layers are sequential,
# never summed. L2 is CONSERVATIVE + CONTENT-NEUTRAL: it rejects clear non-knowledge FORMS
# (trivially short, bare questions, short greetings) and passes everything else — explicit
# writes are intentional. It is NOT a learned/importance classifier (that would reintroduce a
# capturable authority) and holds no state; it may never look at topic, meaning or importance.
# Opt-in via `remember --gate`; the shared core hosts it so every agent gates identically.
_GREETINGS = ("hi ", "hi,", "hi!", "hello", "hey ", "thanks", "thank you",
              "greetings", "good morning", "good afternoon", "good evening", "yo ")


def _is_admissible(content):
    c = (content or "").strip()
    if len(c) < 15:                                   # trivially short → noise
        return False
    if c.endswith("?") and "." not in c:              # a bare question is not a fact
        return False
    cl = c.lower()
    if len(c) < 60 and any(cl.startswith(g) for g in _GREETINGS):  # short pleasantry
        return False
    return True




# Structural markers of a TRANSIENT operational-status claim — a state that will change, so the
# audit should RE-CHECK it (volatile) rather than trust it indefinitely. Deliberately HIGH-PRECISION
# and content-NEUTRAL: it matches the claim FORM (a liveness predicate / freshness marker), never the
# topic. Better to miss a volatile fact than to mislabel a durable one. `is up` excludes "up to date".
_VOLATILE_RE = re.compile(
    r"\b(is|are|stays?|remains?)\s+(currently\s+|now\s+)?"
    r"(running|up(?!\s+to\s+date)|down|online|offline|reachable|unreachable|listening|"
    r"stopped|healthy|unhealthy|degraded|failing|connected|disconnected|available|unavailable)\b"
    r"|\bas of (today|now|\d{4}-\d{2}-\d{2})\b"
    r"|\bport\s+\d+\s+(is\s+)?(open|closed|listening)\b",
    re.IGNORECASE,
)
# NOTE: bare freshness adverbs ("currently", "right now") are deliberately NOT triggers — they
# fire on durable prose ("currently agents don't ...") too. They only count when attached to a
# status above ("is currently down"). High precision: better to miss than to mislabel.


def _detect_volatile(content):
    """True if `content` asserts a transient operational status (see _VOLATILE_RE). Conservative."""
    try:
        return bool(_VOLATILE_RE.search(content or ""))
    except Exception:
        return False


# A fact written as a correction usually names what it contravenes in prose, e.g.
# "resolves #119" / "CORRECTION to fact #275". The audit parses these so it can flag a
# correction whose target is still live (the agent appended but never reconciled).
_REFERENCE_RE = re.compile(r"(?:resolves|supersedes|obsoletes|corrects?|correction to)\s+(?:fact\s+)?(#\d+|h:[0-9a-f]{10})",
                           re.IGNORECASE)


def _parse_fact_references(content):
    """References this content claims to resolve/supersede/obsolete/correct (see _REFERENCE_RE): an int
    for a prose `#N` (a LOCAL id — best-effort, it drifts) or a `h:…` short id string (exact; 1.19 PR3b)."""
    out = []
    try:
        for m in _REFERENCE_RE.findall(content or ""):
            out.append(int(m[1:]) if m.startswith("#") else m.lower())
    except Exception:
        pass
    return out


def remember(args):
    """Store a fact. Confidence is DERIVED from the number of distinct sources that
    asserted identical content (not from repetition) — see _recompute_confidence.
    Transient operational-status claims are auto-tagged `volatile` so the audit re-checks them.
    `--resolves N` links this write to a prior fact it corrects and soft-retracts N (deliberate
    negative evidence, reversible) so the corpus reconciles instead of asserting both at once."""
    if getattr(args, "gate", False) and not _is_admissible(args.content):
        print(f"Skipped (admission gate): {args.content[:60]}")
        return
    tags = args.tags.split(",") if args.tags else []
    tl = [t.strip().lower() for t in tags]
    detected = _detect_volatile(args.content)
    already = "volatile" in tl or any(t.startswith("ttl:") for t in tl)
    opted_out = getattr(args, "no_volatile", False)
    auto_volatile = detected and not already and not opted_out
    if auto_volatile:
        tags.append("volatile")
    elif detected and not already and opted_out:
        tags.append("durable")   # record the opt-out so audit-time detection honors it

    source = _write_source(args)

    # --resolves: resolve the target fact's journal identity + content up front (like
    # `decide --supersedes`). A missing target is a warning, not an error — never lose content.
    resolves_ref = resolved_content = None
    if getattr(args, "resolves", None):
        # 1.19 PR3b: `h:` short id / `node_id:seq`, kind-checked. A WRONG-kind reference aborts (it names
        # something that is not a fact), and so does a local id (2.0, #59): downgrading that to "write
        # without the link" would drop the link the caller asked for. An unresolvable one stays a warning.
        conn0 = get_conn()
        try:
            resolves_ref = _resolve_id_arg(conn0, args.resolves, "fact", "--resolves")
        except ValueError as e:
            conn0.close()
            if isinstance(e, (LocalIdRejected, KindMismatch)):
                print(str(e), file=sys.stderr)
                sys.exit(1)
            print(f"  ⚠ no fact {_id_label(args.resolves)} to resolve — writing the fact without a resolve link")
            resolves_ref = None
            conn0 = get_conn()
        row0 = None
        if resolves_ref is not None:
            rid = _index_row(conn0, resolves_ref)
            row0 = conn0.execute("SELECT content FROM facts WHERE id = ?", (rid[1],)).fetchone() if rid else None
        conn0.close()
        if resolves_ref is not None and row0 is None:
            print(f"  ⚠ no fact {_id_label(args.resolves)} to resolve — writing the fact without a resolve link")
            resolves_ref = None
        elif row0 is not None:
            resolved_content = row0["content"]

    # --outcome-of (1.19 PR4): this fact is an OUTCOME of a decision. Resolve the decision BEFORE any
    # write — a wrong or missing reference aborts (no orphan fact, no dangling link). Stable refs
    # `node_id:seq` are primary; a bare integer or `dN` is a kind-checked local decision id.
    outcome_ref = None
    channel = getattr(args, "channel", None) or None
    if getattr(args, "outcome_of", None):
        tok = str(args.outcome_of).strip()
        if tok.isdigit():
            tok = "d" + tok                                   # an outcome can only be OF a decision
        conn0 = get_conn()
        try:
            okind, outcome_ref = _parse_ref_arg(conn0, tok, default_kind="decision")
        except ValueError as e:
            conn0.close()
            print(f"--outcome-of: {e}", file=sys.stderr)
            sys.exit(1)
        conn0.close()
        if okind != "decision":
            print(f"--outcome-of: {args.outcome_of!r} is a {okind}, not a decision — an outcome is of a decision",
                  file=sys.stderr)
            sys.exit(1)
    polarity = int(getattr(args, "polarity", 1) if getattr(args, "polarity", None) is not None else 1)

    # --supports / --contradicts (1.21, #71): this observation is evidence for or against a FACT or an IDEA.
    # Resolved and kind-checked BEFORE any write: a wrong-kind or unknown reference aborts, nothing written.
    evidence_kind = evidence_ref = evidence_tkind = None
    for flag in ("supports", "contradicts"):
        tok = getattr(args, flag, None)
        if not tok:
            continue
        conn0 = get_conn()
        try:
            tkind, tref = _parse_ref_arg(conn0, tok)
        except ValueError as e:
            conn0.close()
            print(f"--{flag}: {e}", file=sys.stderr)
            sys.exit(1)
        conn0.close()
        if tkind == "decision":
            print(f"--{flag}: {tok!r} is a decision; to report how a decision worked out, use --outcome-of",
                  file=sys.stderr)
            sys.exit(1)
        if tkind not in ("fact", "idea"):
            print(f"--{flag}: {tok!r} is not a fact or idea", file=sys.stderr)
            sys.exit(1)
        evidence_kind, evidence_ref, evidence_tkind = flag, tref, tkind

    # --extends (1.22, #115): this entry BUILDS ON a fact, idea or decision. No evidence semantics — the
    # link is an edge row only, weighed on no channel. Resolved and kind-checked before any write.
    extends_ref = extends_tkind = None
    if getattr(args, "extends", None):
        tok = args.extends
        conn0 = get_conn()
        try:
            extends_tkind, extends_ref = _parse_ref_arg(conn0, tok)
        except ValueError as e:
            conn0.close()
            print(f"--extends: {e}", file=sys.stderr)
            sys.exit(1)
        conn0.close()
        if extends_tkind not in ("fact", "idea", "decision"):
            print(f"--extends: {tok!r} is not a fact, idea or decision", file=sys.stderr)
            sys.exit(1)

    payload = {
        "content": args.content,
        "tags": tags,
        "importance": args.importance,
        "source": source,
    }
    if channel:
        payload["channel"] = channel                          # additive; absent = sense
    entry = append_journal("fact", payload)
    outcome_link = resolves_link = None
    if resolves_ref:
        # 1.19 PR2b (write-path switch): ONE `resolves` link instead of the legacy `resolves_ref` field +
        # `retract` entry. The projection folds it as retract-equivalent negative evidence on the target
        # (hard or downgraded alike) and, when hard, records `facts.resolves` — the same effect as before.
        resolves_link = append_journal("link", _link_payload("resolves", [entry["node_id"], entry["seq"]],
                                                             resolves_ref, source))
    if outcome_ref:
        # Same channel stamped on the fact and the link; the projection reads the LINK's (§4 Shape).
        outcome_link = append_journal("link", _link_payload("outcome-of", [entry["node_id"], entry["seq"]],
                                                            outcome_ref, source, data={"polarity": polarity},
                                                            channel=channel))
    evidence_link = None
    if evidence_ref:
        # Same channel on the fact and the link, as --outcome-of does; the projection reads the LINK's.
        evidence_link = append_journal("link", _link_payload(evidence_kind, [entry["node_id"], entry["seq"]],
                                                             evidence_ref, source, channel=channel))
    extends_link = None
    if extends_ref:
        # The link records the write's channel for readers; the kind is never weighed on any channel.
        extends_link = append_journal("link", _link_payload("extends", [entry["node_id"], entry["seq"]],
                                                            extends_ref, source, channel=channel))

    try:
        conn = get_conn()
        res = persist_fact(conn, entry)

        # Read the journal ONCE after all appends, then reproject confidence per affected content
        # (keeps the live path consistent with rebuild without a full rebuild).
        journal = merkle.read_all_entries(JOURNAL_DIR)
        all_entries = _projection_entries(journal)
        gov = _governance_state(all_entries)
        by_ref = {(e.get("node_id"), e.get("seq")): e for e in all_entries}
        if resolves_link is not None:
            resolve_link(conn, resolves_link, gov, by_ref)
        if outcome_link is not None:
            resolve_link(conn, outcome_link, gov, by_ref)
            _recompute_decision_outcome(conn, all_entries)
        if evidence_link is not None:
            resolve_link(conn, evidence_link, gov, by_ref)
        if extends_link is not None:
            resolve_link(conn, extends_link, gov, by_ref)
        cev = _content_evidence(all_entries, gov)
        ev = cev.get(args.content, {"pos": {}, "neg": {}, "forget": False, "last_ts": ""})
        n = len(ev["pos"])
        conf = _content_confidence(ev, gov)
        _apply_content_confidence(conn, args.content, ev, gov)
        if resolved_content is not None:
            ev2 = cev.get(resolved_content, {"pos": {}, "neg": {}, "forget": False, "last_ts": ""})
            _apply_content_confidence(conn, resolved_content, ev2, gov)
        if evidence_link is not None and evidence_tkind == "fact":       # #71: the target moves now, not at rebuild
            tcontent = ((by_ref.get(tuple(evidence_ref)) or {}).get("payload") or {}).get("content")
            if tcontent is not None and tcontent != args.content:
                ev3 = cev.get(tcontent, {"pos": {}, "neg": {}, "forget": False, "last_ts": ""})
                _apply_content_confidence(conn, tcontent, ev3, gov)
        if evidence_link is not None and evidence_tkind == "idea":
            _recompute_idea_confidence(conn, all_entries)
        _recompute_importance(conn, all_entries)          # 1.19 PR6: the column is learned, never the raw hint
        if outcome_link is not None:
            _recompute_utility(conn, all_entries)         # an outcome changes what the informing facts earned
        _mark_projected(conn, journal, [entry, resolves_link, outcome_link, evidence_link, extends_link])
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:                # after the append: never report failure (#70)
        _store_deferred(entry, e)

    src_word = "identity" if n == 1 else "identities"
    conn = get_conn()
    sid = _sid_of(conn, "fact", res["id"])           # the row's canonical short id (first asserting entry)
    rsid = _short_id(*resolves_ref) if resolves_ref else None
    conn.close()
    if res["inserted"]:
        print(f"Remembered as {sid} (fact #{res['id']}, confidence {conf:.2f}, {n} {src_word})")
    else:
        print(f"Corroborated {sid} (fact #{res['id']}, confidence {conf:.2f}, {n} {src_word})")
    print(f"  ref: {_ref_str([entry['node_id'], entry['seq']])}")
    if resolves_ref:
        print(f"  ↩ resolved fact {rsid} {_signing_note(resolves_link)} (soft retract — reversible; "
              f"`hive-mind retract {rsid} --owner` to forget it decisively)")
    if outcome_ref:
        sign = "+1" if polarity > 0 else ("−1" if polarity < 0 else "0")
        print(f"  ↗ outcome ({sign}) of decision {_ref_str(outcome_ref)} {_signing_note(outcome_link)}"
              + ("" if (channel or "sense") == "sense" else f"  [channel {channel}: not counted toward outcome_score]"))
    if evidence_ref:
        arrow = "↗" if evidence_kind == "supports" else "↘"
        print(f"  {arrow} {evidence_kind} {evidence_tkind} {_short_id(*evidence_ref)} {_signing_note(evidence_link)}")
        author = (by_ref.get(tuple(evidence_ref)) or {}).get("node_id")
        if evidence_tkind == "idea" and evidence_kind == "supports" and _same_principal(gov, entry["node_id"], author):
            print("  ⊘ your own idea: an author's support doesn't count; it earns confidence only from others' "
                  "observations")
    if extends_ref:
        print(f"  ↗ extends {extends_tkind} {_short_id(*extends_ref)} {_signing_note(extends_link)}")
    if channel == "introspect" and not outcome_ref:
        isw_now = float((gov.get("config") or {}).get("introspect_support_weight", CONF_INTROSPECT_SUPPORT_WEIGHT))
        print(f"  ⊘ channel introspect: recorded; counts {isw_now:g}× toward confidence "
              "(introspect_support_weight): reasoning is not observation")
    if auto_volatile:
        print("  ↻ tagged volatile (transient status — the audit will flag it to re-check; "
              "use --no-volatile to opt out)")


def _owner_forget(ref, reason):
    """Placeholder for the owner step of `retract --owner`. On the control plane `hivemind_owner.py`
    replaces it with the step that signs and appends the owner-forget; here it refuses (2.0 S2)."""
    raise NotOnDataPlane("retract --owner")


def retract(args):
    """Record NEGATIVE evidence against a fact (soft-forget). Confidence stays a derived
    projection: a peer retract counts negative (can drive 'rejected'); --owner forgets it
    (governance — to the forget floor, regardless of corroboration). Never a self-set number.
    The journal keeps the fact + the retract (auditable; reversible by re-corroboration)."""
    # 1.19 PR3b (closes hive #58): the target is named by its `h:` short id or `node_id:seq` ref — both
    # stable across the rebuild that follows every write and sync (2.0 refuses local ids, #59).
    # Kind-checked: a decision is an error, never a silent re-target.
    conn = get_conn()
    try:
        ref = _resolve_id_arg(conn, args.fact_id, "fact", "retract")
    except ValueError as e:
        conn.close()
        print(f"retract: {e}", file=sys.stderr)
        sys.exit(1)
    rid = _index_row(conn, ref)
    row = conn.execute("SELECT id, content FROM facts WHERE id = ?", (rid[1],)).fetchone() if rid else None
    sid = _sid_of(conn, "fact", rid[1]) if rid else None
    conn.close()
    if row is None:
        print(f"retract: no fact {args.fact_id}", file=sys.stderr)
        sys.exit(1)
    content = row["content"]
    owner = getattr(args, "owner", False)       # only the control plane's parser defines --owner
    if owner:
        rentry = _owner_forget(ref, args.reason)      # the owner step: control plane only (2.0 S2)
        if rentry is None:
            return
    else:
        source = _write_source(args)
        rentry = append_journal("retract", {"retracts_ref": ref, "reason": args.reason or "", "source": source})

    try:
        conn = get_conn()
        journal = merkle.read_all_entries(JOURNAL_DIR)
        all_entries = _projection_entries(journal)
        gov = _governance_state(all_entries)
        ev = _content_evidence(all_entries, gov).get(
            content, {"pos": {}, "neg": {}, "forget": False, "last_ts": ""})
        conf = _content_confidence(ev, gov)
        _apply_content_confidence(conn, content, ev, gov)
        _mark_projected(conn, journal, [rentry])
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:                # after the append: never report failure (#70)
        _store_deferred(rentry, e, "Retraction")
    kind = "FORGOTTEN (owner)" if owner else "retracted"
    print(f"Fact {sid} (#{row['id']}) {kind} → confidence {conf:.2f}")


def _fts_query(raw):
    """Turn arbitrary user input into a safe FTS5 MATCH expression: each term
    becomes a quoted token (implicit AND), so punctuation can't be parsed as an
    operator. Returns None if there are no terms."""
    terms = raw.split()
    if not terms:
        return None
    return " ".join('"' + t.replace('"', '""') + '"' for t in terms)


_FACT_COLS = ("id, content, tags, confidence, contested, last_evidence_at, source_agent, created_at, "
              "importance, utility, last_link_at")


def _query_facts(conn, query, limit=200):
    """Facts matching `query` via FTS5 (falling back to LIKE when FTS is unavailable or the query
    has no tokens). The shared read used by `hv search` and the dashboard /api/search."""
    fts_expr = _fts_query(query)
    if fts_expr is not None:
        try:
            return conn.execute(
                f"SELECT {', '.join('f.' + c for c in _FACT_COLS.split(', '))} "
                f"FROM facts f JOIN facts_fts ON f.id = facts_fts.rowid "
                f"WHERE facts_fts MATCH ? LIMIT ?", (fts_expr, limit)).fetchall()
        except sqlite3.OperationalError:
            pass  # FTS unavailable — fall back
    return conn.execute(f"SELECT {_FACT_COLS} FROM facts WHERE content LIKE ? LIMIT ?",
                        (f"%{query}%", limit)).fetchall()


def _query_decisions(conn, query, limit=10):
    """Decisions matching `query` (LIKE over content/rationale/tags), newest-first. No FTS /
    confidence projection — the table is small. Superseded ones are included (flagged by caller)."""
    like = f"%{query}%"
    return conn.execute(
        "SELECT id, content, rationale, tags, source_agent, created_at, superseded_by, informed_by, "
        "outcome_score, last_outcome_at "
        "FROM decisions WHERE content LIKE ? OR rationale LIKE ? OR tags LIKE ? "
        "ORDER BY created_at DESC LIMIT ?", (like, like, like, limit)).fetchall()


def _query_ideas(conn, query, limit=200):
    """Ideas matching `query` (LIKE over content/tags). No FTS — the table is small; ranking is by
    effective confidence in the caller."""
    like = f"%{query}%"
    return conn.execute(
        "SELECT id, content, tags, source_agent, created_at, confidence, contested, last_evidence_at, "
        "importance, utility, last_link_at "
        "FROM ideas WHERE content LIKE ? OR tags LIKE ? ORDER BY created_at DESC LIMIT ?",
        (like, like, limit)).fetchall()


def _chain(args):
    """`hv search --chain <sid|ref>` (#157): follow a decision's supersede chain, one hop per line, to the
    live entry. Each hop names the superseding entry by sid and the link's authority; a `supersedes` link
    recorded as evidence only is shown as not in effect, and the walk stops there (that entry is live). Reads
    the local store. Exit 1 when the id names no decision."""
    conn = get_conn()
    try:
        try:
            kind, ref = _parse_ref_arg(conn, args.chain_id)
        except ValueError as e:
            kind, ref, err = None, None, str(e)
        else:
            err = f"{args.chain_id!r} is a {kind}, not a decision" if kind != "decision" else None
        row = _index_row(conn, ref) if ref and not err else None
        if err or row is None:
            print(f"hv search --chain: {err or repr(args.chain_id) + ' names no decision on this node'}", file=sys.stderr)
            sys.exit(1)
        hops, seen, cur = [], set(), row[1]
        while cur is not None and cur not in seen:
            seen.add(cur)
            me = _ids_for(conn, "decision", [cur]).get(cur) or {}
            r = conn.execute("SELECT content FROM decisions WHERE id = ?", (cur,)).fetchone()
            info = _supersede_info(conn, [cur]).get(cur) or _NOT_SUPERSEDED
            hops.append({"sid": me.get("sid"), "ref": me.get("ref"), "content": r["content"] if r else None,
                         "superseded_by_sid": info["superseded_by_sid"], "superseded_by_ref": info["superseded_by_ref"],
                         "authority": info["superseded_by_authority"], "supersede_evidence": info["supersede_evidence"]})
            nxt = conn.execute("SELECT superseded_by FROM decisions WHERE id = ?", (cur,)).fetchone()
            cur = nxt["superseded_by"] if nxt else None
        live = hops[-1] if hops and not hops[-1]["superseded_by_sid"] else None
    finally:
        conn.close()
    if args.format == "json":
        print(json.dumps({"chain": hops, "live": live["sid"] if live else None}, indent=2))
        return
    for i, h in enumerate(hops):
        step = (f"superseded by {h['superseded_by_sid']} ({h['authority']})" if h["superseded_by_sid"]
                else "LIVE (not superseded)")
        print(f"{'  ' * i}{h['sid']}  {step}  {(h['content'] or '')[:80]}")
        for e in h["supersede_evidence"]:
            print(f"{'  ' * i}  evidence only, not in effect: {e['sid']}")
    if live is None:
        print("  (chain does not end at a live entry: a supersede cycle)")


def _lookup_id(args):
    """`hv search --id <sid|ref>` (#158): one entry by its stable id, straight from the local store (the same
    resolution as the dashboard's /api/item, with no daemon). Exit 1 when it names nothing."""
    res = api_item(args.lookup_id)
    if res.get("error") or not res.get("item"):
        print(f"hv: {args.lookup_id!r} does not resolve to a fact, decision or idea on this node"
              + (f" ({res['error']})" if res.get("error") else ""), file=sys.stderr)
        sys.exit(1)
    if args.format == "json":
        print(json.dumps(res, indent=2))
        return
    it = res["item"]
    print(f"{res['kind']} {res['sid']}  ref: {res['ref']}")
    print(f"  {it['content']}")
    if it.get("rationale"):
        print(f"  ↳ {it['rationale']}")
    if it.get("tags"):
        print(f"  Tags: {', '.join(it['tags'])}")
    bits = []
    if it.get("source"):
        bits.append(f"From: {it['source']}")
    if it.get("confidence") is not None:
        bits.append(f"Conf: {it['confidence']:.2f}")
    if res["kind"] == "decision":
        sup = _supersede_text(it)
        if it.get("superseded_by_sid"):
            bits.append(sup.strip().replace("⚠ ", "").split("  (supersede")[0])
        else:
            bits.append("SUPERSEDED" if it.get("superseded") else "current")
        if it.get("supersede_evidence"):
            bits.append(sup.strip().split("  ")[-1] if it.get("superseded_by_sid") else sup.strip())
        if it.get("outcome_score") is not None:
            bits.append(f"outcome {it['outcome_score']:+.2f}")
    if it.get("contested"):
        bits.append("CONTESTED")
    if it.get("forgotten"):
        bits.append("FORGOTTEN")
    if it.get("created"):
        bits.append(f"created {it['created']}")
    print("  " + "  ".join(bits))


def search(args):
    """Search facts AND decisions. Facts rank/filter by EFFECTIVE confidence (the time-invariant base
    projection decayed by recency, computed at query time with $HIVE_NOW) and surface contested claims.
    Decisions have no confidence projection, so they match by content/rationale/tags (newest-first,
    superseded ones flagged) — finding a decision by tag/text is the stable alternative to citing its
    node-local `#id`."""
    if getattr(args, "lookup_id", None):
        return _lookup_id(args)
    if getattr(args, "chain_id", None):
        return _chain(args)
    if args.query is None:
        print("hv search: give a query, or --id <sid|ref> to look one entry up", file=sys.stderr)
        sys.exit(2)
    conn = get_conn()
    now = os.environ.get("HIVE_NOW") or _now_iso()
    kind = getattr(args, "kind", None) or "all"
    sort = getattr(args, "sort", None) or "confidence"
    rows = _query_facts(conn, args.query) if kind in ("all", "fact") else []
    dec_rows = _query_decisions(conn, args.query) if kind in ("all", "decision") else []
    idea_rows = _query_ideas(conn, args.query) if kind in ("all", "idea") else []
    # 1.19 PR6: decay runs under the entry's CLASS half-life (governed: halflife_fact / _idea / _volatile),
    # and every fact/idea row carries learned `importance` + `utility` (stored undecayed, decayed here).
    gov = _governance_state(merkle.read_all_entries(JOURNAL_DIR))
    cap = float((gov.get("config") or {}).get("importance_self_cap", CONF_IMPORTANCE_SELF_CAP))

    def sal(r, cls):
        hl = _halflife(gov, cls)
        imp = r["importance"] if r["importance"] is not None else 0.0
        return (_effective_salience(imp, r["last_link_at"], now, hl, floor=_salience_floor(cls, imp, cap)),
                _effective_salience(r["utility"] or 0.0, r["last_link_at"], now, hl))

    def rank(items, cls_of):
        keyf = {"recency": lambda t: (t[1]["created_at"] or "",),
                "importance": lambda t: (sal(t[1], cls_of(t[1]))[0], t[0], t[1]["created_at"] or ""),
                "utility": lambda t: (sal(t[1], cls_of(t[1]))[1], t[0], t[1]["created_at"] or "")}.get(
            sort, lambda t: (t[0], t[1]["created_at"] or ""))
        items.sort(key=keyf, reverse=True)
        return items

    # Decay + threshold + rank in Python (effective confidence depends on `now`).
    scored = [(_effective_confidence(r["confidence"], r["last_evidence_at"], now, _halflife(gov, _fact_class(r["tags"]))), r)
              for r in rows]
    scored = [(eff, r) for eff, r in scored if eff >= args.min_confidence]
    scored = rank(scored, lambda r: _fact_class(r["tags"]))[:10]
    # 1.19 PR3: every row carries its STABLE identity `ref` (node_id:seq) beside the rebuild-unstable
    # local id; decisions also expose what they relied on (`informed_by`, refs + this node's local ids).
    # 1.20: ideas rank like facts but sit at 0.0 until they earn confidence; under `all` only earned
    # ideas surface (a raw hypothesis is not knowledge yet), `--kind idea` lists them all.
    iscored = [(_effective_confidence(r["confidence"], r["last_evidence_at"], now, _halflife(gov, "idea")), r)
               for r in idea_rows]
    if kind == "all":
        iscored = [(eff, r) for eff, r in iscored if eff > 0]
    iscored = [(eff, r) for eff, r in iscored if eff >= args.min_confidence or kind == "idea"]
    iscored = rank(iscored, lambda r: "idea")[:10]
    hl_fact = _halflife(gov, "fact")
    fids = _ids_for(conn, "fact", [r["id"] for _e, r in scored])
    dids = _ids_for(conn, "decision", [r["id"] for r in dec_rows])
    iids = _ids_for(conn, "idea", [r["id"] for _e, r in iscored])
    # 1.19 PR3b: `sid` (the `h:` short id) is the human form of `ref`; both are stable, `id` is not.
    frefs = {k: v["ref"] for k, v in fids.items()}
    drefs = {k: v["ref"] for k, v in dids.items()}
    irefs = {k: v["ref"] for k, v in iids.items()}
    fsids = {k: v["sid"] for k, v in fids.items()}
    dsids = {k: v["sid"] for k, v in dids.items()}
    dsup = _supersede_info(conn, [r["id"] for r in dec_rows])
    isids = {k: v["sid"] for k, v in iids.items()}
    dinformed = {r["id"]: _local_ids_for_refs(conn, _clean_refs(r["informed_by"]))
                 for r in dec_rows}
    # 1.22 (#115): what each fact row BUILDS ON (`extends` edges), shown in text only — JSON consumers
    # already have the `links` table. Target named by its canonical short id.
    fextends = {}
    if args.format != "json" and fids:
        q = ",".join("?" * len(fids))
        for lr in conn.execute(f"SELECT from_id, to_kind, to_id FROM links WHERE kind = 'extends' "
                               f"AND from_kind = 'fact' AND from_id IN ({q}) ORDER BY to_kind, to_id",
                               tuple(fids)):
            tsid = _sid_of(conn, lr["to_kind"], lr["to_id"])
            if tsid:
                fextends.setdefault(lr["from_id"], []).append(tsid)
    conn.close()

    if args.format == "json":
        # Stays a flat list (back-compat) with a new `kind` discriminator; decisions carry no
        # confidence, so a min_confidence>0 consumer naturally drops them.
        # `tags` is a list (2.0, #77), like every /api/* row already; it was the stored JSON-encoded string
        # through 1.x. `tag_list` (1.21) stays as the same list, since contract §7 told adapters to read it.
        def _tag_list(r):
            try:
                t = json.loads(r["tags"]) if r["tags"] else []
            except (TypeError, ValueError):
                return []
            return [str(x) for x in t] if isinstance(t, list) else []
        out = [{**dict(r), "kind": "fact", "effective_confidence": eff, "ref": frefs.get(r["id"]),
                "tags": _tag_list(r), "tag_list": _tag_list(r),
                "sid": fsids.get(r["id"]),
                "effective_importance": sal(r, _fact_class(r["tags"]))[0],
                "effective_utility": sal(r, _fact_class(r["tags"]))[1]} for eff, r in scored]
        # Decisions carry `outcome_score` (stored, undecayed) + `effective_outcome_score` (evidence decayed
        # under the fact half-life at `now`); both stay absent-from-confidence, so --min-confidence
        # consumers still drop decisions. `last_outcome_at` NULL = no outcome yet.
        out += [{**{k: v for k, v in dict(r).items() if k != "informed_by"}, "kind": "decision",
                 "ref": drefs.get(r["id"]), "sid": dsids.get(r["id"]), "informed_by": dinformed.get(r["id"], []),
                 **(dsup.get(r["id"]) or _NOT_SUPERSEDED),
                 "tags": _tag_list(r), "tag_list": _tag_list(r),
                 "effective_outcome_score": (_effective_confidence(r["outcome_score"] or 0.0, r["last_outcome_at"], now, hl_fact)
                                             if r["last_outcome_at"] else None)} for r in dec_rows]
        out += [{**dict(r), "kind": "idea", "effective_confidence": eff, "ref": irefs.get(r["id"]),
                 "sid": isids.get(r["id"]), "tags": _tag_list(r), "tag_list": _tag_list(r),
                 "effective_importance": sal(r, "idea")[0], "effective_utility": sal(r, "idea")[1]}
                for eff, r in iscored]
        print(json.dumps(out, indent=2))
    else:
        for eff, r in scored:
            tags = json.loads(r["tags"]) if r["tags"] else []
            flag = "  ⚠ CONTESTED" if r["contested"] else ""
            imp, util = sal(r, _fact_class(r["tags"]))
            print(f"[{fsids.get(r['id'])} · {r['id']}] {r['content']}")
            print(f"     Tags: {', '.join(tags)}  Conf: {eff:.2f}  Imp: {imp:.2f}  Util: {util:.2f}  From: {r['source_agent']}{flag}")
            if fextends.get(r["id"]):
                print(f"     extends {', '.join(fextends[r['id']])}")
            print(f"     ref: {frefs.get(r['id'])}")
            print()
        if dec_rows:
            print("Decisions:")
            for r in dec_rows:
                dtags = json.loads(r["tags"]) if r["tags"] else []
                tagstr = f"  [{', '.join(dtags)}]" if dtags else ""
                sup = _supersede_text(dsup.get(r["id"]))
                if r["superseded_by"] and not sup:
                    sup = "  ⚠ SUPERSEDED"
                outc = ""
                if r["last_outcome_at"]:
                    eff_o = _effective_confidence(r["outcome_score"] or 0.0, r["last_outcome_at"], now, hl_fact)
                    outc = f"  outcome {eff_o:+.2f}"
                print(f"  {dsids.get(r['id'])} (#{r['id']}) {r['content']}{tagstr}{sup}{outc}")
                if r["rationale"]:
                    print(f"       ↳ {r['rationale']}")
                inf = dinformed.get(r["id"]) or []
                if inf:
                    shown = ", ".join((i["sid"] or i["ref"]) + (f" ({i['kind'][0]}{i['id']})" if i["id"] is not None else " (not landed here)")
                                      for i in inf)
                    print(f"       informed by: {shown}")
                print(f"       ref: {drefs.get(r['id'])}")
            print()
        if iscored:
            print("Ideas (hypotheses — confidence is earned from sense-channel links, never asserted):")
            for eff, r in iscored:
                itags = json.loads(r["tags"]) if r["tags"] else []
                tagstr = f"  [{', '.join(itags)}]" if itags else ""
                flag = "  ⚠ CONTESTED" if r["contested"] else ""
                imp, util = sal(r, "idea")
                print(f"  {isids.get(r['id'])} (i{r['id']}) {r['content']}{tagstr}  Conf: {eff:.2f}  Imp: {imp:.2f}  Util: {util:.2f}{flag}")
                print(f"       ref: {irefs.get(r['id'])}")
            print()


def propose(args):
    """1.20: record an IDEA — a hypothesis the hive can support or contradict. It starts at confidence
    0.0 and earns confidence only from `sense`-channel `supports`/`contradicts` links by other identities;
    restating it never counts. Channel defaults to `introspect` (a hypothesis is internal state)."""
    tags = [t.strip() for t in args.tags.split(",")] if getattr(args, "tags", None) else []
    tags = [t for t in tags if t]
    source = _write_source(args)
    payload = {"content": args.content, "tags": tags, "source": source,
               "channel": getattr(args, "channel", None) or "introspect"}
    entry = append_journal("idea", payload)
    try:
        conn = get_conn()
        res = persist_idea(conn, entry)
        _mark_projected(conn, merkle.read_all_entries(JOURNAL_DIR), [entry])
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:                # after the append: never report failure (#70)
        _store_deferred(entry, e, "Proposed idea")
    tagnote = f"  [{', '.join(tags)}]" if tags else ""
    print(f"Proposed idea i{res['id']} {_short_id(entry['node_id'], entry['seq'])}{tagnote}  (confidence 0.00 — "
          f"earned only from sense-channel supports/contradicts links by other identities)")
    print(f"  ref: {_ref_str([entry['node_id'], entry['seq']])}")


def decide(args):
    """Record a decision. `--tags` scopes it (e.g. by project) and is journaled in the
    decision payload, so the decision is findable by `hv search` alongside facts — the stable
    alternative to citing a decision by its node-local, rebuild-unstable `#id`.

    `--revoke` (1.24, #45) withdraws a decision with no replacement: the same `supersedes` link, from a
    decision tagged `revocation` whose payload names the target (`revokes`). It commands only where the
    link is `hard` (§5); otherwise it is recorded as evidence and the confirmation says it is not in
    effect."""
    revoke = getattr(args, "revoke", None)
    if not args.content and not revoke:
        print("decide: content is required (it is optional only with --revoke)", file=sys.stderr)
        sys.exit(2)
    if revoke and not (args.rationale or "").strip():
        print("--revoke: --rationale is required: say why the decision is withdrawn", file=sys.stderr)
        sys.exit(1)
    # Resolve --supersedes / --revoke (a sid or ref; 2.0 refuses local ids) to a journal-identity reference so the
    # supersedes link survives rebuilds and cross-node merges. Kind-checked: a fact target aborts.
    supersedes_ref = None
    revoked_line = ""
    informed = []                     # 1.19 PR3: [(kind, [node_id, seq]), ...] the decision relied on
    conn0 = get_conn()
    target_opt = "--revoke" if revoke else "--supersedes"
    if args.supersedes or revoke:
        try:
            supersedes_ref = _resolve_id_arg(conn0, revoke or args.supersedes, "decision", target_opt)
        except ValueError as e:
            conn0.close()
            print(f"{target_opt}: {e}", file=sys.stderr)
            sys.exit(1)
    if revoke:
        row = conn0.execute("SELECT content FROM decisions WHERE id = ?",
                            (_resolve_ref(conn0, supersedes_ref),)).fetchone()
        revoked_line = next(iter(((row["content"] if row else "") or "").strip().splitlines()), "")[:120]
    # Resolve EVERY --informed reference before anything is journaled: an unresolvable or wrong-kind id
    # aborts the whole write (no partial decision, no dangling links). Stable `node_id:seq` refs are
    # the primary form; 2.0 refuses local ids (see _parse_ref_arg).
    for tok in (getattr(args, "informed", None) or []):
        try:
            informed.append(_parse_ref_arg(conn0, tok))
        except ValueError as e:
            conn0.close()
            print(f"--informed: {e}", file=sys.stderr)
            sys.exit(1)
    conn0.close()
    seen = set()
    informed_refs = []
    for _kind, ref in informed:               # de-dup, keep order
        if tuple(ref) not in seen:
            seen.add(tuple(ref))
            informed_refs.append(ref)

    tags = [t.strip() for t in args.tags.split(",")] if getattr(args, "tags", None) else []
    tags = [t for t in tags if t]
    revoked_sid = _short_id(*supersedes_ref) if revoke else None
    if revoke and "revocation" not in tags:
        tags.append("revocation")              # matches the revocations already in the corpus
    # #114 (D-6): an agent names itself with --source, so its decision is not attributed to a person and
    # its links are not owner-signed. Same fallback as `remember` (an omitted --source is `manual`: #119).
    source = _write_source(args)
    payload = {
        "content": args.content or (f"Revoke {revoked_sid}: {revoked_line}" if revoked_line else f"Revoke {revoked_sid}"),
        "rationale": args.rationale,
        "tags": tags,
        "source": source,
    }
    if informed_refs:
        payload["informed_by"] = informed_refs   # additive (1.15 `tags` precedent): the human-legible record
    if revoke:
        payload["revokes"] = list(supersedes_ref)   # additive: a pre-1.24 node sees an ordinary decision
    entry = append_journal("decision", payload)
    # 1.19 PR2b (write-path switch): `--supersedes` is ONE `supersedes` link (owner-signed on the owner
    # machine → hard everywhere; else hard only where this device authored the target), never the legacy
    # `supersedes_ref` field. The legacy resolver stays for entries already in journals.
    link_entries = []
    supersedes_link = None
    if supersedes_ref:
        supersedes_link = append_journal("link", _link_payload("supersedes", [entry["node_id"], entry["seq"]],
                                                               supersedes_ref, source))
        link_entries.append(supersedes_link)
    # One `informed` link per ref — what the utility projection reads (design §3). Same source as the
    # decision; no channel (a decision is neither an observation nor introspection about one). Through
    # the one builder since #114, so the signing rule is the same for every kind.
    informed_links = [append_journal("link", _link_payload("informed", [entry["node_id"], entry["seq"]], ref, source))
                      for ref in informed_refs]
    link_entries += informed_links

    journal = merkle.read_all_entries(JOURNAL_DIR)
    all_entries = _projection_entries(journal)
    gov = _governance_state(all_entries) if link_entries else None
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in all_entries} if link_entries else {}
    try:
        conn = get_conn()
        res = persist_decision(conn, entry)
        if link_entries:
            for le in link_entries:
                resolve_link(conn, le, gov, by_ref)
            _recompute_importance(conn, all_entries)      # 1.19 PR6: `informed` links are attention + utility
            _recompute_utility(conn, all_entries)
        _mark_projected(conn, journal, [entry] + link_entries)
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:                # after the append: never report failure (#70)
        _store_deferred(entry, e, "Decided")

    tagnote = f"  [{', '.join(tags)}]" if tags else ""
    infnote = f"  informed by {len(informed_refs)} ref(s)" if informed_refs else ""
    if revoke:
        # #45 R4: say whether the revoke is IN EFFECT, from the authority the projection gives the link
        # (§5), not from --source: the same agent writes a hard revoke on the device that authored the
        # target and an evidence one anywhere else.
        hard = _link_authority(supersedes_link, by_ref.get(tuple(supersedes_ref)), gov) == "hard"
        what = f'decision {revoked_sid}' + (f' ("{revoked_line}")' if revoked_line else "")
        if hard:
            print(f"Revoked {what} {_signing_note(supersedes_link)}")
        else:
            print(f"Revoke of {what} recorded {_signing_note(supersedes_link)}; NOT in effect until the owner, "
                  f"or the device that wrote the decision, re-runs `hv decide --revoke {revoked_sid}` "
                  f"(`hv doctor` lists it under link-authz)")
        print(f"  revocation: {_short_id(entry['node_id'], entry['seq'])} (decision #{res['id']}){tagnote}{infnote}")
    else:
        print(f"Decided as {_short_id(entry['node_id'], entry['seq'])} (decision #{res['id']}){tagnote}{infnote}")
    print(f"  ref: {_ref_str([entry['node_id'], entry['seq']])}")
    if supersedes_link is not None and not revoke:
        print(f"  ⤳ supersedes decision {_short_id(*supersedes_ref)} {_signing_note(supersedes_link)}")
    if informed_links:
        print(f"  ⇠ informed links {_signing_note(informed_links[0])}")


