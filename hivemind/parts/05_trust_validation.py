# --------------------------------------------------------------------------
# 1.19 PR7: trust velocity (design §8) — a DERIVED view of the same evidence, per signer. Advisory
# only: it feeds `doctor trust-drift` and a `hv peers` column, and by decision it is NOT wired into
# admission, purge, or link authority (that is a 1.2x call once real drift has been observed).
# Change over time is the security signal, not the level: a long-reliable device that suddenly starts
# being contradicted is more interesting than one that was always mediocre.
# --------------------------------------------------------------------------

def _in_window(ts, now, days):
    a, b = _to_dt(ts), _to_dt(now)
    if a is None or b is None:
        return False
    delta = (b - a).total_seconds() / 86400.0
    return 0.0 <= delta <= days


def _signer_reliability(entries, gov, window_days, now):
    """Per node_id, over the trailing `window_days` ending at `now` (ISO; `$HIVE_NOW`-drivable):
      asserted      — facts this node wrote in the window
      contradicted  — how many of those were retracted or `contradicts`-linked by a DIFFERENT node
                      in the window (self-correction is not a reliability hit)
      reliability   — 1 − contradicted/asserted, or None when nothing was asserted
      channels      — the same three, split by the contradicted FACT's channel (`sense` observations vs
                      `introspect` reasoning point at different compromises, §0.1)
      decisions / outcome_mean — decisions this node wrote in the window that have ≥1 sense-channel
                      outcome, and the mean of their outcome scores (via `_decision_evidence`), else None
    Pure over (journal, gov, now). Only admitted devices once an owner exists."""
    admitted = gov.get("admitted") if gov.get("owner_id") else None
    facts = {}          # (node, seq) -> (node, channel)
    out = {}

    def node_rec(n):
        return out.setdefault(n, {"asserted": 0, "contradicted": 0, "reliability": None,
                                  "channels": {"sense": {"asserted": 0, "contradicted": 0, "reliability": None},
                                               "introspect": {"asserted": 0, "contradicted": 0, "reliability": None}},
                                  "decisions": 0, "outcome_mean": None})

    for e in entries:
        n = e.get("node_id")
        if n is None or (admitted is not None and n not in admitted):
            continue
        if e.get("type") == "fact" and _in_window(e.get("timestamp", ""), now, window_days):
            ch = _channel(e.get("payload"))
            ch = "sense" if ch == "act" else ch        # an action is reported like an observation
            facts[(n, e.get("seq"))] = (n, ch)
            r = node_rec(n)
            r["asserted"] += 1
            r["channels"][ch]["asserted"] += 1
    hit = set()
    for e in entries:
        t = e.get("type")
        if t not in ("retract", "link") or not _in_window(e.get("timestamp", ""), now, window_days):
            continue
        if "sig" in e and not _verify_entry(e):
            continue
        p = e.get("payload") or {}
        if t == "retract":
            ref = p.get("retracts_ref")
        elif p.get("kind") == "contradicts":
            ref = p.get("to_ref")
        else:
            continue
        if not _valid_ref(ref):
            continue
        key = tuple(ref)
        if key not in facts or facts[key][0] == e.get("node_id"):
            continue                                       # unknown target, or self-correction
        hit.add(key)
    for key in hit:
        n, ch = facts[key]
        out[n]["contradicted"] += 1
        out[n]["channels"][ch]["contradicted"] += 1
    dev = _decision_evidence(entries, gov)
    scores = {}
    for e in entries:
        n = e.get("node_id")
        if e.get("type") != "decision" or n not in out and (admitted is not None and n not in admitted):
            continue
        if not _in_window(e.get("timestamp", ""), now, window_days):
            continue
        ev = dev.get((n, e.get("seq")))
        if not ev or not ev.get("last_ts"):
            continue
        scores.setdefault(n, []).append(_content_confidence(ev, gov))
    for n, vals in scores.items():
        r = node_rec(n)
        r["decisions"] = len(vals)
        r["outcome_mean"] = round(sum(vals) / len(vals), 6)
    for r in out.values():
        if r["asserted"]:
            r["reliability"] = round(1.0 - r["contradicted"] / r["asserted"], 6)
        for c in r["channels"].values():
            if c["asserted"]:
                c["reliability"] = round(1.0 - c["contradicted"] / c["asserted"], 6)
    return out


def _trust_velocity(entries, gov, now):
    """Per node: short-window minus long-window reliability (and outcome mean), plus the per-channel
    deltas. None where either window has nothing to measure. Windows are the governed knobs
    `trust_long_days` / `trust_short_days`, so every node computes the same drift."""
    cfg = gov.get("config") or {}
    L = float(cfg.get("trust_long_days", GOV_TRUST_LONG_DAYS))
    S = float(cfg.get("trust_short_days", GOV_TRUST_SHORT_DAYS))
    long, short = _signer_reliability(entries, gov, L, now), _signer_reliability(entries, gov, S, now)

    def d(a, b):
        return round(b - a, 6) if (a is not None and b is not None) else None

    out = {}
    for n in set(long) | set(short):
        lo, sh = long.get(n) or {}, short.get(n) or {}
        out[n] = {
            "long": lo.get("reliability"), "short": sh.get("reliability"),
            "delta": d(lo.get("reliability"), sh.get("reliability")),
            "outcome_long": lo.get("outcome_mean"), "outcome_short": sh.get("outcome_mean"),
            "outcome_delta": d(lo.get("outcome_mean"), sh.get("outcome_mean")),
            "channels": {ch: d((lo.get("channels") or {}).get(ch, {}).get("reliability"),
                               (sh.get("channels") or {}).get(ch, {}).get("reliability"))
                         for ch in ("sense", "introspect")},
            "short_asserted": sh.get("asserted", 0), "long_asserted": lo.get("asserted", 0),
        }
    return out


def _trust_drifting(entries, gov, now):
    """Nodes whose velocity (reliability or outcome mean, overall or per channel) fell below the governed
    `trust_drift_threshold`. Returns ['<node> reliability 0.95→0.40 (Δ-0.55)', ...]. Advisory only."""
    thr = float((gov.get("config") or {}).get("trust_drift_threshold", GOV_TRUST_DRIFT_THRESHOLD))
    out = []
    for n, v in sorted(_trust_velocity(entries, gov, now).items()):
        parts = []
        if v["delta"] is not None and v["delta"] < thr:
            parts.append(f"reliability {v['long']:.2f}→{v['short']:.2f} (Δ{v['delta']:+.2f})")
        if v["outcome_delta"] is not None and v["outcome_delta"] < thr:
            parts.append(f"decision outcomes {v['outcome_long']:+.2f}→{v['outcome_short']:+.2f} (Δ{v['outcome_delta']:+.2f})")
        for ch, cd in (v.get("channels") or {}).items():
            if cd is not None and cd < thr and v["delta"] is not None and not (v["delta"] < thr):
                parts.append(f"{ch}-channel reliability Δ{cd:+.2f}")
        if parts:
            out.append(f"{n}: " + "; ".join(parts))
    return out


def _same_principal(gov, dev_a, dev_b):
    """True when two devices are the same device or map to the same admitted principal."""
    if dev_a == dev_b:
        return True
    prins = (gov or _DEFAULT_GOV).get("principals") or {}
    pa, pb = prins.get(dev_a), prins.get(dev_b)
    return pa is not None and pa == pb


def _link_attention(entries, gov=None):
    """Salience L3 input (design §7.2): target (node_id, seq) -> {'weights': {identity: w}, 'last_ts'}
    from every verified inbound `link` (ANY kind — attention is attention) whose signer is a DIFFERENT
    principal from the target entry's author (self-links never raise one's own importance). One
    identity's repeated links of one kind count once (max weight per (identity, kind)); kinds sum.
    Admission and the same-device discount are applied by the caller via `_governed_side`.
    `access_count` / `last_accessed` are never read — node-local state never enters a projection."""
    gov = gov or _DEFAULT_GOV
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    per = {}
    for e in entries:
        if e.get("type") != "link":
            continue
        if "sig" in e and not _verify_entry(e):
            continue
        p = e.get("payload", {}) or {}
        to_ref, frm = p.get("to_ref"), p.get("from_ref")
        if not (_valid_ref(to_ref) and tuple(to_ref) in by_ref):
            continue
        if not (_valid_ref(frm) and tuple(frm) in by_ref):
            continue
        target = by_ref[tuple(to_ref)]
        if _same_principal(gov, e.get("node_id"), target.get("node_id")):
            continue
        key, w = _identity_weight(e.get("node_id"), p.get("source", "manual"))
        if w <= 0:
            continue
        slot = per.setdefault(tuple(to_ref), {"by_kind": {}, "last_ts": ""})
        k = (key, str(p.get("kind")))
        if w > slot["by_kind"].get(k, 0.0):
            slot["by_kind"][k] = w
        ts = e.get("timestamp", "")
        if ts > slot["last_ts"]:
            slot["last_ts"] = ts
    out = {}
    for ref, slot in per.items():
        weights = {}
        for (key, _kind), w in slot["by_kind"].items():
            weights[key] = weights.get(key, 0.0) + w
        out[ref] = {"weights": weights, "by_kind": slot["by_kind"], "last_ts": slot["last_ts"]}
    return out


def _importance(prior, weights, volatile, gov=None):
    """§7.2: prior + w_links × squash(governed other-identity link weight) + w_volatile × volatile,
    clamped to [0, 1]. Time-invariant (decay is query-time, `_effective_salience`)."""
    gov = gov or _DEFAULT_GOV
    cfg = gov.get("config") or {}
    total, _devs = _governed_side(weights, gov) if weights else (0.0, set())
    w_links = float(cfg.get("w_links", CONF_W_LINKS))
    w_vol = float(cfg.get("w_volatile", CONF_W_VOLATILE))
    return round(max(0.0, min(1.0, prior + w_links * _squash(total) + w_vol * (1.0 if volatile else 0.0))), 6)


def _utility_evidence(entries, gov=None):
    """§3 / §7.2: target (node_id, seq) -> {'weights': {identity: Σw}, 'last_ts'} over every verified
    `informed` link whose from_ref is a DECISION. Weight = identity weight of the decision's signer ×
    (0.25 + 0.75 × max(0, outcome_score)) — "was used" counts the 0.25 prior before "worked out" is
    known; a negative outcome floors at the prior. Uses the decision's base (undecayed) outcome score
    from `_decision_evidence`, so the projection stays time-invariant."""
    gov = gov or _DEFAULT_GOV
    by_ref = {(e.get("node_id"), e.get("seq")): e for e in entries}
    dscore = {ref: _content_confidence(ev, gov) for ref, ev in _decision_evidence(entries, gov).items()}
    out = {}
    for e in entries:
        if e.get("type") != "link":
            continue
        if "sig" in e and not _verify_entry(e):
            continue
        p = e.get("payload", {}) or {}
        if p.get("kind") != "informed":
            continue
        to_ref, frm = p.get("to_ref"), p.get("from_ref")
        if not (_valid_ref(frm) and tuple(frm) in by_ref):
            continue
        if by_ref[tuple(frm)].get("type") != "decision":
            continue
        if not (_valid_ref(to_ref) and tuple(to_ref) in by_ref):
            continue
        key, w = _identity_weight(e.get("node_id"), p.get("source", "manual"))
        mult = 0.25 + 0.75 * max(0.0, dscore.get(tuple(frm), 0.0))
        slot = out.setdefault(tuple(to_ref), {"weights": {}, "last_ts": ""})
        slot["weights"][key] = slot["weights"].get(key, 0.0) + w * mult
        ts = e.get("timestamp", "")
        if ts > slot["last_ts"]:
            slot["last_ts"] = ts
    return out


def _utility(weights, gov=None):
    """squash(governed Σ informed-link weight) in [0, 1)."""
    total, _devs = _governed_side(weights, (gov or _DEFAULT_GOV)) if weights else (0.0, set())
    return round(_squash(total), 6)


def _salience_rows(conn, entries, gov):
    """(fact rows by content, idea rows by ref) with their journal entries, shared by the two
    projections so a corroborated fact (many entries → one row) is aggregated once."""
    facts = {}                                   # content -> {'id', 'tags', 'refs': [...], 'asserted': float}
    for r in conn.execute("SELECT id, content, tags FROM facts"):
        facts[r["content"]] = {"id": r["id"], "tags": r["tags"], "refs": [], "asserted": None}
    for e in entries:
        if e.get("type") != "fact":
            continue
        p = e.get("payload", {}) or {}
        f = facts.get(p.get("content"))
        if f is None:
            continue
        f["refs"].append((e.get("node_id"), e.get("seq")))
        check, default = _PAYLOAD_SHAPES["fact"]["importance"]       # a journaled NaN / "nan" / list is the default
        a = float(p["importance"]) if p.get("importance") is not None and check(p["importance"]) else default
        f["asserted"] = a if f["asserted"] is None else max(f["asserted"], a)
    ideas = {}
    for e in entries:
        if e.get("type") == "idea":
            row = _index_row(conn, [e.get("node_id"), e.get("seq")])
            if row and row[0] == "idea":
                ideas[(e.get("node_id"), e.get("seq"))] = row[1]
    return facts, ideas


def _recompute_importance(conn, entries):
    """The ONLY writer of facts.importance / ideas.importance / *.last_link_at (1.19 PR6, salience L3).
    The journal keeps what the agent ASSERTED (`payload.importance`); the column is what the hive
    learned: prior = min(asserted, importance_self_cap) for a fact (0 for an idea — no asserted value),
    raised only by link in-degree from OTHER identities. Pure over the journal + governance."""
    gov = _governance_state(entries)
    cap = float((gov.get("config") or {}).get("importance_self_cap", CONF_IMPORTANCE_SELF_CAP))
    att = _link_attention(entries, gov)
    uev = _utility_evidence(entries, gov)
    facts, ideas = _salience_rows(conn, entries, gov)

    def merged(refs):
        """One row, possibly many entries (a corroborated fact): re-aggregate per (identity, kind) with
        max, then sum kinds per identity — the same rule `_link_attention` applies within one entry."""
        by_kind, last = {}, ""
        for ref in refs:
            a = att.get(ref)
            if a:
                for k, w in a["by_kind"].items():
                    by_kind[k] = max(by_kind.get(k, 0.0), w)
                last = max(last, a["last_ts"])
            u = uev.get(ref)
            if u:
                last = max(last, u["last_ts"])
        weights = {}
        for (key, _kind), w in by_kind.items():
            weights[key] = weights.get(key, 0.0) + w
        return weights, (last or None)

    for content, f in facts.items():
        weights, last = merged(f["refs"])
        prior = min(f["asserted"] if f["asserted"] is not None else 0.5, cap)
        imp = _importance(prior, weights, _fact_class(f["tags"]) == "volatile", gov)
        conn.execute("UPDATE facts SET importance = ?, last_link_at = ? WHERE id = ?", (imp, last, f["id"]))
    for ref, iid in ideas.items():
        weights, last = merged([ref])
        conn.execute("UPDATE ideas SET importance = ?, last_link_at = ? WHERE id = ?",
                     (_importance(0.0, weights, False, gov), last, iid))


def _recompute_utility(conn, entries):
    """The ONLY writer of facts.utility / ideas.utility (1.19 PR6, design §3): how much recorded
    decision-making relied on this entry, weighted by how those decisions turned out."""
    gov = _governance_state(entries)
    uev = _utility_evidence(entries, gov)
    facts, ideas = _salience_rows(conn, entries, gov)
    conn.execute("UPDATE facts SET utility = 0.0")
    conn.execute("UPDATE ideas SET utility = 0.0")
    for content, f in facts.items():
        weights = {}
        for ref in f["refs"]:
            for k, w in (uev.get(ref) or {"weights": {}})["weights"].items():
                weights[k] = weights.get(k, 0.0) + w
        if weights:
            conn.execute("UPDATE facts SET utility = ? WHERE id = ?", (_utility(weights, gov), f["id"]))
    for ref, iid in ideas.items():
        weights = (uev.get(ref) or {"weights": {}})["weights"]
        if weights:
            conn.execute("UPDATE ideas SET utility = ? WHERE id = ?", (_utility(weights, gov), iid))


def _to_dt(s):
    from datetime import datetime
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _days_between(ts_a, ts_b):
    """Whole+fractional days from ts_a to ts_b (ISO-8601), or 0.0 if either is unparseable. Used by
    the dead-man switch (Stage C) to measure owner inactivity against a proposal's basis_ts."""
    a, b = _to_dt(ts_a), _to_dt(ts_b)
    if a is None or b is None:
        return 0.0
    return (b - a).total_seconds() / 86400.0


def _age_days(ts):
    """Whole days since ISO-8601 `ts`, or None if unparseable. The staleness signal for `hv peers`
    and the dashboard /api/peers (a device idle > 14d is a purge candidate)."""
    try:
        import datetime
        t = datetime.datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - t).days
    except Exception:
        return None


def _election_id(new_owner_pub_b64, basis_ts):
    """Content-addressed election proposal id: derived from WHAT is proposed (the new owner pubkey
    + the proposer's basis timestamp). So every device's vote/re-proposal for the same intent shares
    one id and merges deterministically, and a proposal can't be re-pointed at a different key."""
    return "e1:" + hashlib.sha256(_canonical({"new_owner_pub": new_owner_pub_b64,
                                              "basis_ts": basis_ts})).hexdigest()[:16]


def _effective_confidence(base, last_evidence_at, now, halflife=None):
    """Query-time confidence: base decayed by recency. Owner-forget (FORGET_FLOOR) does NOT
    decay (stays gone). Deterministic given (base, last_evidence_at, now) — `now` is injectable
    via $HIVE_NOW so every node computes identical effective confidence for the same instant.
    `halflife` (days; 1.19 PR6) selects the entry's CLASS half-life — `_halflife(gov, cls)`; the
    default is the fact half-life, so pre-PR6 callers are unchanged."""
    if base == FORGET_FLOOR or not last_evidence_at:
        return base
    a, b = _to_dt(last_evidence_at), _to_dt(now)
    if a is None or b is None:
        return base
    age_days = max(0.0, (b - a).total_seconds() / 86400.0)
    return round(base * (0.5 ** (age_days / (halflife or HALFLIFE_DAYS))), 6)


def _salience_floor(cls, importance, cap):
    """What an entry keeps when its links go stale: a fact settles to what its author could claim alone
    (min(importance, importance_self_cap)); an idea has no self-assertion, so it settles to 0."""
    return 0.0 if cls == "idea" else min(importance, cap)


def _effective_salience(base, last_link_at, now, halflife, floor=0.0):
    """Query-time importance / utility (1.19 PR6): the part of `base` above `floor` decays from the most
    recent contributing link (`last_link_at`; NULL = nothing to decay — an unlinked fact keeps its
    capped self-assertion). Importance passes floor = min(base, importance_self_cap) so a fact whose
    links have gone stale settles back to what its author could claim alone, never below an unlinked
    peer; utility passes floor 0."""
    if not last_link_at or base <= floor:
        return round(base, 6)
    return round(floor + _effective_confidence(base - floor, last_link_at, now, halflife), 6)


def persist_decision(conn, entry):
    if not _projectable(entry):
        return None
    held = _claim_write(conn, entry, "decision")
    if held is not None:
        return {"id": held}
    payload = entry["payload"]
    ts = entry.get("timestamp", _now_iso())
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO decisions (content, rationale, source_agent, created_at, tags, informed_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        payload["content"],
        _payload_field(entry, "rationale"),
        _payload_field(entry, "source"),
        _payload_field(entry, "created_at") or ts,
        json.dumps(_payload_field(entry, "tags")),
        json.dumps(_clean_refs(payload.get("informed_by"))),   # pre-1.19 decisions read back as []
    ))
    did = cur.lastrowid
    _record_index(conn, entry, "decision", did)
    return {"id": did}


def persist_idea(conn, entry):
    """Pass 1 (1.20): one row per `idea` ENTRY — deliberately NO content de-dup (unlike persist_fact):
    a hypothesis restated by another agent is another hypothesis, not corroboration. Confidence starts
    at 0.0 and is written only by `_recompute_idea_confidence`."""
    if not _projectable(entry):
        return None
    held = _claim_write(conn, entry, "idea")
    if held is not None:
        return {"id": held}
    payload = entry["payload"]
    ts = entry.get("timestamp", _now_iso())
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ideas (content, tags, source_agent, source_session, created_at, confidence)
        VALUES (?, ?, ?, ?, ?, 0.0)
    """, (payload["content"], json.dumps(_payload_field(entry, "tags")), _payload_field(entry, "source"),
          _payload_field(entry, "source_session"), _payload_field(entry, "created_at") or ts))
    iid = cur.lastrowid
    _record_index(conn, entry, "idea", iid)
    return {"id": iid}


_ENTITY_CONTEXT = threading.local()      # .identity_of while a projection holds a resolution (`_entity_identities`)


@contextlib.contextmanager
def _entity_identities(identity_of):
    """Hold `_entity_resolution`'s identity map for the `persist_entity` calls of one projection (a rebuild, or the
    one entry `entity add` projects). Without it `persist_entity` reads the entry's own fields, which is enough for a
    create and for an update whose target is already in the store."""
    prior = getattr(_ENTITY_CONTEXT, "identity_of", None)
    _ENTITY_CONTEXT.identity_of = identity_of
    try:
        yield
    finally:
        _ENTITY_CONTEXT.identity_of = prior


def _entity_form(entry):
    """How an `entity` entry names the entity it writes (3.0 plan §4.2): ("new", None) carries `new_identity: true`
    and creates one; ("update", ref) carries `identity_ref` and writes the entity that ref names; ("legacy", None)
    carries neither (every entry a 2.x node wrote) and is read by name; ("both", None) is malformed. A field of the
    wrong shape is absent, as `_payload_field` reads it."""
    p = entry.get("payload") or {}
    ref = tuple(p["identity_ref"]) if _valid_ref(p.get("identity_ref")) else None
    new = p.get("new_identity") is True
    if ref is not None and new:
        return "both", None
    if ref is not None:
        return "update", ref
    return ("new", None) if new else ("legacy", None)


def _entity_identity_for(conn, entry):
    """The identity ref an entry's write belongs to: the projection's resolution when one is held, else what the
    entry itself says (a create is its own ref; an update names a ref that the store maps, or is the identity), else
    None for the legacy reading, which folds by name."""
    ref = (entry.get("node_id"), entry.get("seq"))
    held = getattr(_ENTITY_CONTEXT, "identity_of", None)
    if held is not None and ref in held:
        return held[ref]
    form, target = _entity_form(entry)
    if form == "new":
        return ref
    if form == "update":
        row = conn.execute("SELECT e.ref_node, e.ref_seq FROM journal_index j JOIN entities e ON e.id = j.local_id "
                           "WHERE j.kind = 'entity' AND j.node_id = ? AND j.seq = ?", target).fetchone()
        return (row[0], row[1]) if row and row[0] is not None else target
    return None


def persist_entity(conn, entry):
    if not _projectable(entry):
        return None
    payload = entry["payload"]
    ts = entry.get("timestamp", _now_iso())
    cur = conn.cursor()
    attrs = payload.get("attributes")
    if isinstance(attrs, str):
        # An older writer stored the attributes as JSON text. Keep it when it is an object, else default.
        try:
            attrs = json.loads(attrs)
        except ValueError:
            attrs = None
    if attrs is not None and not isinstance(attrs, dict):
        _PROJECTION_NOTES.append(f"{entry.get('node_id')}:{entry.get('seq')} entity.attributes: defaulted")
        attrs = None
    attrs_json = json.dumps(attrs if attrs is not None else {})
    etype = _payload_field(entry, "type")
    seen = _payload_field(entry, "created_at") or ts
    # The name lookup and the insert are one write transaction, as 2.4's single upsert was: a second writer must
    # wait here and then see the first one's row, or two rows share a name (`name` is no longer UNIQUE).
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    ident = _entity_identity_for(conn, entry)
    if ident is None:
        # The legacy reading (§4.2 of the 3.0 plan): an entry folds by name into the entity that name already has, and
        # the first applied entry for a name creates it, its journal ref being the identity. Every entry any 2.x node
        # wrote is read this way.
        row = cur.execute("SELECT id FROM entities WHERE name = ? ORDER BY id LIMIT 1", (payload["name"],)).fetchone()
        ident = (entry.get("node_id"), entry.get("seq"))
    else:
        row = cur.execute("SELECT id FROM entities WHERE ref_node = ? AND ref_seq = ?", tuple(ident)).fetchone()
    if row is None:
        cur.execute("""
            INSERT INTO entities (name, type, attributes, first_seen, last_updated, ref_node, ref_seq)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (payload["name"], etype, attrs_json, seen, ts, ident[0], ident[1]))
        eid = cur.lastrowid
    else:
        eid = row[0]
        cur.execute("UPDATE entities SET type = ?, attributes = ?, last_updated = ? WHERE id = ?",
                    (etype, attrs_json, ts, eid))
        if tuple(ident) == (entry.get("node_id"), entry.get("seq")):
            # The creating entry, replayed after an update of it that sorts earlier (a lower node_id): the row is the
            # update's placeholder, and its creation time is the create's.
            cur.execute("UPDATE entities SET first_seen = ? WHERE id = ?", (seen, eid))
    _record_index(conn, entry, "entity", eid)
    return {"id": eid, "name": payload["name"], "type": etype}


def _entity_name(entry):
    n = (entry.get("payload") or {}).get("name")
    return n if isinstance(n, str) else None


def _entity_declined(entries, gov):
    """The `entity` entries the projection does not apply, as a set of (node_id, seq): the module-policy ones
    and the weigh-only ones (`_entity_verdicts`)."""
    module_declined, weigh_only = _entity_verdicts(entries, gov)
    return module_declined | weigh_only


def _entity_verdicts(entries, gov):
    """(module_declined, weigh_only), each a set of (node_id, seq) of `entity` entries the projection skips; see
    `_entity_resolution`, which also says which entity every other entry writes."""
    declined, weigh_only, _identity_of = _entity_resolution(entries, gov)
    return declined, weigh_only


def _entity_resolution(entries, gov):
    """(declined, weigh_only, identity_of): the `entity` entries the projection skips, and for every other one the
    identity (the journal ref of its creating entry) it writes. Pure over the journal and governance, so every node
    reaches the same verdicts whatever order entries arrived in. A skipped entry is not kept as evidence.

    3.0 (plan §4.2). An entry is a CREATE (`new_identity: true`: a new identity, its own ref, whatever the name), an
    UPDATE (`identity_ref`: the entity whose creating entry that ref names) or LEGACY (neither: what every 2.x node
    writes, folded by name into the first identity the name has; the first entry for a name creates it, so a name
    that only 2.x writers use has one identity, as before). A second create of a name is a second identity, and later
    legacy entries for the name stay with the first. An update's ref may be the creating entry or any legacy entry
    that folded into that identity; it may not name another update. An update that names nothing, names an entity of
    another name, or carries both fields is declined, as an entry whose body does not match its type.

    2.1 (#208, option 3): a module device (the `module` admit marker, `gov["modules"]`) may write only
    `x-<its module>:<name>` entities (the gate's `entity-prefix-required`), may update one only if it created it
    (`not-entity-owner`), and may not create a second identity for a name that already has one (`entity-name-taken`):
    its names stay unique, so the namespace rule and the `same-as` joins by ref are unchanged.

    SECREV B3 (hive-mind-private #51): every other device is held to the rule links use (`_link_authority`, the
    creator's entry standing as the target). The identity's creator, or an owner-signed write, rewrites the entity;
    any other admitted device's write is weigh-only: it is skipped like a declined one, so it does not replace the
    entity. Pre-owner, only the creator rule applies, as for links. A create needs no authority: it makes a new
    identity and replaces nothing. The module marker is read as of the end of the journal, like the election
    exclusion."""
    modules = gov.get("modules") or {}
    declined, weigh_only = set(), set()
    creator = {}          # identity -> the entry that created it
    group = {}            # name -> the first identity the name has: where the legacy reading folds
    identity_of = {}      # (node_id, seq) -> identity, for every applied create and legacy entry
    updates = []
    for e in entries:
        if e.get("type") != "entity":
            continue
        name = _entity_name(e)
        if name is None:
            continue
        node = e.get("node_id")
        key = (node, e.get("seq"))
        module = modules.get(node)
        form, target = _entity_form(e)
        if form == "both":
            declined.add(key)
            continue
        if module is not None:
            split = vocabulary.split_module_name(name)
            if split is None or split[0] != module:
                declined.add(key)
                continue
        if form == "update":
            updates.append((e, key, target))
            continue
        first = creator.get(group.get(name))
        if form == "new":
            if module is not None and first is not None:
                declined.add(key)
                continue
        elif first is not None:
            if module is not None:
                if first.get("node_id") != node:
                    declined.add(key)
                    continue
            elif _link_authority(e, first, gov) != "hard":
                weigh_only.add(key)
                continue
            identity_of[key] = group[name]
            continue
        creator[key] = e
        identity_of[key] = key
        group.setdefault(name, key)
    named = dict(identity_of)
    for e, key, target in updates:
        ident = named.get(target)
        first = creator.get(ident)
        if first is None or _entity_name(first) != _entity_name(e):
            declined.add(key)
        elif modules.get(key[0]) is not None:
            if first.get("node_id") != key[0]:
                declined.add(key)
            else:
                identity_of[key] = ident
        elif _link_authority(e, first, gov) != "hard":
            weigh_only.add(key)
        else:
            identity_of[key] = ident
    return declined, weigh_only, identity_of


# ── the module write policy (2.1; hive-mind-private #50) ───────────────────────────────────────────────────
# What a module device (one the owner admitted with `--module`) may journal, as pure functions of the module's
# name, the entry's type and its payload. A problem is `(http status, message, extra fields)`, or None.
# `hive_module_api` enforces it before it appends (and turns a problem into a 4xx), and the projection enforces the
# SAME functions on every module-carried entry (`_module_policy_declined`), so a peer that pushes a module's entry
# through `/sync/ingest` cannot land what the API would have refused, and the two cannot drift: there is one rule
# table (`vocabulary.MODULE_ENTRY_TYPES`, `check_module_name`, `REF_FIELDS`) and one set of readers of it. State the
# rule needs beyond the entry (the entity's creator, a link's ends, the signature, the quota) stays where that state
# is: `_entity_declined`, `resolve_link`, ingest, the API.

_MODULE_REF_WANT = {"pair": "a [node_id, seq] pair", "pairs": "a list of [node_id, seq] pairs",
                    "ref": "a [node_id, seq] pair or an `h:` short id"}
# Payload fields that name a local row id or a pre-1.19 reference. `rebuild_db` still projects them from an old
# journal, with no authority check, so a module may not carry them. The table is read from `REF_FIELDS`; the
# names listed are the ones the plan named, kept so a status change in the table cannot drop them.
_MODULE_LEGACY_REF_NAMES = ("supersedes_ref", "supersedes", "resolves_ref", "entity_ref", "fact_ref", "entity_id", "fact_id")
# field -> (what it must be, test); each is "absent or ..." and the projection binds it straight into SQLite
_MODULE_BOUND_FIELDS = {
    "importance": ("a number", lambda v: _is_number(v)), "confidence": ("a number", lambda v: _is_number(v)),
    "source_session": ("a string", lambda v: isinstance(v, str)), "created_at": ("a string", lambda v: isinstance(v, str)),
    "rationale": ("a string", lambda v: isinstance(v, str)),
    "access_count": ("an integer", lambda v: _is_int64(v)),
    "attributes": ("an object", lambda v: isinstance(v, dict)),
    "new_identity": ("a boolean", lambda v: isinstance(v, bool)),
}


def _module_legacy_ref_fields():
    return sorted(set(_MODULE_LEGACY_REF_NAMES) | {k for k, r in vocabulary.REF_FIELDS.items() if r["status"] == vocabulary.LEGACY})


def _module_type_problem(module, etype, payload):
    if etype not in vocabulary.MODULE_ENTRY_TYPES:
        return 403, f"a module may write {', '.join(vocabulary.MODULE_ENTRY_TYPES)}, not {etype!r}", {"field": "type"}
    return None


def _module_names_problem(module, etype, payload):
    """Every name the payload introduces is a core name a module may use or its own `x-<module>:` name (plan A4,
    reserved names): the source app and class, each tag. A fact whose source is `manual` is refused here."""
    source = payload.get("source")
    if not isinstance(source, str) or not source:
        return 400, "payload.source is required: a module's source is `x-<module>`", {}
    app, ctx, _inst, _sess = _parse_source(source)
    why = vocabulary.check_module_name(module, "source_apps", app)
    if why is None and ":" in source:
        why = vocabulary.check_module_name(module, "source_contexts", ctx)
    if why:
        return 403, why, {"field": "source"}
    if "channel" in payload and payload["channel"] not in vocabulary.CHANNEL_NAMES:
        return 400, "payload.channel must be one of " + ", ".join(vocabulary.CHANNEL_NAMES), {"got": payload["channel"]}
    tags = payload.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        return 400, "payload.tags must be a list of strings", {}
    for t in tags:
        why = vocabulary.check_module_name(module, "behaviour_tags", t)
        if why:
            return 403, why, {"field": "tags"}
    return None


def _module_fields_problem(module, etype, payload):
    """Refuse a legacy ref field, and a field the projection binds whose type SQLite cannot take (plan A4: a signed
    payload must not make `rebuild_db` raise). `type` is checked only on an entity, where it is the entity's type."""
    legacy = [k for k in _module_legacy_ref_fields() if k in payload]
    if legacy:
        return 400, "a module may not carry a legacy reference field; use a link entry", {"fields": legacy}
    for k, (want, ok) in _MODULE_BOUND_FIELDS.items():
        if k in payload and not ok(payload[k]):
            return 400, f"payload.{k} must be {want} or absent", {}
    if etype == "entity" and "type" in payload and not isinstance(payload["type"], str):
        return 400, "payload.type must be a string or absent", {}
    return None


def _module_shape_problem(module, etype, payload):
    if etype in ("fact", "decision", "idea") and not (isinstance(payload.get("content"), str) and payload["content"]):
        return 400, f"a {etype} needs payload.content, a non-empty string", {}
    if etype == "entity" and not (isinstance(payload.get("name"), str) and payload["name"]):
        return 400, "an entity needs payload.name, a non-empty string", {}
    return None


def _module_link_problem(module, etype, payload):
    """A link's kind is a core kind or `x-<module>:…`. A core kind carries the `from_ref`/`to_ref` pairs
    `resolve_link` reads, and a `data` object whose `confidence` and `polarity` the pass-2 readers
    (`_link_entity`, `_decision_evidence`) bind or dereference raw. A module's own kind carries the envelope's
    `from`/`to`, each a pair or an `h:` short id (shape-checked in the refs stage, resolved when a projection reads
    it). The link's ends are state, checked by the API (`shared-entity-link`) and `resolve_link`."""
    if etype != "link":
        return None
    kind = payload.get("kind")
    why = vocabulary.check_module_name(module, "link_kinds", kind) if isinstance(kind, str) else "payload.kind is required"
    if why:
        return (403 if isinstance(kind, str) else 400), why, {"field": "kind"}
    if kind == "same-as":
        return 403, "same-as-core-only", {"detail": "a join between a module's entity and a shared one is written by a "
                                          "device or the owner, never by a module", "field": "kind"}
    if kind in vocabulary.LINK_KINDS and "data" in payload:
        data = payload["data"]
        if not isinstance(data, dict):
            return 400, "payload.data must be an object or absent", {}
        for k in ("confidence", "polarity"):
            if k in data and not _is_number(data[k]):
                return 400, f"payload.data.{k} must be a number or absent", {}
    return None


def _module_ref_check(shape, v):
    if shape == "pair":
        return _valid_ref(v)
    if shape == "pairs":
        return isinstance(v, list) and all(_valid_ref(x) for x in v)
    if shape == "ref":
        return _valid_ref(v) or (isinstance(v, str) and bool(_SID_RE.match(v)))
    raise KeyError(f"REF_FIELDS shape {shape!r} has no module-gate check")


def _module_ref_rows(etype, payload):
    """The `REF_FIELDS` rows a module's `etype` entry must carry or may carry: (field, row, required)."""
    for k, r in vocabulary.REF_FIELDS.items():
        if r["status"] not in (vocabulary.WRITTEN, vocabulary.RESERVED) or etype not in r["types"]:
            continue
        if etype == "link":     # a core kind carries from_ref/to_ref, a module's own kind the envelope's from/to
            if (k in ("from_ref", "to_ref")) == (payload.get("kind") in vocabulary.LINK_KINDS):
                yield k, r, True
        else:
            yield k, r, False


def _module_refs_problem(module, etype, payload):
    """Shape-check every reference field a module may write, read from `REF_FIELDS` so a row added later is
    covered (or raises in `_module_ref_check`) without a hand-kept list."""
    for k, r, required in _module_ref_rows(etype, payload):
        if k not in payload and not required:
            continue
        if not _module_ref_check(r["shape"], payload.get(k)):
            return 400, f"payload.{k} must be {_MODULE_REF_WANT[r['shape']]}" + ("" if required else " or absent"), {}
    return None


_MODULE_POLICY_STAGES = (("type", _module_type_problem), ("names", _module_names_problem),
                         ("fields", _module_fields_problem), ("shape", _module_shape_problem),
                         ("link", _module_link_problem), ("refs", _module_refs_problem))


def _module_policy_problem(module, etype, payload, stages=None):
    """The first reason module `module` may not journal an `etype` entry with this `payload`, or None: the type
    allow-list (no `retract`, no `governance`), the names (no `manual` or `owner` source, no foreign `x-` name), the
    fields, the content, a link's kind and the reference fields. `stages` names a subset, in order, for the API
    (which checks state between them); the default is all of them. A payload that is not an object is a problem."""
    if not isinstance(payload, dict):
        return 400, "the payload must be an object", {}
    for name, fn in _MODULE_POLICY_STAGES:
        if stages is None or name in stages:
            problem = fn(module, etype, payload)
            if problem is not None:
                return problem
    return None


def _module_policy_declined(entries, gov):
    """The entries the projection does not apply because a module device carried them in breach of the write
    policy, as a set of (node_id, seq): the module marker (`gov["modules"]`) says whose entries are judged, as of the
    end of the journal, as `_entity_declined` reads it, and `_module_policy_problem` is the API's own gate. Governance
    is not content and is left to `_governance_state` (a module device neither votes nor proposes there). A rule
    that cannot be evaluated declines the entry: a module's entry is never kept for want of a verdict. Pure over the
    journal and governance, so every node declines the same entries."""
    modules = gov.get("modules") or {}
    if not modules:
        return set()
    declined = set()
    for e in entries:
        module = modules.get(e.get("node_id"))
        if module is None or e.get("type") == "governance":
            continue
        try:
            problem = _module_policy_problem(module, e.get("type"), e.get("payload"))
        except Exception:
            problem = (400, "unreadable", {})
        if problem is not None:
            declined.add((e.get("node_id"), e.get("seq")))
    return declined


_PASS1 = {
    "fact": persist_fact,
    "decision": persist_decision,
    "entity": persist_entity,
    "idea": persist_idea,          # 1.20
}


def persist_entry(conn, entry):
    """Pass 1: apply a row-producing journal entry (fact/decision/entity)."""
    fn = _PASS1.get(entry["type"])
    return fn(conn, entry) if fn else None


def _is_int64(v):
    """An int (not a bool) that SQLite can bind; anything wider raises OverflowError."""
    return isinstance(v, int) and not isinstance(v, bool) and -2**63 <= v < 2**63


def _valid_ref(ref):
    """A journal-identity ref is [node_id: str, seq: int64]. Anything else is skipped, not bound:
    a signed payload must never make rebuild_db raise on every node."""
    return isinstance(ref, (list, tuple)) and len(ref) == 2 \
        and isinstance(ref[0], str) and _is_int64(ref[1])


# --------------------------------------------------------------------------
# #205: the shape of the payload fields the projection binds or reads. ONE validator for every place an
# entry enters (`append_foreign_entries`, so sync and the module route; `append_journal`, the local
# writers), and the same table drives the projection's fallbacks, so a bad value that is already in a
# journal (a journal is permanent; refusing at ingest cannot remove it) is defaulted or skipped and never
# makes `rebuild_db` or a reader raise. An absent field, or an explicit null, is always acceptable.
# --------------------------------------------------------------------------

def _is_number(v):
    """A finite int or float (not a bool): what SQLite binds and what arithmetic can use. Never raises. An int
    beyond int64 is refused (not stored as a float): SQLite cannot bind it and `float()` may overflow on it."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return -2**63 <= v < 2**63
    return isinstance(v, float) and math.isfinite(v)


def _is_str(v):
    return isinstance(v, str)


def _is_tags(v):
    return isinstance(v, list) and all(isinstance(t, str) for t in v)


def _is_pairs(v):
    return isinstance(v, list) and all(_valid_ref(r) for r in v)


# type -> {field: (check, default)}. `required` fields have no default: an entry without one projects to nothing.
_PAYLOAD_SHAPES = {
    "fact": {"content": (_is_str, None), "tags": (_is_tags, []), "importance": (_is_number, 0.5),
             "confidence": (_is_number, None), "source": (_is_str, "manual"), "source_session": (_is_str, None),
             "created_at": (_is_str, None), "access_count": (_is_int64, 0)},
    "decision": {"content": (_is_str, None), "rationale": (_is_str, None), "source": (_is_str, "manual"),
                 "created_at": (_is_str, None), "tags": (_is_tags, []), "informed_by": (_is_pairs, []),
                 "revokes": (_valid_ref, None)},
    "idea": {"content": (_is_str, None), "tags": (_is_tags, []), "source": (_is_str, "manual"),
             "source_session": (_is_str, None), "created_at": (_is_str, None)},
    "entity": {"name": (_is_str, None), "type": (_is_str, "unknown"), "attributes": (lambda v: isinstance(v, dict), {}),
               "created_at": (_is_str, None),
               "identity_ref": (_valid_ref, None), "new_identity": (lambda v: isinstance(v, bool), None)},   # 3.0, §4.2
    "entity_fact": {"confidence": (_is_number, 1.0)},
    "link": {"kind": (_is_str, None), "from_ref": (_valid_ref, None), "to_ref": (_valid_ref, None),
             "channel": (_is_str, None), "source": (_is_str, "manual")},
    "retract": {"retracts_ref": (_valid_ref, None), "unretracts_ref": (_valid_ref, None)},
}
_PAYLOAD_EXTRA = {"link": None}       # type -> a check beyond the field shapes (set below)
_PAYLOAD_REQUIRED = {"fact": ("content",), "decision": ("content",), "idea": ("content",), "entity": ("name",)}


def _link_data_problem(p):
    """A core link kind's `data` is an object or absent, and `data.confidence` / `data.polarity` are finite
    numbers or absent: pass 2 binds the first and does arithmetic on the second. A module kind's `data` is its own."""
    if p.get("kind") not in _LINK_RESOLVERS:
        return None
    data = p.get("data")
    if data is None:
        return None
    if not isinstance(data, dict):
        return "data is not an object"
    for k in ("confidence", "polarity"):
        if data.get(k) is not None and not _is_number(data[k]):
            return f"data.{k} is not a finite number"
    return None


_PAYLOAD_EXTRA["link"] = _link_data_problem


def _payload_problem(entry):
    """Why this entry's payload cannot be projected safely, or None. Pure over the entry; the entry types
    that produce rows or edges are checked, every other type passes."""
    typ = entry.get("type")
    shapes = _PAYLOAD_SHAPES.get(typ)
    if shapes is None:
        return None
    p = entry.get("payload")
    if not isinstance(p, dict):
        return "payload is not an object"
    for field in _PAYLOAD_REQUIRED.get(typ, ()):
        if field not in p:
            return f"{field} is missing"
    for field, (check, _default) in shapes.items():
        if p.get(field) is not None and not check(p[field]):
            return f"{field} has the wrong shape"
        if p.get(field) is None and field in _PAYLOAD_REQUIRED.get(typ, ()):
            return f"{field} is missing"
    extra = _PAYLOAD_EXTRA.get(typ)
    return extra(p) if extra else None


def _payload_field(entry, field):
    """The value of a payload field for the projection: the stored value when it has the right shape,
    else the field's default (the entry still projects). A mismatch is recorded in `_PROJECTION_NOTES`."""
    check, default = _PAYLOAD_SHAPES[entry["type"]][field]
    v = (entry.get("payload") or {}).get(field)
    if v is None:
        return default
    if check(v):
        return v
    _PROJECTION_NOTES.append(f"{entry.get('node_id')}:{entry.get('seq')} {entry['type']}.{field}: defaulted")
    return default


def _hostile_number(v):
    """An int or float no honest writer produces: an int beyond int64 (SQLite cannot bind it, `float()` may
    overflow on it), or a NaN / inf. A bool, a string or a list is an ordinary shape mistake, not this."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return not -2**63 <= v < 2**63
    return isinstance(v, float) and not math.isfinite(v)


def _hostile_problem(entry):
    """The first number field of this entry holding a hostile value, or None (#205). Such an entry is refused at
    ingest and skipped whole by the projection: it is not defaulted, because only a hostile or broken writer
    produces it."""
    p = entry.get("payload")
    shapes = _PAYLOAD_SHAPES.get(entry.get("type"))
    if shapes is None or not isinstance(p, dict):
        return None
    for field, (check, _default) in shapes.items():
        if check in (_is_number, _is_int64) and _hostile_number(p.get(field)):
            return f"{field} is not a finite number within int64"
    extra = _HOSTILE_EXTRA.get(entry.get("type"))
    return extra(p) if extra else None


def _link_data_hostile(p):
    """A core link kind's `data.confidence` / `data.polarity` holding a hostile number, or None."""
    data = p.get("data")
    if p.get("kind") in _LINK_RESOLVERS and isinstance(data, dict):
        for k in ("confidence", "polarity"):
            if _hostile_number(data.get(k)):
                return f"data.{k} is not a finite number within int64"
    return None


_HOSTILE_EXTRA = {"link": _link_data_hostile}


def _unprojectable(entry):
    """Why this entry projects to nothing, or None: the payload is not an object, a required field has the
    wrong shape, or a number field holds a hostile value. Pure; `_projectable` records the skip."""
    p = entry.get("payload")
    if not isinstance(p, dict) or not all(isinstance(p.get(f), str) for f in _PAYLOAD_REQUIRED.get(entry.get("type"), ())):
        return "payload is not an object or a required field has the wrong shape"
    return _hostile_problem(entry)


def _projectable(entry):
    """False, and the skip recorded, when the entry projects to nothing (`_unprojectable`)."""
    if _unprojectable(entry) is None:
        return True
    _PROJECTION_NOTES.append(f"{entry.get('node_id')}:{entry.get('seq')} {entry.get('type')}: skipped")
    return False


def _projection_entries(journal, note=False):
    """The journal entries the projection reads: those of a shaped type that project to something (#205). The
    one filter for `rebuild_db` and the live writers (`remember`, `decide`, `link`), so an incremental write
    and a full rebuild agree on a hostile entry already on disk. `note` records each skip for `rebuild_db`."""
    gov = _governance_state(journal)
    journal = _ts_unskipped(journal, gov)    # #217: the timestamp bounds skip an entry for every type
    journal = _admitted_content(journal, gov)
    refused = _module_policy_declined(journal, gov)     # 2.1 (#50): what the module write policy would have refused
    if refused:
        journal = [e for e in journal if (e.get("node_id"), e.get("seq")) not in refused]
    return [e for e in journal if e["type"] not in _PAYLOAD_SHAPES
            or (_projectable(e) if note else _unprojectable(e) is None)]


_PROJECTION_NOTES = []     # what the last projection defaulted or skipped (reset by `rebuild_db`)


def _clean_refs(raw):
    """The valid `[node_id, seq]` pairs in a stored `informed_by` (JSON text or a list): a reader skips a
    malformed item or value instead of raising."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return []
    return [list(r) for r in raw if _valid_ref(r)] if isinstance(raw, list) else []


def _resolve_ref(conn, ref):
    """Map a journal-identity reference [node_id, seq] to a local row id. A string never binds: binding an `h:`
    short id on one node only would make two nodes project one journal two ways."""
    if not _valid_ref(ref):
        return None
    r = conn.execute(
        "SELECT local_id FROM journal_index WHERE node_id = ? AND seq = ?",
        (ref[0], ref[1]),
    ).fetchone()
    return r["local_id"] if r else None


def _ref_or_legacy_id(conn, p, ref_key, legacy_key, kind, table):
    """The local id of the `kind` row a payload points at: its journal-identity ref, else the legacy
    local-id field (pre-Phase-2). None when the target is absent, of another kind, or not a row on this node."""
    if p.get(ref_key):
        row = _index_row(conn, p.get(ref_key))
        return row[1] if row and row[0] == kind else None
    lid = p.get(legacy_key)
    if _is_int64(lid) \
            and conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (lid,)).fetchone():
        return lid
    return None


def resolve_entity_fact(conn, entry, gov=None):
    """Pass 2: wire an entity_fact link via journal-identity refs (falling back
    to legacy local-id fields for pre-Phase-2 journals). A pair it cannot wire
    (a target absent, of the wrong kind, or no such local id) is skipped. 2.1 (#208): the legacy form of a
    link, which a module may not write, so a module-signed `entity_fact` wires nothing. It attaches a fact to
    its own entity with a `link` of kind `entity`."""
    p = entry["payload"]
    eid = _ref_or_legacy_id(conn, p, "entity_ref", "entity_id", "entity", "entities")
    fid = _ref_or_legacy_id(conn, p, "fact_ref", "fact_id", "fact", "facts")
    if eid is None or fid is None:
        return
    if gov is not None and _module_of(gov, entry) is not None:
        return
    conn.execute(
        "INSERT OR REPLACE INTO entity_facts (entity_id, fact_id, confidence) VALUES (?, ?, ?)",
        (eid, fid, p.get("confidence") if _is_number(p.get("confidence")) else 1.0),
    )


def _legacy_authority(conn, entry, kind, target_id, gov, by_ref, ref=None):
    """#204: the verdict `_link_authority` gives a pre-1.19 `supersedes_ref` / `supersedes` / `resolves_ref`
    payload field, read as a link from the entry to its target. It commands only when the owner key signed
    it or its signer wrote the target; otherwise the field does nothing. A target with no journal identity
    on this node is evidence. `ref` is the payload's journal-identity ref when it has one: judge that entry, because
    rows are shared by identical content and a reverse lookup of the row could name a different writer's entry.
    Only the local-id `supersedes` falls back to the row lookup. Returns "hard" or "evidence"."""
    if "sig" in entry and not _verify_entry(entry):
        return "evidence"
    if not (isinstance(ref, (list, tuple)) and _valid_ref(ref)):
        ref = _index_lookup(conn, kind, target_id)
    target = by_ref.get(tuple(ref)) if ref else None
    return _link_authority(entry, target, gov)


def resolve_supersedes(conn, entry, gov, by_ref):
    """Pass 2: mark the decision this entry supersedes (by journal identity, falling back to a legacy
    local-id field), when `_legacy_authority` says the entry may command it (#204)."""
    p = entry["payload"]
    old = _ref_or_legacy_id(conn, p, "supersedes_ref", "supersedes", "decision", "decisions")
    if not old:
        return
    new = _resolve_ref(conn, [entry.get("node_id"), entry.get("seq")])
    if new is None:
        return
    if _legacy_authority(conn, entry, "decision", old, gov, by_ref, p.get("supersedes_ref")) != "hard":
        return
    conn.execute("UPDATE decisions SET superseded_by = ? WHERE id = ?", (new, old))


def resolve_resolves(conn, entry, gov, by_ref):
    """Pass 2: record on the NEW fact row which prior fact it resolves (`facts.resolves`
    -> the resolved fact's local id). The actual confidence effect rides on the separate
    `retract` entry `remember --resolves` emits; this link is provenance ("what did fact X
    resolve") and lets the audit/search show the chain. New-row direction, unlike decision
    supersedes which marks the old row. The target must be a fact, and the entry must pass
    `_legacy_authority` (#204)."""
    p = entry["payload"]
    row = _index_row(conn, p.get("resolves_ref"))
    if row is None or row[0] != "fact":
        return
    old = row[1]
    new = _resolve_ref(conn, [entry.get("node_id"), entry.get("seq")])
    if new is None:
        return
    if _legacy_authority(conn, entry, "fact", old, gov, by_ref, p.get("resolves_ref")) != "hard":
        return
    conn.execute("UPDATE facts SET resolves = ? WHERE id = ?", (old, new))


