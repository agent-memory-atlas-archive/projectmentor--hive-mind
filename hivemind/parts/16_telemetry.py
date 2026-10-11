# --------------------------------------------------------------------------
# Telemetry — a LOCAL-ONLY observability lane, deliberately OUTSIDE the journal
# --------------------------------------------------------------------------
# Session telemetry (who/where/when + token usage + cost) is observability, NOT
# knowledge. It must never enter the facts journal/merkle: that would pollute the
# corpus, inflate confidence, and sync as "knowledge". So it lives in its own
# SQLite file under .telemetry/ that `hv doctor rebuild` never touches and sync never sees.
# node_id is part of the primary key, so per-node stores are non-colliding shards
# that a future release can union for cross-node aggregation with no schema change.

TELEMETRY_DIR = HIVE_HOME / ".telemetry"
TELEMETRY_DB = TELEMETRY_DIR / "telemetry.db"

# Best-effort default pricing ($ per 1M tokens). Override per-node via
# .telemetry/pricing.json: {"model": {"in":N,"out":N,"cache_read":N,"cache_creation":N}}.
# cache_read defaults to ~0.1x input, cache_creation to ~1.25x input (Anthropic ratios).
_TELEMETRY_PRICES = {
    "claude-opus-4-8":   {"in": 15.0, "out": 75.0},
    "claude-sonnet-4-6": {"in": 3.0,  "out": 15.0},
    "claude-haiku-4-5":  {"in": 1.0,  "out": 5.0},
}


def telemetry_conn():
    """Open (and lazily create) the local-only telemetry DB. Separate file from store.db so
    `hv doctor rebuild` never wipes it and sync never sees it."""
    TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(TELEMETRY_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    init_telemetry_db(conn)
    return conn


def init_telemetry_db(conn):
    """Idempotent telemetry schema. One row per session, keyed by the composite identity so two
    same-named agents (e.g. two `hermes`) never collapse, and so node shards merge cleanly later."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS telemetry_sessions (
        node_id        TEXT NOT NULL,
        session_id     TEXT NOT NULL,
        agent          TEXT NOT NULL,
        agent_identity TEXT NOT NULL DEFAULT '',
        os_user        TEXT,
        ip             TEXT,
        project        TEXT,
        cwd            TEXT,
        started_at     TEXT,
        ended_at       TEXT,
        duration_s     REAL,
        tokens_in      INTEGER DEFAULT 0,
        tokens_out     INTEGER DEFAULT 0,
        cache_read     INTEGER DEFAULT 0,
        cache_creation INTEGER DEFAULT 0,
        cost_usd       REAL,
        models         TEXT,
        updated_at     TEXT,
        PRIMARY KEY (node_id, session_id, agent, agent_identity)
    );
    CREATE INDEX IF NOT EXISTS idx_tel_started ON telemetry_sessions(started_at);
    CREATE INDEX IF NOT EXISTS idx_tel_project ON telemetry_sessions(project);
    """)
    conn.commit()


def _node_ip():
    """Best-effort machine IP for telemetry: prefer the Tailscale IP, else the first `hostname -I`
    address, else ''. Never raises."""
    for cmd in (["tailscale", "ip", "-4"], ["hostname", "-I"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            if out.returncode == 0 and out.stdout.split():
                return out.stdout.split()[0].strip()
        except Exception:
            continue
    return ""


def _os_user():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def _project_for(cwd):
    """Project key: git remote basename, else cwd basename."""
    cwd = cwd or os.getcwd()
    try:
        out = subprocess.run(["git", "-C", cwd, "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=4)
        if out.returncode == 0 and out.stdout.strip():
            base = out.stdout.strip().rstrip("/").split("/")[-1]
            return base[:-4] if base.endswith(".git") else base
    except Exception:
        pass
    return Path(cwd).name


def _locate_transcript(session_id, explicit=""):
    """Find the Claude Code transcript jsonl for a session id (or honor an explicit path)."""
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    if not session_id:
        return None
    try:
        hits = list((Path.home() / ".claude" / "projects").glob(f"*/{session_id}.jsonl"))
        return hits[0] if hits else None
    except Exception:
        return None


def _sum_transcript_usage(path):
    """Sum message.usage per model from a transcript jsonl. Returns {model: {in,out,cache_read,
    cache_creation}}. Best-effort; skips the synthetic model and malformed lines."""
    models = {}
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                msg = o.get("message") or {}
                u = msg.get("usage") or {}
                model = msg.get("model") or ""
                if not u or not model or model == "<synthetic>":
                    continue
                m = models.setdefault(model, {"in": 0, "out": 0, "cache_read": 0, "cache_creation": 0})
                m["in"] += int(u.get("input_tokens", 0) or 0)
                m["out"] += int(u.get("output_tokens", 0) or 0)
                m["cache_read"] += int(u.get("cache_read_input_tokens", 0) or 0)
                m["cache_creation"] += int(u.get("cache_creation_input_tokens", 0) or 0)
    except Exception:
        pass
    return models


def _telemetry_prices():
    prices = {k: dict(v) for k, v in _TELEMETRY_PRICES.items()}
    try:
        f = TELEMETRY_DIR / "pricing.json"
        if f.is_file():
            prices.update(json.loads(f.read_text()))
    except Exception:
        pass
    return prices


def _estimate_cost(models):
    """Best-effort $ estimate from a {model: {in,out,...}} breakdown. Returns (total or None,
    models_with_cost). Unknown models contribute nothing; total is None if NOTHING was priced."""
    prices = _telemetry_prices()
    total, priced = 0.0, False
    out = {}
    for model, t in (models or {}).items():
        entry = dict(t)
        p = prices.get(model)
        if p:
            cin = p.get("in", 0.0)
            c = (t.get("in", 0) * cin
                 + t.get("out", 0) * p.get("out", 0.0)
                 + t.get("cache_read", 0) * p.get("cache_read", cin * 0.1)
                 + t.get("cache_creation", 0) * p.get("cache_creation", cin * 1.25)) / 1_000_000.0
            entry["cost"] = round(c, 4)
            total += c
            priced = True
        out[model] = entry
    return (round(total, 4) if priced else None), out


def telemetry_cmd(args):
    """Local-only observability lane. Best-effort: never raises, never blocks a caller."""
    action = getattr(args, "telemetry_action", None)
    try:
        if action == "record":
            _telemetry_record(args)
        elif action == "list":
            _telemetry_list(args)
        else:
            _telemetry_report(args)   # default
    except Exception:
        pass


def _telemetry_record(args):
    now = _now_iso()
    node, sid = NODE_ID, (args.session or "_anon")
    agent, ident = (args.agent or "agent"), (args.identity or "")
    key = (node, sid, agent, ident)
    cwd = args.cwd or os.getcwd()
    conn = telemetry_conn()
    conn.execute(
        "INSERT OR IGNORE INTO telemetry_sessions (node_id, session_id, agent, agent_identity, "
        "os_user, ip, project, cwd, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (node, sid, agent, ident, _os_user(), _node_ip(), _project_for(cwd), cwd, now))
    if args.event == "start":
        conn.execute("UPDATE telemetry_sessions SET started_at=COALESCE(started_at, ?), updated_at=? "
                     "WHERE node_id=? AND session_id=? AND agent=? AND agent_identity=?", (now, now, *key))
    elif args.event == "end":
        r = conn.execute("SELECT started_at FROM telemetry_sessions WHERE node_id=? AND session_id=? "
                         "AND agent=? AND agent_identity=?", key).fetchone()
        a = _to_dt(r["started_at"]) if (r and r["started_at"]) else None
        b = _to_dt(now)
        dur = max(0.0, (b - a).total_seconds()) if (a and b) else None
        tp = _locate_transcript(sid, getattr(args, "transcript", "") or "")
        models = _sum_transcript_usage(tp) if tp else {}
        cost, models_cost = _estimate_cost(models)
        conn.execute(
            "UPDATE telemetry_sessions SET ended_at=?, duration_s=?, tokens_in=?, tokens_out=?, "
            "cache_read=?, cache_creation=?, cost_usd=?, models=?, updated_at=? "
            "WHERE node_id=? AND session_id=? AND agent=? AND agent_identity=?",
            (now, dur,
             sum(m["in"] for m in models.values()), sum(m["out"] for m in models.values()),
             sum(m["cache_read"] for m in models.values()), sum(m["cache_creation"] for m in models.values()),
             cost, json.dumps(models_cost), now, *key))
    conn.commit()
    conn.close()


def _parse_since(s):
    """'7d'|'24h'|'30m'|'2w' -> ISO cutoff (UTC), or '' for all-time. Best-effort."""
    s = (s or "").strip().lower()
    if not s:
        return ""
    try:
        from datetime import timedelta
        hours = {"d": 24, "h": 1, "w": 168, "m": 1 / 60.0}[s[-1]]
        cut = datetime.now(timezone.utc) - timedelta(hours=int(s[:-1]) * hours)
        return cut.isoformat(timespec="milliseconds")
    except Exception:
        return ""


def _telemetry_rows(since=""):
    conn = telemetry_conn()
    q = "SELECT * FROM telemetry_sessions"
    p = ()
    if since:
        q += " WHERE COALESCE(started_at, updated_at) >= ?"
        p = (since,)
    q += " ORDER BY COALESCE(started_at, updated_at) DESC"
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return rows


def _fmt_dur(s):
    if not s:
        return "-"
    s = int(s)
    h, m = s // 3600, (s % 3600) // 60
    return f"{h}h{m:02d}m" if h else f"{m}m"


def _fmt_cost(c):
    return f"~${c:,.2f}" if c is not None else "n/a"


def _telemetry_report(args):
    since = _parse_since(getattr(args, "since", "") or "")
    by = getattr(args, "by", None)
    rows = _telemetry_rows(since)
    tot = {"sessions": len(rows), "dur": 0.0, "in": 0, "out": 0, "cost": 0.0, "priced": False}
    permodel, groups = {}, {}
    for r in rows:
        tot["dur"] += r["duration_s"] or 0
        tot["in"] += r["tokens_in"] or 0
        tot["out"] += r["tokens_out"] or 0
        if r["cost_usd"] is not None:
            tot["cost"] += r["cost_usd"]; tot["priced"] = True
        try:
            mm = json.loads(r["models"]) if r["models"] else {}
        except Exception:
            mm = {}
        for model, t in mm.items():
            pm = permodel.setdefault(model, {"in": 0, "out": 0, "cost": 0.0, "priced": False})
            pm["in"] += t.get("in", 0); pm["out"] += t.get("out", 0)
            if "cost" in t:
                pm["cost"] += t["cost"]; pm["priced"] = True
        if by in ("project", "agent", "node"):
            k = (r["project"] if by == "project" else
                 (f'{r["agent"]}:{r["agent_identity"]}'.rstrip(":") if by == "agent" else r["node_id"])) or "(unknown)"
            g = groups.setdefault(k, {"sessions": 0, "dur": 0.0, "in": 0, "out": 0, "cost": 0.0, "priced": False})
            g["sessions"] += 1; g["dur"] += r["duration_s"] or 0
            g["in"] += r["tokens_in"] or 0; g["out"] += r["tokens_out"] or 0
            if r["cost_usd"] is not None:
                g["cost"] += r["cost_usd"]; g["priced"] = True

    if getattr(args, "format", "text") == "json":
        print(json.dumps({"since": since or "all", "node": NODE_ID, "totals": tot,
                          "by_model": permodel, "by": by, "groups": groups}, indent=2, default=str))
        return
    print(f"hive telemetry — {('since ' + getattr(args, 'since', '')) if since else 'all time'}  (node: {NODE_ID})")
    print(f"  sessions: {tot['sessions']}   time: {_fmt_dur(tot['dur'])}   "
          f"tokens: {tot['in']:,} in / {tot['out']:,} out   cost: {_fmt_cost(tot['cost'] if tot['priced'] else None)}")
    for model, pm in sorted(permodel.items(), key=lambda kv: -(kv[1]['in'] + kv[1]['out'])):
        print(f"    {model:22s} {pm['in']:>12,} in / {pm['out']:>10,} out   {_fmt_cost(pm['cost'] if pm['priced'] else None)}")
    if by in ("project", "agent", "node") and groups:
        print(f"  by {by}:")
        for k, g in sorted(groups.items(), key=lambda kv: -kv[1]['cost']):
            print(f"    {k:24s} {g['sessions']} sess  {_fmt_dur(g['dur'])}  {_fmt_cost(g['cost'] if g['priced'] else None)}")
    if not rows:
        print("  (no telemetry recorded yet)")


def _telemetry_list(args):
    rows = _telemetry_rows("")[:(getattr(args, "limit", 0) or 20)]
    if not rows:
        print("(no telemetry recorded yet)")
        return
    for r in rows:
        who = f'{r["agent"]}:{r["agent_identity"]}'.rstrip(":")
        print(f'{(r["started_at"] or r["updated_at"] or "")[:19]}  {who}  {r["project"] or "-"}  '
              f'{_fmt_dur(r["duration_s"])}  {r["tokens_in"] or 0}/{r["tokens_out"] or 0} tok  '
              f'{_fmt_cost(r["cost_usd"])}  [{r["node_id"]}]')


