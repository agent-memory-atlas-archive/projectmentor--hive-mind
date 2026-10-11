# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

# How long a connection waits for another writer's lock before `database is locked` (#70). Python's default
# is 5 s; writes take well under a second, so 10 s rides out any normal overlap. Env override for tests.
_BUSY_TIMEOUT_S = float(os.environ.get("HIVE_BUSY_TIMEOUT_MS", "10000")) / 1000.0


def get_conn():
    """Open a tuned SQLite connection. WAL persists on the file; the rest are
    per-connection, so we apply them on every open."""
    conn = sqlite3.connect(DB_PATH, timeout=_BUSY_TIMEOUT_S)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")      # 64MB page cache
    conn.execute("PRAGMA mmap_size=268435456")    # 256MB mmap
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


_ENTITY_DDL = """
    CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,   -- a label (3.0), not unique: the identity is (ref_node, ref_seq)
        type TEXT, -- person, project, concept
        attributes TEXT, -- JSON
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP,
        ref_node TEXT,        -- 3.0: the identity, the journal ref of the entry that created the entity
        ref_seq INTEGER,
        UNIQUE (ref_node, ref_seq)
    );

    CREATE TABLE IF NOT EXISTS entity_facts (
        entity_id INTEGER REFERENCES entities(id),
        fact_id INTEGER REFERENCES facts(id),
        confidence REAL DEFAULT 1.0,
        PRIMARY KEY (entity_id, fact_id)
    );

    CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
    CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

    -- Maps a journal entry's identity to the row it produced. Lets cross-row
    -- links (entity_fact, decision supersedes) reference (node_id, seq) and
    -- resolve to whatever local id THIS node assigned on its last rebuild.
    CREATE TABLE IF NOT EXISTS journal_index (
        node_id  TEXT NOT NULL,
        seq      INTEGER NOT NULL,
        kind     TEXT NOT NULL,        -- fact | decision | entity | idea (1.20)
        local_id INTEGER NOT NULL,
        sid      TEXT,                 -- 1.19 PR3b: `h:` + sha256("node_id:seq")[:10], the human-stable id
        PRIMARY KEY (node_id, seq)
    );
    CREATE INDEX IF NOT EXISTS idx_jidx_local ON journal_index(kind, local_id);

    -- 1.19: generic edge table projected from `link` journal entries (rebuilt every time, never
    -- migrated). `authority` is the projection's §5 verdict: `hard` (owner-signed at that position,
    -- or the target's author — the link COMMANDS) vs `evidence` (any other admitted device — the
    -- link only WEIGHS). The bespoke columns (facts.resolves, decisions.superseded_by, entity_facts)
    -- stay as the 1.11/1.15 read paths; this table is the generic provenance view.
    CREATE TABLE IF NOT EXISTS links (
        kind       TEXT NOT NULL,
        from_kind  TEXT NOT NULL,
        from_id    INTEGER NOT NULL,
        to_kind    TEXT NOT NULL,
        to_id      INTEGER NOT NULL,
        signer     TEXT NOT NULL,        -- node_id of the (verified) link entry
        authority  TEXT NOT NULL,        -- hard | evidence
        channel    TEXT,                 -- sense | act | introspect (absent = sense)
        created_at TIMESTAMP,
        PRIMARY KEY (kind, from_kind, from_id, to_kind, to_id, signer)
    );
    CREATE INDEX IF NOT EXISTS idx_links_to ON links(to_kind, to_id, kind);
"""


# The store's schema version (`meta.schema_version`). 3 (3.0): `entities` is keyed by the creating entry's journal
# ref and `name` is a non-unique label. `CREATE TABLE IF NOT EXISTS` cannot alter a table, so a store without
# version 3 has the entity-bearing tables dropped and is rebuilt from the journal, which loses nothing: the store
# is a projection.
STORE_SCHEMA_VERSION = "3"


class NewerStoreSchema(Exception):
    """store.db carries a `schema_version` newer than this `hv` reads: another, newer `hv` wrote it."""
    def __init__(self, found):
        self.found = found
        super().__init__(
            f"store.db was written by a newer schema ({found}); this hv reads schema {STORE_SCHEMA_VERSION}. "
            f"Update hv, or run `hv doctor rebuild` to build a fresh store from the journal")


def _newer_store_schema():
    """The `schema_version` of an existing store.db when it is newer than `STORE_SCHEMA_VERSION`, else None.
    Reads only `meta`: a newer store's other tables may not be shaped as this `hv` expects."""
    if not DB_PATH.exists():
        return None
    try:
        conn = get_conn()
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        finally:
            conn.close()
        return row[0] if row and int(row[0]) > int(STORE_SCHEMA_VERSION) else None
    except (sqlite3.Error, ValueError, TypeError):
        return None


def _ddl_statements(ddl):
    """Split a DDL script into statements, so they can run inside a transaction (`executescript` commits)."""
    out, cur = [], ""
    for line in ddl.splitlines(keepends=True):
        cur += line
        if sqlite3.complete_statement(cur):
            if cur.strip():
                out.append(cur)
            cur = ""
    return out


def _migrate_store_schema(conn):
    """One-time, idempotent, ATOMIC: a store not at `STORE_SCHEMA_VERSION` has `entity_facts`, `entities`, `links`
    and `journal_index` dropped, recreated and refilled from the journal in ONE transaction, and only then is
    `schema_version` stamped. Every command reaches this through `init_db`, so none (doctor, version, sync, the
    daemon) can see a store with the tables gone; a crash rolls back to the old tables and the old version, and
    the next `init_db` migrates again. Runs after every other table exists. A store already in the new shape
    (a fresh one) is only stamped. Loses nothing: the store is a projection."""
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if row and row[0] == STORE_SCHEMA_VERSION:
        return
    conn.commit()
    stamp = "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)"
    if "ref_node" in {r[1] for r in conn.execute("PRAGMA table_info(entities)")}:
        conn.execute(stamp, (STORE_SCHEMA_VERSION,))
        conn.commit()
        return
    try:
        conn.execute("BEGIN IMMEDIATE")
        for t in ("entity_facts", "links", "entities", "journal_index"):
            conn.execute(f"DROP TABLE IF EXISTS {t}")
        for stmt in _ddl_statements(_ENTITY_DDL):
            conn.execute(stmt)
        _rebuild_in_transaction(conn, begun=True)
        conn.execute(stamp, (STORE_SCHEMA_VERSION,))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    _prune_ended_peers_after_rebuild()


def init_db():
    """Initialize database schema (idempotent)."""
    HIVE_HOME.mkdir(parents=True, exist_ok=True)
    JOURNAL_DIR.mkdir(exist_ok=True)
    newer = _newer_store_schema()
    if newer:
        raise NewerStoreSchema(newer)

    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS facts (
        id INTEGER PRIMARY KEY,
        content TEXT NOT NULL,
        tags TEXT,
        importance REAL DEFAULT 0.5,
        source_agent TEXT NOT NULL,
        source_session TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed TIMESTAMP,
        access_count INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0.0
    );

    CREATE TABLE IF NOT EXISTS decisions (
        id INTEGER PRIMARY KEY,
        content TEXT NOT NULL,
        rationale TEXT,
        superseded_by INTEGER REFERENCES decisions(id),
        source_agent TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        tags TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_facts_tags ON facts(tags);
    CREATE INDEX IF NOT EXISTS idx_facts_source ON facts(source_agent, created_at);
    CREATE INDEX IF NOT EXISTS idx_decisions_active ON decisions(id) WHERE superseded_by IS NULL;

    """)
    conn.executescript(_ENTITY_DDL)
    conn.executescript("""
    -- 1.20: ideas — hypotheses whose confidence is EARNED from links (never asserted, never
    -- corroborated by restatement). facts minus importance/access_count/last_accessed, plus utility.
    -- Two identical idea texts are two rows: identity is the journal entry, not the content.
    CREATE TABLE IF NOT EXISTS ideas (
        id INTEGER PRIMARY KEY,
        content TEXT NOT NULL,
        tags TEXT,
        source_agent TEXT NOT NULL,
        source_session TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confidence REAL DEFAULT 0.0,
        contested INTEGER DEFAULT 0,
        last_evidence_at TIMESTAMP,
        utility REAL DEFAULT 0.0,
        importance REAL DEFAULT 0.0,   -- 1.19 PR6: projection-written (no asserted prior for an idea)
        last_link_at TIMESTAMP         -- 1.19 PR6: most recent other-identity inbound link (query-time decay)
    );
    CREATE INDEX IF NOT EXISTS idx_ideas_created ON ideas(created_at);
    """)
    conn.commit()

    # Migration: add derived columns to pre-existing facts tables
    # (CREATE TABLE IF NOT EXISTS won't alter an existing table).
    fcols = {r[1] for r in conn.execute("PRAGMA table_info(facts)")}
    if "confidence" not in fcols:
        conn.execute("ALTER TABLE facts ADD COLUMN confidence REAL DEFAULT 0.0")
    if "contested" not in fcols:               # Phase C: genuine disagreement (support AND dispute)
        conn.execute("ALTER TABLE facts ADD COLUMN contested INTEGER DEFAULT 0")
    if "last_evidence_at" not in fcols:        # Phase C: most-recent evidence ts (drives decay)
        conn.execute("ALTER TABLE facts ADD COLUMN last_evidence_at TIMESTAMP")
    if "resolves" not in fcols:                # 1.11: local id of the fact this row resolves/closes
        conn.execute("ALTER TABLE facts ADD COLUMN resolves INTEGER")
    dcols = {r[1] for r in conn.execute("PRAGMA table_info(decisions)")}
    if "tags" not in dcols:                     # 1.15: project/topic tags on a decision (JSON list)
        conn.execute("ALTER TABLE decisions ADD COLUMN tags TEXT")
    if "informed_by" not in dcols:              # 1.19 PR3: journal refs the decision relied on (JSON list)
        conn.execute("ALTER TABLE decisions ADD COLUMN informed_by TEXT")
    if "outcome_score" not in dcols:            # 1.19 PR4: vindication axis (NOT confidence) — projection-written
        conn.execute("ALTER TABLE decisions ADD COLUMN outcome_score REAL DEFAULT 0.0")
    if "last_outcome_at" not in dcols:          # 1.19 PR4: most-recent sense-channel outcome (drives decay)
        conn.execute("ALTER TABLE decisions ADD COLUMN last_outcome_at TIMESTAMP")
    if "utility" not in fcols:
        conn.execute("ALTER TABLE facts ADD COLUMN utility REAL DEFAULT 0.0")          # 1.19 PR6
    if "last_link_at" not in fcols:
        conn.execute("ALTER TABLE facts ADD COLUMN last_link_at TIMESTAMP")            # 1.19 PR6
    icols = {r[1] for r in conn.execute("PRAGMA table_info(ideas)")}
    if icols and "importance" not in icols:
        conn.execute("ALTER TABLE ideas ADD COLUMN importance REAL DEFAULT 0.0")       # 1.19 PR6
    if icols and "last_link_at" not in icols:
        conn.execute("ALTER TABLE ideas ADD COLUMN last_link_at TIMESTAMP")            # 1.19 PR6
    jcols = {r[1] for r in conn.execute("PRAGMA table_info(journal_index)")}
    if "sid" not in jcols:
        conn.execute("ALTER TABLE journal_index ADD COLUMN sid TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jidx_sid ON journal_index(sid)")
    conn.commit()
    # Index created here (not in the schema script above) so it works on both
    # fresh and migrated DBs — the column is guaranteed to exist by this point.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_confidence ON facts(confidence)")
    conn.commit()

    _init_fts(conn)

    conn.commit()
    _migrate_store_schema(conn)
    conn.close()


def _init_fts(conn):
    """Create the FTS5 full-text index over facts (external-content) plus the
    triggers that keep it in sync. Falls back silently if FTS5 is unavailable
    (search() then uses LIKE)."""
    try:
        # Note: for an external-content FTS5 table, `SELECT count(*) FROM
        # facts_fts` reflects the CONTENT table's row count, not the indexed
        # token count — so it can't tell us whether the index is populated.
        # Instead we backfill exactly once, when the table is first created.
        existed = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts_fts'"
        ).fetchone()
        # One statement per execute: `executescript` would COMMIT a transaction the caller holds open
        # (`rebuild_db` builds the whole projection in one, #206).
        for stmt in (
            """CREATE VIRTUAL TABLE IF NOT EXISTS facts_fts USING fts5(
                content, tags, content='facts', content_rowid='id'
            )""",
            """CREATE TRIGGER IF NOT EXISTS facts_ai AFTER INSERT ON facts BEGIN
                INSERT INTO facts_fts(rowid, content, tags)
                VALUES (new.id, new.content, new.tags);
            END""",
            """CREATE TRIGGER IF NOT EXISTS facts_ad AFTER DELETE ON facts BEGIN
                INSERT INTO facts_fts(facts_fts, rowid, content, tags)
                VALUES ('delete', old.id, old.content, old.tags);
            END""",
            """CREATE TRIGGER IF NOT EXISTS facts_au AFTER UPDATE ON facts BEGIN
                INSERT INTO facts_fts(facts_fts, rowid, content, tags)
                VALUES ('delete', old.id, old.content, old.tags);
                INSERT INTO facts_fts(rowid, content, tags)
                VALUES (new.id, new.content, new.tags);
            END""",
        ):
            conn.execute(stmt)
        if not existed:
            # Freshly created: backfill the index from existing facts rows
            # (first upgrade, or after a rebuild dropped+recreated it).
            conn.execute(
                "INSERT INTO facts_fts(rowid, content, tags) SELECT id, content, tags FROM facts"
            )
    except sqlite3.OperationalError:
        pass  # FTS5 not compiled in — search() falls back to LIKE


# --------------------------------------------------------------------------
# Journal — the append-only source of truth (G-Set CRDT)
# --------------------------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _canonical(obj):
    """Stable bytes for hashing. The definition is `merkle._canonical` (#153): one copy, so no two can
    diverge into a hash or signature the fleet disagrees on. The name stays here for hv's own callers and
    for `sync_common.load_hv()` consumers."""
    return merkle._canonical(obj)


def compute_hash(entry):
    return "sha256:" + hashlib.sha256(_canonical(entry)).hexdigest()


def _entry_signing_bytes(entry):
    """Canonical bytes a device signature covers: the whole entry except the signature itself.
    `pub` IS covered, so the signing key is bound into what's signed. The hash chain
    (compute_hash) commits to the full entry including `sig`."""
    return _canonical({k: v for k, v in entry.items() if k != "sig"})


def _sign_entry(entry, seed, pub):
    """Attach `pub` (b64 signer key) then `sig` (b64 signature over the entry sans sig)."""
    entry["pub"] = base64.b64encode(pub).decode()
    entry["sig"] = base64.b64encode(_ed25519.sign(_entry_signing_bytes(entry), seed)).decode()
    return entry


# Signature-verification memo (#70). It caches ONLY the pure cryptographic check, and only POSITIVE results,
# keyed on (sha512(message), sig, pub). Ed25519 already hashes the message with SHA-512, so the digest key adds
# no assumption. AUTHORIZATION IS NEVER CACHED: admission, revocation, owner-as-of, the writer policies, link
# authority and the node_id <-> pub binding in _verify_entry are recomputed from current governance every
# time. Rejections are not cached, so a peer streaming bad signatures can't evict good ones. A bounded LRU,
# in memory only: a persisted table would make store.db part of the trust base. Worst case at the cap is
# about 7 MB (16,384 entries, measured with tracemalloc on CPython 3.12). Sync-request and release-manifest
# signatures don't use it (fresh nonces every time); they call _ed25519.verify directly.
_VERIFY_MEMO_MAX = 16384
_VERIFY_MEMO = collections.OrderedDict()
_VERIFY_MEMO_LOCK = threading.Lock()
_VERIFY_STATS = {"hits": 0, "misses": 0}          # read by tests/test_perf.py


def _verify_sig(message, sig, pub):
    """`_ed25519.verify(message, sig, pub)` through the memo. The verifier of `_verify_entry` and
    `_verify_governance`, and nothing else."""
    key = (hashlib.sha512(message).digest(), bytes(sig), bytes(pub))
    with _VERIFY_MEMO_LOCK:
        if key in _VERIFY_MEMO:
            _VERIFY_MEMO.move_to_end(key)
            _VERIFY_STATS["hits"] += 1
            return True
        _VERIFY_STATS["misses"] += 1
    ok = _ed25519.verify(message, sig, pub)
    if ok:
        with _VERIFY_MEMO_LOCK:
            _VERIFY_MEMO[key] = True
            while len(_VERIFY_MEMO) > _VERIFY_MEMO_MAX:
                _VERIFY_MEMO.popitem(last=False)
    return ok


def _verify_entry(entry):
    """A SIGNED entry is valid iff its node_id is the fingerprint of its embedded pub and the
    signature checks out — so no one can attribute an entry to a device_id they don't hold the
    key for. UNSIGNED entries return True (grandfathered: pre-migration history, legacy peers)."""
    if "sig" not in entry:
        return True
    if _ed25519 is None:
        return True   # a stripped build can't verify; don't reject on that alone
    try:
        pub = base64.b64decode(entry.get("pub", ""))
        sig = base64.b64decode(entry["sig"])
        if len(pub) != 32 or entry.get("node_id") != _device_id_for_pub(pub):
            return False
        return _verify_sig(_entry_signing_bytes(entry), sig, pub)
    except Exception:
        return False


# `_sign_governance_payload` moved to the control plane (2.0 S2, `hivemind_owner.py`). `_verify_governance`
# below deliberately stays: every node, agent nodes included, keeps verifying owner signatures it can never
# produce.


def _verify_governance(payload):
    """Return the owner_id that signed this governance payload (verified), or None if the owner
    signature is missing/invalid. The signer is the fingerprint of the embedded owner_pub, so an
    action can only be attributed to an owner key it was actually signed with."""
    if _ed25519 is None:
        return None
    try:
        owner_pub = base64.b64decode(payload.get("owner_pub", ""))
        owner_sig = base64.b64decode(payload.get("owner_sig", ""))
        if len(owner_pub) != 32:
            return None
        body = _canonical({k: v for k, v in payload.items() if k != "owner_sig"})
        if not _verify_sig(body, owner_sig, owner_pub):
            return None
        return _owner_id_for_pub(owner_pub)
    except Exception:
        return None


def _next_seq_and_prev(node_id, with_timestamp=False):
    """Next per-node monotonic seq and the hash of this device's latest entry (plus the LATEST timestamp this device
    holds, by instant, or None, when `with_timestamp`: rule 1 measures against the chain max). Derived from the journal itself (stateless, correct after a fresh start)."""
    mine = [e for e in merkle.read_all_entries(JOURNAL_DIR) if e.get("node_id") == node_id]
    if not mine:
        out = (1, "sha256:genesis")
        return out + (None,) if with_timestamp else out
    last = max(mine, key=lambda e: e["seq"])
    out = (last["seq"] + 1, compute_hash(last))
    if not with_timestamp:
        return out
    stamped = [(i, e["timestamp"]) for e in mine for i in [_ts_instant(e.get("timestamp"))] if i is not None]
    return out + (max(stamped)[1] if stamped else last.get("timestamp"),)


# An entry's timestamp names its journal file, so it must be a real ISO-8601 time before anything is written
# (private #29: an unchecked `../` or absolute prefix wrote outside journal/). Both shapes the journal holds are
# accepted: `_now_iso()`'s `YYYY-MM-DDTHH:MM:SS.mmm+00:00` and the naive `YYYY-MM-DDTHH:MM:SS` of early-June lines;
# `Z` and microseconds are ISO too. The read path never checks this: lines already on disk stay as they are.
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?")


def _valid_timestamp(ts):
    """True iff `ts` is an ISO-8601 timestamp this hive writes (see _TIMESTAMP_RE) on a real calendar date."""
    if not isinstance(ts, str) or not _TIMESTAMP_RE.fullmatch(ts):
        return False
    try:
        datetime.strptime(ts[:10], "%Y-%m-%d")
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Bounded entry timestamps (#217). Journal order is (timestamp, node_id, seq) and the writer picks the timestamp,
# so two rules bound it per device, and both apply at ingest AND in the projection (every node agrees):
#   1. monotonic: a timestamp is no earlier than the latest timestamp of the device's lower seqs, less 5 minutes;
#   2. no earlier than admission: no earlier than the device's first honoured `admit`, less 5 minutes (a
#      `join-request` and an `announce`, which a device writes before any admit, are exempt).
# A checked entry must also carry the one canonical shape, so the folds that sort the raw string order by instant.
# Nothing is checked until the owner signs a `freeze-timestamps` marker: its `tips` freeze each device's chain at a
# seq, and an entry at or below its device's tip is unchecked. Grandfathering is by seq, never by timestamp, so a
# backdated entry cannot claim it. Without a marker nothing is skipped, so a node keeps today's projection.
# The bounds apply only in the projection (#230, #250; David's rulings of 2026-10-06). Ingest checks the signature, the
# purge, the payload and the admission of an entry and refuses nothing for its timestamp: an entry the bounds would skip
# is stored all the same, so two nodes that are offered the same entries hold the same journal, whatever the order or
# the batch split, and the projection judges one set.
# Tiebreak: owner-signed governance beats a device-stamped entry. A device-stamped entry is every entry the owner did not
# sign: content, and the authority-less `announce`, `join-request`, `propose-election` and `vote-election`. The walk of a
# chain in seq order skips a device-stamped entry that would push the chain's latest timestamp past a higher-seq
# owner-signed act (an admit, a revoke, a marker), and that skipped entry does not move the chain. Owner-signed entries
# that pass still do. So a device cannot void an owner act by writing a lower seq with a later stamp, with content or with
# the device key's own announce. Content projects only while the same projection lists its device in `admitted`.
# Arrival times and flood counts are detection only: `hv doctor` and `hv audit` report them, nothing refuses.
# --------------------------------------------------------------------------

TS_TOLERANCE = timedelta(minutes=5)       # clock-correction slack; one budget against the chain's latest timestamp
FUTURE_DATED_MINUTES = 10                 # a timestamp this far ahead of the receiver's clock on arrival is flagged
FLOOD_PER_MINUTE = 120                    # default `flood_per_minute`: entries one device may stamp into a minute
FLOOD_PER_DAY = 2000                      # default `flood_per_day`
_CANONICAL_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00")
_TS_PARTS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:(Z)|([+-])(\d{2}):(\d{2}))?")
_TS_RULE2_EXEMPT = ("join-request", "announce")


def _ts_instant(ts):
    """The UTC instant of a timestamp of any shape the journal holds (naive means UTC), or None."""
    if not _valid_timestamp(ts):
        return None
    m = _TS_PARTS_RE.fullmatch(ts)
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            microsecond=int((m.group(2) or "0").ljust(6, "0")), tzinfo=timezone.utc)
        if m.group(4):
            off = timedelta(hours=int(m.group(5)), minutes=int(m.group(6)))
            dt = dt - off if m.group(4) == "+" else dt + off
        return dt
    except (ValueError, OverflowError):
        return None


def _ts_is_marker(e, gov):
    """True for a `freeze-timestamps` entry that `_governance_state` honours (signed by the owner current at its
    position). The marker is never itself checked: it is what arms the rules, so skipping it would make the rules
    depend on their own verdict. A marker signed by any other embedded key arms nothing and is checked like any entry."""
    return (e.get("node_id"), e.get("seq")) in (gov.get("ts_markers") or ())


def _ts_grandfathered(e, tips):
    """An entry at or below its device's frozen tip is unchecked: by chain position, never by timestamp."""
    seq = e.get("seq")
    return isinstance(seq, int) and seq <= tips.get(e.get("node_id"), 0)


def _ts_chain_max(prior):
    """The latest instant among a device's lower seqs (None if there are none): the one reference rule 1 measures
    its single 5-minute budget against, so a run of small steps cannot walk back without a limit."""
    return max(prior) if prior else None


def _ts_problem(e, floor, prior_max):
    """Why this checked entry's timestamp is outside the bounds, or None. Pure over its arguments. `floor` is the
    instant of the device's first honoured admit (None if it has none), `prior_max` is `_ts_chain_max`."""
    ts = e.get("timestamp")
    inst = _ts_instant(ts) if isinstance(ts, str) and _CANONICAL_TS_RE.fullmatch(ts) else None
    if inst is None:
        return "timestamp is not the canonical YYYY-MM-DDTHH:MM:SS.mmm+00:00 shape"
    if prior_max is not None and inst < prior_max - TS_TOLERANCE:
        return "timestamp is more than 5 minutes before the device's latest earlier entry"
    if (floor is not None and not (e.get("type") == "governance"
                                   and (e.get("payload") or {}).get("action") in _TS_RULE2_EXEMPT)
            and inst < floor - TS_TOLERANCE):
        return "timestamp is more than 5 minutes before the device's first admit"
    return None


def _ts_owner_signed(e, gov):
    """True for a governance act whose owner signature verifies as the owner in authority at the act's position
    (`_owner_at`, as `_is_authorized_writer` reads it). Every other entry is device-stamped: content, the acts only the
    device key signs (`announce`, `join-request`, `propose-election`, `vote-election`), and an act signed by a key that
    is not that owner, such as a throwaway key embedded in its own payload. Those land only on the chain of the
    device that wrote them and never shield or move anything for the owner."""
    p = e.get("payload")
    if e.get("type") != "governance" or not isinstance(p, dict):
        return False
    oid = _verify_governance(p)
    tl = gov.get("owner_timeline") or []
    pos = (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0))
    # The owner at the act's position, or the one just before it: the outgoing owner signs a `transfer`, and the walk
    # records the successor at that same position.
    if not _member_at(gov, pos[1], pos):
        return False                           # SECREV A3: an act no member carried is not honoured, so it shields nothing
    return oid is not None and oid in (_owner_at(tl, pos), _owner_at([t for t in tl if t[:3] < pos], pos))


def _ts_violations(entries, gov):
    """{(node_id, seq): reason} for every entry the bounds skip. Pure and deterministic over the journal and the
    governance projection: a device's entries are walked in seq order, and only an entry that passes (or is
    grandfathered) moves the chain's latest timestamp. Empty until a marker is honoured.

    Tiebreak (#230, #250; David's ruling of 2026-10-06): owner-signed governance beats a device-stamped entry. A
    device-stamped entry that would push the chain's latest timestamp past a higher-seq owner-signed act, so that the
    bounds skip that act, is itself skipped and does not move the chain. An owner-signed entry that passes still
    does. Which entries are skipped is then a function of the set held, whatever order it arrived in."""
    tips = gov.get("ts_tips") or {}
    if not tips:
        return {}
    by_dev = {}
    for e in entries:
        if e.get("node_id") is not None and isinstance(e.get("seq"), int):
            by_dev.setdefault(e["node_id"], []).append(e)
    first = gov.get("first_admit") or {}
    out = {}
    for nid, es in by_dev.items():
        floor = _ts_instant(first.get(nid))
        es.sort(key=lambda x: x["seq"])
        # The owner-signed acts the bounds check and keep unless something earlier on the chain pushes past them:
        # the instants a device-stamped entry must not push past. Sorted; an entry leaves it as the walk reaches it.
        ahead = sorted(i for e in es if _ts_owner_signed(e, gov)
                       and not (_ts_grandfathered(e, tips) or _ts_is_marker(e, gov))
                       and _ts_problem(e, floor, None) is None
                       for i in [_ts_instant(e.get("timestamp"))])
        prior = []
        for e in es:
            checked = not (_ts_grandfathered(e, tips) or _ts_is_marker(e, gov))
            owner_signed = _ts_owner_signed(e, gov)
            if owner_signed and checked and _ts_problem(e, floor, None) is None:
                del ahead[bisect.bisect_left(ahead, _ts_instant(e.get("timestamp")))]
            if checked:
                why = _ts_problem(e, floor, _ts_chain_max(prior))
                if why is None and not owner_signed and ahead:
                    inst = _ts_instant(e.get("timestamp"))
                    lo = bisect.bisect_left(ahead, max(prior) - TS_TOLERANCE) if prior else 0
                    if lo < len(ahead) and ahead[lo] < inst - TS_TOLERANCE:
                        why = "timestamp would make the bounds skip a later owner-signed act on the device's chain"
                if why is not None:
                    out[(nid, e["seq"])] = why
                    continue
            inst = _ts_instant(e.get("timestamp"))
            if inst is not None:
                prior.append(inst)
    return out


_KEEP_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _keep_pair(p):
    """The `(keep_through, keep_hash)` an owner-signed `purge` carries when its pair is well formed, else None: a
    seq that is an int (not a bool) of at least 1, and a hash of the `compute_hash` shape. A purge without a
    well-formed pair is a plain purge (compromise: none of the device's content projects). Pure; whether the hash
    names the entry at that seq is judged against the held entries by `_purge_kept`."""
    seq, h = p.get("keep_through"), p.get("keep_hash")
    if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 1 and isinstance(h, str) and _KEEP_HASH_RE.fullmatch(h):
        return seq, h
    return None


def _purge_kept(entries, keep):
    """{(node_id, seq)} a retire keeps (#260): for each device whose latest honoured purge carries the pair `keep[device]
    = (seq, hash)`, the entry held at that seq whose `compute_hash` is the hash, then each entry held on that device
    whose `compute_hash` is the `prev_hash` of the one above it, down the chain. The head commits to those bytes
    transitively, so a body at a lower seq that the head does not name is not kept, and a gap stops the walk until the
    entry that fills it is held. Pure over the held entries: a stamp and the arrival order never enter."""
    if not keep:
        return set()
    by_hash = {}
    for e in entries:
        nid = e.get("node_id")
        if nid in keep and isinstance(e.get("seq"), int):
            by_hash[(nid, compute_hash(e))] = e
    kept = set()
    for nid, (seq, h) in keep.items():
        e = by_hash.get((nid, h))
        if e is None or e.get("seq") != seq:
            continue                                   # the head is not held, or the pair does not name its own seq
        while e is not None and (nid, e["seq"]) not in kept:
            kept.add((nid, e["seq"]))
            nxt = by_hash.get((nid, e.get("prev_hash")))
            e = nxt if nxt is not None and nxt["seq"] < e["seq"] else None
    return kept


def _purge_unkept(entries, gov):
    """`entries` without the content of a purged device that the latest honoured purge does not keep (#260). A plain
    purge keeps nothing; a retire keeps the prefix `_purge_kept` names."""
    purged = gov.get("purged") or set()
    if gov.get("owner_id") is None or not purged:
        return entries
    kept = gov.get("kept") or set()
    return [e for e in entries if e.get("type") == "governance" or e.get("node_id") not in purged
            or (e.get("node_id"), e.get("seq")) in kept]


def _admitted_content(entries, gov):
    """`entries` without the content of a device the same projection does not list in `admitted` once an owner exists
    (#230, #250): ingest stores what the timestamp bounds would skip, so admission is read here, from the projection
    that has applied the bounds, and not from what ingest saw on arrival. Governance is not content. Content that
    precedes the genesis owner in the journal's order stays, as the pre-genesis forget does, unless its device has an
    honoured revoke or a purge: the bootstrap hive accepted every device, and the owner's first act must not unwrite
    what came before it, but a writer-chosen stamp must not outlive the owner's revoke. The genesis device is a member
    from genesis without an admit, until an honoured revoke or purge of it (a later admit restores it)."""
    if gov.get("owner_id") is None:
        return entries
    gen = gov.get("genesis_device")
    ok = gov["admitted"] | ({gen} if gen is not None and gen not in gov.get("revoked", set()) else set())
    ok = ok - gov.get("purged", set())          # the genesis device is a member until an honoured revoke or purge
    ended = gov.get("purged", set()) | gov.get("revoked", set())   # an honoured revoke or purge ends the pre-genesis stay
    timeline = gov.get("owner_timeline") or []
    kept = gov.get("kept") or set()        # a retired device's named prefix (#260)
    return [e for e in entries if e.get("type") == "governance" or e.get("node_id") in ok
            or (e.get("node_id"), e.get("seq")) in kept
            or (isinstance(e.get("payload"), dict)                                      # an owner act, not device-stamped:
                and _is_authorized_writer(None, (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0)),
                                          e["payload"], gov, "owner"))                  # verified, as of its position
            or (e.get("node_id") not in ended
                and _owner_at(timeline, (e.get("timestamp", ""), str(e.get("node_id", "")), e.get("seq", 0))) is None)]


def _ts_unskipped(entries, gov=None):
    """`entries` without those the timestamp bounds skip. The one filter for the projection's non-governance
    readers; `_governance_state` applies the same verdict to governance entries itself."""
    gov = gov if gov is not None else _governance_state(entries)
    skipped = _ts_violations(entries, gov)
    if not skipped:
        return entries
    return [e for e in entries if (e.get("node_id"), e.get("seq")) not in skipped]


def _arrivals_path():
    return HIVE_HOME / ".arrivals.jsonl"


def _record_arrivals(keys):
    """Append when this node first received each entry (`keys` = [(node_id, seq)]) to `$HIVE_HOME/.arrivals.jsonl`.
    Local evidence for the `future-dated` check: never synced, never consensus, never read by the projection."""
    if not keys:
        return
    at = os.environ.get("HIVE_NOW") or _now_iso()
    try:
        with open(_arrivals_path(), "a") as f:
            for nid, seq in keys:
                f.write(json.dumps({"n": nid, "s": seq, "at": at}) + "\n")
    except OSError:
        pass


def _read_arrivals():
    """{(node_id, seq): arrival instant string}, the first record of each (a damaged line is skipped)."""
    out = {}
    try:
        for line in _arrivals_path().read_text().splitlines():
            try:
                r = json.loads(line)
                out.setdefault((r["n"], r["s"]), r["at"])
            except (ValueError, KeyError, TypeError):
                continue
    except OSError:
        pass
    return out


def _future_dated(entries):
    """{node_id: {"count", "worst_minutes"}} for entries whose timestamp was more than FUTURE_DATED_MINUTES ahead of
    this node's clock when they arrived. Detection only: it reads local arrival times and changes no projection."""
    arrived = _read_arrivals()
    out = {}
    for e in entries:
        at = _ts_instant(arrived.get((e.get("node_id"), e.get("seq"))))
        inst = _ts_instant(e.get("timestamp"))
        if at is None or inst is None:
            continue
        ahead = (inst - at).total_seconds() / 60.0
        if ahead > FUTURE_DATED_MINUTES:
            d = out.setdefault(e["node_id"], {"count": 0, "worst_minutes": 0.0})
            d["count"] += 1
            d["worst_minutes"] = max(d["worst_minutes"], round(ahead, 1))
    return out


def _floods(entries, gov):
    """[{node_id, per, count, limit}] for each device whose busiest timestamp-minute or timestamp-day holds more
    entries than the owner-signed `flood_per_minute` / `flood_per_day`. Detection only."""
    cfg = gov.get("config") or {}
    limits = {"minute": int(cfg.get("flood_per_minute", FLOOD_PER_MINUTE)),
              "day": int(cfg.get("flood_per_day", FLOOD_PER_DAY))}
    counts = {"minute": {}, "day": {}}
    for e in entries:
        inst = _ts_instant(e.get("timestamp"))
        if inst is None or e.get("node_id") is None:
            continue
        for per, fmt in (("minute", "%Y-%m-%dT%H:%M"), ("day", "%Y-%m-%d")):
            k = (e["node_id"], inst.strftime(fmt))
            counts[per][k] = counts[per].get(k, 0) + 1
    worst = {}
    for per in ("minute", "day"):
        for (nid, _bucket), n in counts[per].items():
            if n > limits[per] and n > worst.get((nid, per), 0):
                worst[(nid, per)] = n
    return [{"node_id": nid, "per": per, "count": n, "limit": limits[per]}
            for (nid, per), n in sorted(worst.items())]


def _journal_path_for(timestamp):
    """The day file for `timestamp`. Refuses a date prefix that is not `YYYY-MM-DD`, and any path that would
    land outside JOURNAL_DIR, so no caller (ingest, append_journal, HIVE_NOW) can write elsewhere."""
    day = str(timestamp)[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        raise ValueError(f"not a journal timestamp: {timestamp!r}")
    path = JOURNAL_DIR / f"{day}.jsonl"
    if path.resolve().parent != JOURNAL_DIR.resolve():
        raise ValueError(f"journal path escapes {JOURNAL_DIR}: {timestamp!r}")
    return path


try:
    import fcntl as _fcntl
except Exception:                       # non-POSIX (e.g. Windows) — no flock available
    _fcntl = None


def _append_line(path, line):
    """Append one serialized JSON line to a daily journal file under an EXCLUSIVE advisory lock, so a
    concurrent daemon+CLI write (normal operation) can't interleave mid-line and corrupt the .jsonl.
    A line can exceed PIPE_BUF (4096B), so O_APPEND alone is NOT atomic for our records — the lock is.
    Released on close. flock is POSIX-only; without it we fall back to a plain append (single-writer
    is the common case there, and the best-effort corrupt-line skip in merkle.read_all_entries remains
    the second line of defense)."""
    with open(path, "a") as f:
        if _fcntl is not None:
            try:
                _fcntl.flock(f.fileno(), _fcntl.LOCK_EX)
            except Exception:
                pass
        f.write(line + "\n")


QUARANTINE_MAX = 200               # the most records the quarantine keeps: the newest 200, older ones are dropped
QUARANTINE_BYTES_MAX = 16 * 1024 * 1024   # ...and the file stays within this many bytes, oldest dropped first
QUARANTINE_ENTRY_MAX = 64 * 1024   # an entry up to this many canonical bytes is kept verbatim; a larger one as hash, size, head
QUARANTINE_HEAD = 4096             # the first bytes kept of an oversize entry


def _signer(node_id, gov=None):
    """Who signed: the device id, and the principal when the device is admitted."""
    prin = ((gov or {}).get("principals") or {}).get(node_id) if node_id in ((gov or {}).get("admitted") or ()) else None
    return {"node_id": node_id, "principal": prin}


def _quarantine(refused, gov=None):
    """Node-local evidence (#205): write each refused entry with the reason, the signer and the time to
    `$HIVE_HOME/.quarantine.jsonl`. Never synced and never journaled. An entry up to `QUARANTINE_ENTRY_MAX` canonical
    bytes is kept verbatim; a larger one as `{hash, size, head}` (the first `QUARANTINE_HEAD` bytes). The file keeps
    the newest `QUARANTINE_MAX` records and at most `QUARANTINE_BYTES_MAX` bytes. A refusal APPENDS one line and
    never reads the file: the dedupe key (the entry's canonical hash) and the record size live in a small index,
    `.quarantine.idx`, one `hash size` line per record. The file is rewritten only when a cap is crossed (it is
    then at most 16 MB). An entry already held (a peer re-pushes it each sync) is not written twice. Best effort:
    it never makes ingest raise. `refused` is a list of (entry, reason); the caller has already dropped
    signers this node does not admit."""
    try:
        path = HIVE_HOME / ".quarantine.jsonl"
        idx_path = HIVE_HOME / ".quarantine.idx"
        with open(HIVE_HOME / ".quarantine.lock", "a") as lock:
            if _fcntl:
                _fcntl.flock(lock.fileno(), _fcntl.LOCK_EX)
            index = _quarantine_index(path, idx_path)
            seen = {h for h, _n in index}
            fresh = []
            for entry, reason in refused:
                try:
                    raw = _canonical(entry)
                except Exception:
                    continue
                h = hashlib.sha256(raw).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                rec = {"at": _now_iso(), "reason": reason, "signer": _signer(entry.get("node_id"), gov)}
                if len(raw) <= QUARANTINE_ENTRY_MAX:
                    rec["entry"] = entry
                else:
                    rec["oversize"] = {"hash": "sha256:" + h, "size": len(raw),
                                       "head": raw[:QUARANTINE_HEAD].decode("utf-8", "replace")}
                line = json.dumps(rec) + "\n"
                fresh.append((h, line))
            if not fresh:
                return
            with open(path, "a") as f, open(idx_path, "a") as ix:
                for h, line in fresh:
                    f.write(line)
                    ix.write(f"{h} {len(line.encode())}\n")
            index += [(h, len(line.encode())) for h, line in fresh]
            if len(index) > QUARANTINE_MAX or sum(n for _h, n in index) > QUARANTINE_BYTES_MAX:
                lines = path.read_text().splitlines(keepends=True)
                if len(lines) != len(index):          # the index drifted (a crash between the two appends)
                    index = _quarantine_index(path, idx_path, rebuild=True)
                while len(index) > QUARANTINE_MAX or sum(n for _h, n in index) > QUARANTINE_BYTES_MAX:
                    index.pop(0)
                    lines.pop(0)
                for p, body in ((path, "".join(lines)), (idx_path, "".join(f"{h} {n}\n" for h, n in index))):
                    tmp = p.with_name(p.name + ".tmp")
                    tmp.write_text(body)
                    os.replace(tmp, p)
    except Exception:
        pass


def _quarantine_index(path, idx_path, rebuild=False):
    """The quarantine's (canonical hash, line bytes) per record, oldest first, from the small index. A missing or
    unreadable index, one whose sizes no longer sum to the file's size, or `rebuild`, is rebuilt by one read of the
    file: a record's `entry` hashes as stored, an oversize record carries its hash."""
    if not rebuild:
        try:
            index = [(h, int(n)) for h, n in (l.split() for l in idx_path.read_text().splitlines())]
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                size = 0
            if sum(n for _h, n in index) == size:     # a cleared or edited quarantine no longer matches its index
                return index
        except (OSError, ValueError):
            pass
    out = []
    try:
        for l in path.read_text().splitlines(keepends=True):
            try:
                r = json.loads(l)
                if "entry" in r:
                    h = hashlib.sha256(_canonical(r["entry"])).hexdigest()
                else:
                    h = r["oversize"]["hash"].split(":", 1)[-1]
            except (ValueError, KeyError, TypeError):
                h = "damaged-" + hashlib.sha256(l.encode()).hexdigest()
            out.append((h, len(l.encode())))
    except OSError:
        pass
    idx_path.write_text("".join(f"{h} {n}\n" for h, n in out))
    return out


def _read_quarantine():
    """The quarantine's records, oldest first (a damaged line is skipped)."""
    path = HIVE_HOME / ".quarantine.jsonl"
    out = []
    try:
        for l in path.read_text().splitlines():
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def _clamp_timestamp(now, prev_ts):
    """`max(now, the latest timestamp this device holds)` (#217; the chain max, which rule 1 measures against). A clock that stepped back would otherwise write
    an entry the bounds skip here and every peer refuses, and a seat or hook writes unattended, so the memory would
    be lost with nobody told. Equal timestamps are allowed. A step past the tolerance is named on stderr."""
    prev, cur = _ts_instant(prev_ts), _ts_instant(now)
    if prev is None or cur is None or cur >= prev:
        return now
    if prev - cur > TS_TOLERANCE:
        print(f"hv: this device's clock is {int((prev - cur).total_seconds() // 60)} min behind its last journal "
              f"entry ({prev_ts}); stamping the entry {prev.isoformat(timespec='milliseconds')} instead",
              file=sys.stderr)
    return prev.isoformat(timespec="milliseconds")


class JournalLockError(OSError):
    """The journal directory's filesystem would not grant the mint lock. Raised before anything is read or
    written, so no seq is consumed and no line is journaled (#253)."""


def _journal_lock_message(err):
    return (f"hv: cannot lock the journal ({err}). The filesystem under {HIVE_HOME} does not support file locking "
            f"(for example NFS without lockd, ENOLCK). Writing without the lock could mint duplicate seqs and "
            f"break the hash chain, so nothing was written. Move HIVE_HOME to a local filesystem.")


@contextlib.contextmanager
def _journal_mint_lock():
    """An exclusive advisory lock (`.journal.lock`) held from reading this device's tip to appending the entry
    built on it, across processes. Without flock (non-POSIX) it is a no-op, as `_append_line` is. If the
    filesystem refuses the lock it FAILS LOUDLY (`JournalLockError`) and never writes unlocked (#253)."""
    if _fcntl is None:
        yield
        return
    with open(HIVE_HOME / ".journal.lock", "a") as lock:
        try:
            _fcntl.flock(lock.fileno(), _fcntl.LOCK_EX)
        except OSError as e:
            raise JournalLockError(_journal_lock_message(e)) from e
        yield


def _journal_lock_problem():
    """None if the journal directory grants the mint lock, else the remedy message (used by `hv doctor`)."""
    try:
        with _journal_mint_lock():
            pass
    except JournalLockError as e:
        return str(e)
    except OSError as e:
        return f"cannot open the lock file under {HIVE_HOME}: {e}"
    return None


def append_journal(entry_type, payload, timestamp=None):
    """Mint and append a LOCAL journal entry. This is the core append API —
    every local write goes through here. Returns the full entry dict."""
    explicit = timestamp is not None
    timestamp = timestamp or _now_iso()
    candidate = {"type": entry_type, "payload": payload}
    problem = _hostile_problem(candidate) or _payload_problem(candidate)
    if problem is not None:
        try:
            gov = _governance_state(merkle.read_all_entries(JOURNAL_DIR))      # the principal, when this device is admitted
        except Exception:
            gov = None
        _quarantine([({"node_id": NODE_ID, "type": entry_type, "timestamp": timestamp, "payload": payload}, problem)], gov)
        raise ValueError(f"invalid {entry_type} payload: {problem}")      # #205: nothing malformed is journaled
    # The next seq is read from the journal, so the read and the append are ONE critical section (#215): two
    # processes that each read the tip before either appended would mint the same (node_id, seq).
    with _journal_mint_lock():
        seq, prev_hash, prev_ts = _next_seq_and_prev(NODE_ID, with_timestamp=True)
        held = merkle.occupied_seqs(JOURNAL_DIR, NODE_ID)      # never reuse the seq of a line the reader skips
        while seq in held and seq < merkle.SEQ_MAX:
            seq += 1
        if seq >= merkle.SEQ_MAX:
            raise ValueError(f"invalid {entry_type} entry: no free seq below {merkle.SEQ_MAX}")
        if not explicit:
            timestamp = _clamp_timestamp(timestamp, prev_ts)
        entry = {
            "node_id": NODE_ID,
            "seq": seq,
            "type": entry_type,          # one of vocabulary.ENTRY_TYPES (tests/test_vocabulary.py checks every call)
            "timestamp": timestamp,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        # The reader skips a line that fails the envelope check, so the next seq would be minted again over it.
        problem = merkle.envelope_problem(entry)
        if problem is not None:
            raise ValueError(f"invalid {entry_type} entry: {problem}")
        seed = _device_seed()
        if seed is not None:
            _sign_entry(entry, seed, _ed25519.pub_from_seed(seed))
        _append_line(_journal_path_for(timestamp), json.dumps(entry))
    return entry


def _entry_keys(entries):
    """The (node_id, seq) key-set of already-read entries (G-Set membership)."""
    return {(e["node_id"], e["seq"]) for e in entries
            if e.get("node_id") is not None and e.get("seq") is not None}


def _journal_sig(keys):
    """Content signature of a journal key-set (the `_GOV_CACHE` idiom): equal iff the sets are equal, so it
    stays correct across a restore or a repair, where a count could match while the set differs."""
    h = hashlib.sha256()
    for k in sorted(f"{n}:{s}" for n, s in keys):
        h.update(k.encode())
        h.update(b"\n")
    return h.hexdigest()


def _projected_sig(conn):
    row = conn.execute("SELECT value FROM meta WHERE key = 'projected_journal_sig'").fetchone()
    return row[0] if row else None


def _mark_projected(conn, entries, appended=()):
    """Record, inside the caller's transaction, that store.db now holds exactly the journal `entries` (#70).
    A full rebuild marks unconditionally. An incremental writer passes the entries it just `appended`: the
    marker advances only if the store was current before this write (the old marker equals the key-set
    minus this write's own keys). If anything else landed meanwhile, for example another process's write
    that failed after its journal append, the marker stays stale and the next command catches up."""
    keys = _entry_keys(entries)
    mine = {(e["node_id"], e["seq"]) for e in appended if e}
    if mine and _projected_sig(conn) != _journal_sig(keys - mine):
        return False
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('projected_journal_sig', ?)",
                 (_journal_sig(keys),))
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('projected_entries', ?)", (str(len(keys)),))
    return True


def _ensure_store_current():
    """Rebuild store.db if it doesn't hold exactly the journal's key-set (#70): after a write that failed
    after its journal append, an append by a command that doesn't project into the store (a capsule, a
    cell, governance handled elsewhere), an ingest by another process, or a restore. Costs one journal
    read when current. remember, decide, propose, retract and entity advance the marker themselves."""
    entries = merkle.read_all_entries(JOURNAL_DIR)
    conn = get_conn()
    try:
        current = _projected_sig(conn) == _journal_sig(_entry_keys(entries))
    finally:
        conn.close()
    if not current:
        rebuild_db()
    return not current


def _store_deferred(entry, err, word="Remembered"):
    """The write is in the journal (the source of truth) but the store write failed after it, typically
    `database is locked` past the busy timeout. Report success, not failure: a caller that retried would
    append a permanent duplicate. The stale marker makes the next command catch the store up."""
    sid = _short_id(entry["node_id"], entry["seq"])
    print(f"{word} as {sid} (journaled; the local store is busy and will catch up on the next command)")
    print(f"  ref: {_ref_str([entry['node_id'], entry['seq']])}")
    print(f"  store write deferred: {err}", file=sys.stderr)
    sys.exit(0)


def _feed_cursor_parse(text):
    """`node:seq,node:seq` -> {node_id: seq}. Node ids contain ':' (`k1:...`), so each pair splits at the
    LAST colon. A malformed pair is a usage error, never a silent restart from the beginning."""
    cur = {}
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        node, _, seq = part.rpartition(":")
        if not node or not seq.isdigit():
            raise ValueError(f"bad cursor entry {part!r}: expected node_id:seq")
        cur[node] = max(cur.get(node, 0), int(seq))
    return cur


def _feed_cursor_str(cur):
    return ",".join(f"{n}:{s}" for n, s in sorted(cur.items()))


def feed_page(after=None, limit=200):
    """One page of the journal for a module (2.1, `hv feed`): the verified entries past a per-node cursor,
    in `(node_id, seq)` order, each with its `ref`/`sid`. Read from the journal files, not the store. Two
    fields are core-computed so a consumer never reimplements the forget rule: `forgotten` on a `fact`
    entry, and `affects` on a `retract` entry (the held facts sharing the target's content when the act is
    honoured, else empty). `sig` and `pub` pass through; an entry with no `sig` is attributed, not
    authenticated. A node's chain is served only up to its first missing seq. Returns {"entries", "cursor", "more"}."""
    after = dict(after or {})
    entries = merkle.read_all_entries(JOURNAL_DIR)   # verified lazily, per served entry: a cold process pays for the page, not the journal
    ev = _content_evidence(entries, _governance_state(entries), links=False)   # links never change `forget` or `acts`
    honoured = {}                               # (node_id, seq) of an honoured owner act -> its content
    for c, cev in ev.items():
        for key, ok in cev.get("acts", {}).items():
            if ok:
                honoured[key] = c
    wanted = set(honoured.values())
    held = {}                                   # content -> [refs of verified facts]; affects never names a withheld ref.
    for e in entries:                           # Only contents under an honoured act are checked, so a caught-up poll verifies nothing.
        c = (e.get("payload") or {}).get("content")
        if e.get("type") == "fact" and c in wanted and _verify_entry(e):
            held.setdefault(c, []).append(_ref_str([e["node_id"], e["seq"]]))
    # Contiguity (#358): sync can land seq N+1 before N, and a cursor that passed N+1 would never serve N. So each
    # node is served only as the run of held seqs starting at `after[node] + 1`; a missing seq withholds every
    # higher seq of that node (not of another node). A held entry that fails verification still occupies its seq.
    held_seqs = {}
    for e in entries:
        if e.get("node_id") is not None and isinstance(e.get("seq"), int):
            held_seqs.setdefault(e["node_id"], set()).add(e["seq"])
    served_to = {}                              # node -> highest seq reachable without a hole above `after`
    for node, seqs in held_seqs.items():
        top = after.get(node, 0)
        while top + 1 in seqs:
            top += 1
        served_to[node] = top
    cursor = dict(after)
    out = []
    more = False
    for e in entries:
        node, seq = e.get("node_id"), e.get("seq")
        if node is None or not isinstance(seq, int) or seq <= after.get(node, 0) or seq > served_to[node]:
            continue
        if not _verify_entry(e):
            continue
        if len(out) >= limit:
            more = True
            break
        item = {"node_id": node, "seq": seq, "ref": _ref_str([node, seq]), "sid": _short_id(node, seq),
                "type": e.get("type"), "timestamp": e.get("timestamp"), "payload": e.get("payload")}
        for k in ("sig", "pub"):
            if k in e:
                item[k] = e[k]
        p = e.get("payload") or {}
        if e.get("type") == "fact" and p.get("content") is not None:
            item["forgotten"] = bool(ev.get(p["content"], {}).get("forget"))
        elif e.get("type") == "retract":
            app, ctx, _inst, _sess = _parse_source(p.get("source", "manual"))
            if app in OWNER_APPS or ctx == "owner":     # an owner act carries the list (maybe empty); a peer retract omits it
                item["affects"] = sorted(held.get(honoured.get((node, seq)), []))
        out.append(item)
        cursor[node] = seq
    return {"entries": out, "cursor": _feed_cursor_str(cursor), "more": more}


def feed(args):
    try:
        after = _feed_cursor_parse(args.after)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(feed_page(after, max(1, args.limit)), sort_keys=True))


def journal_keys():
    """Set of (node_id, seq) present in the journal — the G-Set membership."""
    return {
        (e["node_id"], e["seq"])
        for e in merkle.read_all_entries(JOURNAL_DIR)
        if e.get("node_id") is not None and e.get("seq") is not None
    }


