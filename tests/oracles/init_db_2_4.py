"""FROZEN: `init_db` and `_init_fts` exactly as they stood in hive-mind 2.4 (`main` at 53a3eeb), the code that built a
2.4 node's `store.db`. `tests/test_entity_store_migration.py` builds a 2.4-shaped store with it and requires a 3.0
`hv` to migrate that store once and leave it alone the second time (3.0 plan 4.5, PR 9). Never edit.

`build(home)` runs the frozen text against `home` (`store.db`, `journal/`). The text between the markers is
byte-for-byte the 2.4 text; the test pins its sha256.
"""
# ruff: noqa
# flake8: noqa
import sqlite3
from pathlib import Path

SRC = r'''def init_db():
    """Initialize database schema (idempotent)."""
    HIVE_HOME.mkdir(parents=True, exist_ok=True)
    JOURNAL_DIR.mkdir(exist_ok=True)

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

    CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        type TEXT, -- person, project, concept
        attributes TEXT, -- JSON
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP
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
'''
SRC_SHA256 = "dd00bef9f9e1337df09c3e45648fa8447a9d7d7fc9934b2b4a3fa680b30318c9"


def build(home):
    home = Path(home)

    def get_conn():
        conn = sqlite3.connect(home / "store.db")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    ns = {"sqlite3": sqlite3, "HIVE_HOME": home, "JOURNAL_DIR": home / "journal", "get_conn": get_conn}
    exec(compile(SRC, "init_db_2_4", "exec"), ns)
    ns["init_db"]()
