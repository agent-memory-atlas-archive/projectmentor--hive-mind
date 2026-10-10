"""FROZEN: `persist_entity` exactly as it stood in hive-mind 2.4 / `release/3.0` at `70859ed` (before the 3.0 PR 7
re-keying), and the 2.4 `entities` DDL it ran against (`name TEXT NOT NULL UNIQUE`, no identity columns). Never edit.

`tests/test_entity_rekey.py` projects the entity corpus once with the live function over the 3.0 schema and once
with this one over the 2.4 schema, and requires the two projections to be byte-identical (3.0 plan 4.5, PR 7).
The function text between the markers is byte-for-byte the 2.4 text; the test pins its sha256.
"""
# ruff: noqa
# flake8: noqa
OLD_ENTITIES_DDL = """
CREATE TABLE entities (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT, -- person, project, concept
    attributes TEXT, -- JSON
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP
);
CREATE TABLE entity_facts (
    entity_id INTEGER REFERENCES entities(id),
    fact_id INTEGER REFERENCES facts(id),
    confidence REAL DEFAULT 1.0,
    PRIMARY KEY (entity_id, fact_id)
);
CREATE INDEX idx_entities_name ON entities(name);
"""
# --- begin frozen 2.4 text ---
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
    cur.execute("""
        INSERT INTO entities (name, type, attributes, first_seen, last_updated)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            type = excluded.type,
            attributes = excluded.attributes,
            last_updated = excluded.last_updated
    """, (
        payload["name"],
        etype,
        attrs_json,
        _payload_field(entry, "created_at") or ts,
        ts,
    ))
    eid = cur.execute("SELECT id FROM entities WHERE name = ?", (payload["name"],)).fetchone()[0]
    _record_index(conn, entry, "entity", eid)
    return {"id": eid, "name": payload["name"], "type": etype}
# --- end frozen 2.4 text ---
