"""FROZEN: the entry validator of hive-mind 2.4 (`53a3eeb`): the payload shape tables and the functions that turn an
entry into "refused at ingest" (`_hostile_problem`, `_payload_problem`) or "projects to nothing" (`_unprojectable`).
Never edit.

`tests/test_entity_write_path.py` (3.0 plan 4.5, PR 8) runs the two optional `entity` fields, `identity_ref` and
`new_identity`, through THIS text, so "a 2.4 validator accepts the new fields" is a fact about 2.4 and not a sentence.
The first block is byte-for-byte the 2.4 text (`hv` lines 4000-4120 at `53a3eeb`, before the 3.1 split; now in `hivemind/parts/`); the second is 2.4's reading of
which `entity` entries it applies (`_entity_name`, `_entity_declined`, `_entity_verdicts`, lines 3710-3757), keyed by
name. The test pins the sha256 of each and runs them in `hv`'s namespace, which supplies the helpers
(`_is_str`, `_valid_ref`, `_link_authority`, ...).
"""
# ruff: noqa
# flake8: noqa
# --- begin frozen 2.4 text ---
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
               "created_at": (_is_str, None)},
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


# --- end frozen 2.4 text ---
# --- begin frozen 2.4 verdicts ---
def _entity_name(entry):
    n = (entry.get("payload") or {}).get("name")
    return n if isinstance(n, str) else None


def _entity_declined(entries, gov):
    """The `entity` entries the projection does not apply, as a set of (node_id, seq): the module-policy ones
    and the weigh-only ones (`_entity_verdicts`)."""
    module_declined, weigh_only = _entity_verdicts(entries, gov)
    return module_declined | weigh_only


def _entity_verdicts(entries, gov):
    """(module_declined, weigh_only), each a set of (node_id, seq) of `entity` entries the projection skips.

    2.1 (#208, option 3): a module device (the `module` admit marker, `gov["modules"]`) may write only
    `x-<its module>:<name>` entities (the gate's `entity-prefix-required`), and may update one only if it is that
    name's creator, the first APPLIED entity entry for the name in replay order `(node_id, seq)`, the order
    `persist_entity`'s `ON CONFLICT(name)` folds in (the gate's `not-entity-owner`).

    SECREV B3 (hive-mind-private #51): every other device is held to the rule links use (`_link_authority`, the
    creator's entry standing as the target). The creator, or an owner-signed write, rewrites the entity; any other
    admitted device's write is weigh-only: it is skipped like a declined one, so it does not replace the entity.
    Pre-owner, only the creator rule applies, as for links. Pure over the journal and governance, so every node
    declines the same entries whatever order they arrived in. A declined entry is skipped, not kept as evidence.
    The module marker is read as of the end of the journal, like the election exclusion."""
    modules = gov.get("modules") or {}
    declined, weigh_only, creator = set(), set(), {}
    for e in entries:
        if e.get("type") != "entity":
            continue
        name = _entity_name(e)
        if name is None:
            continue
        node = e.get("node_id")
        module = modules.get(node)
        first = creator.get(name)
        if module is not None:
            split = vocabulary.split_module_name(name)
            if split is None or split[0] != module or (first is not None and first.get("node_id") != node):
                declined.add((node, e.get("seq")))
                continue
        elif first is not None and _link_authority(e, first, gov) != "hard":
            weigh_only.add((node, e.get("seq")))
            continue
        creator.setdefault(name, e)
    return declined, weigh_only

# --- end frozen 2.4 verdicts ---
