"""4.0 C1 (hconfig design §1.2, §6): `config schema --json`, `config show --json`, and `config set` that exits 1 on
every refusal.

`GOVERNED_KEYS` is the one table `_config_set` consults (membership, coercion, choices, range); `NODE_KEYS` is read by
`config schema` (and, in C2, `config node`) and never by `_config_set`, so a node key cannot become a `set-config`.
"""
import json
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
import merkle  # noqa: E402
import vocabulary  # noqa: E402
from test_governance import _run  # noqa: E402
from test_links import _loadhv  # noqa: E402

NODE = ["port", "bind", "sync_auth", "sync_auth_outbound", "dashboard_share", "dashboard_viewers", "dashboard_viewer_port"]


def _journal(home):
    return merkle.read_all_entries(str(Path(home) / "journal"))


def _set_configs(home):
    return [e["payload"] for e in _journal(home)
            if e.get("type") == "governance" and (e.get("payload") or {}).get("action") == "set-config"]


@pytest.fixture
def home(tmp_path):
    _run(tmp_path, "owner", "init")
    return tmp_path


def _good(spec):
    return spec["choices"][0] if "choices" in spec else spec["default"]


def _bad_values(spec):
    """Values outside the table's range, as strings."""
    out = []
    if "min" in spec:
        out.append(spec["min"] if spec.get("min_exclusive") else spec["min"] - 1)
    if "max" in spec:
        out.append(spec["max"] + 1)
    return [str(v) for v in out]


def test_governed_keys_is_the_set_config_will_take_and_node_keys_never_are(tmp_path, monkeypatch, home):
    hv = _loadhv(tmp_path, monkeypatch)
    assert set(NODE).isdisjoint(hv.GOVERNED_KEYS)                     # two tables, not one
    assert list(hv.NODE_KEYS) == NODE
    for key, spec in hv.GOVERNED_KEYS.items():                        # every table row is accepted by the writer
        r = _run(home, "config", "set", key, str(_good(spec)))
        assert r.returncode == 0 and r.stdout.startswith(f"set {key} = "), (key, r.stdout)
    assert {p["key"] for p in _set_configs(home)} == set(hv.GOVERNED_KEYS)   # `owner init` already set forget_writers
    assert all(vocabulary.split_module_name(k) is None for k in hv.GOVERNED_KEYS)


def test_a_node_key_is_an_unknown_config_key_and_journals_nothing(home):
    before, configs = len(_journal(home)), _set_configs(home)
    for key in NODE:
        r = _run(home, "config", "set", key, "1", check=False)
        assert r.returncode == 1 and f"unknown config key {key!r}" in r.stdout, key
    assert len(_journal(home)) == before and _set_configs(home) == configs


def test_every_range_and_choice_check_is_driven_by_the_table(tmp_path, monkeypatch, home):
    hv = _loadhv(tmp_path, monkeypatch)
    n = 0
    for key, spec in hv.GOVERNED_KEYS.items():
        for bad in _bad_values(spec) + (["nope"] if "choices" in spec and spec["type"] == "str" else []):
            before = len(_journal(home))
            r = _run(home, "config", "set", key, bad, check=False)
            assert r.returncode == 1 and spec["error"] in r.stdout, (key, bad, r.stdout)
            assert len(_journal(home)) == before
            n += 1
        if "min" in spec and not spec.get("min_exclusive"):           # the inclusive bound itself is accepted
            assert _run(home, "config", "set", key, str(spec["min"])).returncode == 0
    assert n >= 20


@pytest.mark.parametrize("args,needle", [
    (("cap_self", "abc"), "bad value for cap_self: 'abc'"),
    (("quorum_m", "1.5"), "bad value for quorum_m: '1.5'"),
    (("no_such_key", "1"), "unknown config key 'no_such_key'"),
    (("forget_writers", "legacy"), "forget_writers=legacy is no longer honoured"),
    (("x-hwatch:k", "y" * (vocabulary.MODULE_VALUE_MAX + 1)), "bad value for x-hwatch:k"),
])
def test_each_refusal_exits_1_and_journals_nothing(home, args, needle):
    before = len(_journal(home))
    for verb in (("config", "set"), ("config", "confidence", "set"), ("config", "quorum", "set")):
        r = _run(home, *verb, *args, check=False)
        assert r.returncode == 1 and needle in r.stdout, (verb, r.stdout, r.stderr)
    assert len(_journal(home)) == before


def test_a_device_without_the_owner_key_exits_1(tmp_path):
    r = _run(tmp_path, "config", "set", "cap_self", "0.5", check=False)
    assert r.returncode == 1 and "does not hold the owner key" in r.stdout


def test_the_success_path_output_and_code_are_unchanged(home):
    for args, out in ((("cap_self", "0.5"), "set cap_self = 0.5\n"), (("quorum_m", "2"), "set quorum_m = 2\n"),
                      (("quorum_by", "principal"), "set quorum_by = principal\n"),
                      (("x-hwatch:poll", "30s"), "set x-hwatch:poll = 30s\n")):
        r = _run(home, "config", "set", *args)
        assert r.returncode == 0 and r.stdout == out, (args, r.stdout)
    again = _run(home, "config", "set", "x-hwatch:poll", "30s")           # a no-op is still a success
    assert again.returncode == 0 and "is already '30s': nothing to sign" in again.stdout


def test_schema_json_lists_both_tables_and_no_refusal_text(tmp_path, monkeypatch, home):
    hv = _loadhv(tmp_path, monkeypatch)
    r = _run(home, "config", "schema", "--json")
    doc = json.loads(r.stdout)
    assert doc["schema"] == 1
    assert [k["id"] for k in doc["governed"]] == list(hv.GOVERNED_KEYS)
    assert [k["id"] for k in doc["node"]] == NODE
    by = {k["id"]: k for k in doc["governed"]}
    assert by["cap_self"]["default"] == 0.7 and by["quorum_by"]["choices"] == ["device", "principal"]
    assert by["flood_per_minute"]["min"] == 1 and by["trust_drift_threshold"]["max"] == 0.0
    assert all("error" not in k and k["description"] for k in doc["governed"] + doc["node"])
    assert all(isinstance(k["help"], str) and len(k["help"]) > 40 and k["help"] != k["description"]
               for k in doc["governed"] + doc["node"])                      # every core key explains itself in plain text
    assert {k["id"]: k["choices"] for k in doc["node"] if "choices" in k}["sync_auth"] == ["off", "permissive", "enforce"]
    assert _run(home, "config", "schema").returncode == 0                  # the text form works too


def test_show_json_reports_source_set_by_and_the_governance_block(tmp_path, monkeypatch, home):
    hv = _loadhv(tmp_path, monkeypatch)
    _run(home, "config", "set", "cap_self", "0.5")
    _run(home, "config", "set", "quorum_m", "2")
    _run(home, "config", "set", "cap_self", "0.6")                         # the later entry is the one `set_by` names
    doc = json.loads(_run(home, "config", "show", "--json").stdout)
    rows = {k["id"]: k for k in doc["governed"]}
    assert list(rows) == list(hv.GOVERNED_KEYS) and doc["schema"] == 1
    last = {}
    for e in _journal(home):
        p = e.get("payload") or {}
        if e.get("type") == "governance" and p.get("action") == "set-config":
            last[p["key"]] = e
    for key in ("cap_self", "quorum_m"):
        e = last[key]
        assert rows[key]["source"] == "fleet"
        assert rows[key]["set_by"] == {"device_id": e["node_id"], "ts": e["timestamp"],
                                       "sid": hv._short_id(e["node_id"], e["seq"])}
    assert rows["cap_self"]["value"] == 0.6 and rows["quorum_m"]["value"] == 2
    assert rows["cap_self"]["set_by"]["sid"] != hv._short_id(last["quorum_m"]["node_id"], last["quorum_m"]["seq"])
    assert rows["w_links"] == {"id": "w_links", "value": hv.CONF_W_LINKS, "default": hv.CONF_W_LINKS,
                               "source": "default", "set_by": None}
    g = doc["governance"]
    assert g["quorum_m"] == 2 and g["owner_id"] and isinstance(g["admitted"], list)
    assert all(set(a) == {"device_id", "principal"} for a in g["admitted"])
    assert _run(home, "config", "show").returncode == 0


def test_show_and_schema_carry_no_key_material(home):
    keyfiles = [p for p in Path(home).rglob("*") if p.is_file() and "key" in p.name.lower()]
    secrets = [p.read_text().strip() for p in keyfiles if p.stat().st_size < 400]
    for verb in ("schema", "show"):
        out = _run(home, "config", verb, "--json").stdout
        assert not any(s and s in out for s in secrets)
        assert "seed" not in out and "passphrase" not in out


def test_config_set_holds_no_key_table_of_its_own():
    import ast
    src = (PROJECT / "hivemind_owner.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "_config_set")
    strs = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    hv = _loadhv_names()
    assert not (strs & (hv - {"forget_writers"})), strs & hv         # membership and ranges live in GOVERNED_KEYS only


def _loadhv_names():
    import ast
    tree = ast.parse("\n".join(p.read_text(encoding="utf-8") for p in sorted((PROJECT / "hivemind" / "parts").glob("*.py"))))
    table = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") == "GOVERNED_KEYS" for t in n.targets))
    return {k.value for k in table.keys}
