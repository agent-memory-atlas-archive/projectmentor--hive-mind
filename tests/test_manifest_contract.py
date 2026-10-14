"""3.1 manifest contract 1 (#294, design `module_contract_3_1.md` §2, §4, §6, §13): the optional `contract`, `cli`,
`runtimes`, `config_schema`, `status`, `doctor`, `reads` and `ui` fields. This is what core accepts as a signed
manifest, so every rule has a row that fails without it, and a 3.0-shaped manifest must still be accepted unchanged."""

import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import ed25519  # noqa: E402
import hive_modules  # noqa: E402
from hive_modules import ModuleError, validate_manifest  # noqa: E402

SEED = bytes(range(1, 33))
PUB = base64.b64encode(ed25519.pub_from_seed(SEED)).decode()
CORE = "3.1"


def manifest(**extra):
    base = {"name": "demo", "version": "1", "min_core": "3.1", "publisher": PUB, "files": {"run.sh": "0" * 64},
            "contract": 1}
    base.update(extra)
    return {k: v for k, v in base.items() if v is not None}


def check(m, core=CORE):
    return validate_manifest(json.dumps(m).encode(), core)


def refused(m, needle=None, core=CORE):
    with pytest.raises(ModuleError) as e:
        check(m, core)
    if needle:
        assert needle in str(e.value)


# ── a 3.0-shaped manifest is accepted unchanged ──────────────────────────────────────────────────────

GOLDEN_30 = {"name": "demo", "version": "1", "min_core": "2.1", "publisher": PUB, "files": {"run.sh": "0" * 64, "hooks/stop": "1" * 64},
             "service": {"command": ["run.sh"], "restart": "always", "interval": 60, "stop_grace": 30}, "hooks": ["stop"],
             "config": {"poll": "30"}, "quota": {"per_hour": 10}}


def test_a_3_0_shaped_manifest_is_accepted_unchanged_on_a_3_1_node():
    for core in ("3.0", "3.1"):
        assert check(copy.deepcopy(GOLDEN_30), core) == GOLDEN_30
    minimal = {"name": "demo", "version": "1", "publisher": PUB, "files": {"run.sh": "0" * 64}}
    assert check(minimal) == minimal


@pytest.mark.parametrize("field,value", [("cli", {"name": "demo", "command": ["demo"]}), ("runtimes", ["claude"]),
                                          ("config_schema", {}), ("status", ["demo", "status"]), ("doctor", ["demo", "doctor"]),
                                          ("reads", ["overview"]), ("ui", {"schema": 1})])
def test_a_new_field_without_contract_is_refused(field, value):
    m = copy.deepcopy(GOLDEN_30)
    m[field] = value
    refused(m, "without `contract`")


# ── contract ──────────────────────────────────────────────────────────────────────────────────────────

def test_contract_one_with_no_other_field_is_accepted():
    assert check(manifest())["contract"] == 1


@pytest.mark.parametrize("bad", [2, 0, -1, 1.0, "1", True, None, [1], {"v": 1}])
def test_an_unknown_contract_is_refused(bad):
    refused({**manifest(), "contract": bad}, "contract")


def test_contract_and_config_together_are_refused():
    refused(manifest(config={"poll": "30"}), "both `contract` and `config`")


@pytest.mark.parametrize("min_core", [None, "0", "2.4", "3", "3.0", "3.0.9"])
def test_contract_one_needs_min_core_three_one(min_core):
    refused(manifest(min_core=min_core), "min_core 3.1")


def test_min_core_three_one_or_newer_is_accepted_and_a_3_0_node_refuses_it():
    for ok in ("3.1", "3.1.0", "3.2"):
        assert check(manifest(min_core=ok), "3.9")["min_core"] == ok
    refused(manifest(), "needs core 3.1", core="3.0")


# ── argv fields: cli.command, status, doctor ──────────────────────────────────────────────────────────

BAD_ARGV = [[], "demo status", [""], [1], ["a", None], ["../x"], ["sub/../../x"], ["ok", "bad\narg"], ["bad\x00"], ["x"] * 65,
            ["x" * 1025], {"a": 1}, None]


@pytest.mark.parametrize("field", ["status", "doctor"])
def test_status_and_doctor_take_an_argv(field):
    assert check(manifest(**{field: ["demo", field, "--json"]}))[field] == ["demo", field, "--json"]
    assert check(manifest(**{field: ["/usr/bin/env", "demo"]}))
    for bad in BAD_ARGV:
        if bad is None:
            continue
        refused(manifest(**{field: bad}), field)


def test_cli_needs_exactly_a_name_and_a_command():
    good = {"name": "hwatch", "command": ["hwatch"]}
    assert check(manifest(cli=good))["cli"] == good
    for bad in ({"name": "hwatch"}, {"command": ["x"]}, {**good, "extra": 1}, "hwatch", ["hwatch"], {}, None):
        refused({**manifest(), "cli": bad}, "cli")
    for bad in BAD_ARGV:
        if isinstance(bad, list) and bad or bad in ([], ""):
            refused(manifest(cli={"name": "hwatch", "command": bad}), "cli command")


@pytest.mark.parametrize("name", ["", "a", "Hwatch", "1hwatch", "hw atch", "hw_atch", "hw/atch", "-hwatch", "../hw", "x" * 33,
                                   "hv", "hive-mind", "hive-dispatch", "hive-anything", "module", "hwatch\n", "hw.atch", 7, None])
def test_cli_name_rules_and_the_names_core_uses(name):
    refused(manifest(cli={"name": name, "command": ["x"]}), "cli")


def test_cli_name_at_the_edges_is_accepted():
    for ok in ("ab", "a" + "b" * 31, "a-1-b"):
        assert check(manifest(cli={"name": ok, "command": ["x"]}))


# ── runtimes ──────────────────────────────────────────────────────────────────────────────────────────

def test_runtimes_are_program_names_never_paths():
    assert check(manifest(runtimes=["claude", "grok", "node.js", "x_y-z"]))["runtimes"]
    assert check(manifest(runtimes=[]))["runtimes"] == []
    for bad in (["/usr/bin/claude"], ["bin/claude"], ["../claude"], [".."], ["."], ["-rf"], [""], ["a b"], ["a;b"], ["a\n"],
                ["claude", "claude"], [1], "claude", {"a": 1}, ["x"] * 17, ["x" * 65]):
        refused(manifest(runtimes=bad), "runtimes")


# ── reads ─────────────────────────────────────────────────────────────────────────────────────────────

def test_reads_name_only_known_routes_once():
    assert check(manifest(reads=list(hive_modules.READ_ROUTES)))
    assert check(manifest(reads=[]))
    for bad in (["unknown"], ["overview", "overview"], ["feed"], ["status"], "overview", [1], [["overview"]], {"overview": 1}):
        refused(manifest(reads=bad), "reads")


# ── config_schema ─────────────────────────────────────────────────────────────────────────────────────

def spec(**kw):
    return {"type": "string", "description": "d", **kw}


GOOD_SCHEMA = {
    "seat.{role}.runtime": {"type": "enum", "values": ["claude", "grok"], "scope": "node", "required_at_install": True,
                            "description": "Runtime this node uses for the seat"},
    "operator.name": {"type": "string", "max": 80, "scope": "fleet", "required_at_install": True, "identifying": True,
                      "description": "Name shown for the operator"},
    "channel.github.token": {"type": "string", "scope": "node", "secret": True, "description": "token"},
    "seat.{role}.enabled": {"type": "bool", "default": "false", "scope": "fleet-node", "description": "on or off"},
    "poll": {"type": "int", "min": 5, "max": 3600, "default": "30", "description": "seconds"},
}


def test_the_design_example_schema_is_accepted():
    assert check(manifest(config_schema=GOOD_SCHEMA))["config_schema"] == GOOD_SCHEMA
    assert check(manifest(config_schema={}))


def test_scope_defaults_to_node_and_a_secret_may_leave_it_out():
    assert check(manifest(config_schema={"k": spec(secret=True)}))


BAD_ENTRIES = {
    "not an object": "string", "unknown field": spec(colour="red"), "no type": {"description": "d"}, "bad type": spec(type="float"),
    "bad scope": spec(scope="global"), "no description": {"type": "string"}, "empty description": spec(description="  "),
    "long description": spec(description="x" * 401), "control description": spec(description="a\nb"),
    "flag not bool": spec(secret="yes"), "required not bool": spec(required_at_install=1),
    "identifying not bool": spec(identifying="true"),
    "identifying with a default": spec(identifying=True, default="acme"),
    "identifying with an empty default": spec(identifying=True, default=""),
    "secret with a default": spec(secret=True, default="x"),
    "secret fleet": spec(secret=True, scope="fleet"), "secret fleet-node": spec(secret=True, scope="fleet-node"),
    "default not a string": spec(default=5), "default too long": spec(default="x" * 4097),
    "default control": spec(default="a\nb"), "default over max": spec(max=3, default="abcd"),
    "string max zero": spec(max=0), "string max huge": spec(max=4097), "string max bool": spec(max=True),
    "string min": spec(min=1), "string values": spec(values=["a"]),
    "int bad default": spec(type="int", default="x"), "int default float": spec(type="int", default="1.5"),
    "int default below min": spec(type="int", min=5, default="4"), "int default above max": spec(type="int", max=5, default="6"),
    "int min above max": spec(type="int", min=9, max=1), "int min string": spec(type="int", min="1"),
    "int bounds bool": spec(type="int", max=True), "int values": spec(type="int", values=["1"]),
    "int huge": spec(type="int", default="9" * 30),
    "bool default": spec(type="bool", default="yes"), "bool max": spec(type="bool", max=1),
    "enum no values": spec(type="enum"), "enum empty values": spec(type="enum", values=[]),
    "enum dup": spec(type="enum", values=["a", "a"]), "enum non-string": spec(type="enum", values=[1]),
    "enum empty value": spec(type="enum", values=[""]), "enum long value": spec(type="enum", values=["x" * 81]),
    "enum too many": spec(type="enum", values=[str(i) for i in range(65)]),
    "enum default not a value": spec(type="enum", values=["a"], default="b"), "enum max": spec(type="enum", values=["a"], max=3),
}


@pytest.mark.parametrize("why", sorted(BAD_ENTRIES))
def test_a_bad_schema_entry_is_refused(why):
    refused(manifest(config_schema={"k": BAD_ENTRIES[why]}), "config_schema")


@pytest.mark.parametrize("key", ["", "-a", ".a", "a b", "a:b", "a/b", "x" * 65, "a.{role", "a.{Role}.b", "a.{}.b", "a.x{role}", "{r}{s}",
                                 "a\n"])
def test_a_bad_schema_key_is_refused(key):
    refused(manifest(config_schema={key: spec()}), "config_schema")


def test_a_brace_word_is_a_whole_segment_only():
    assert check(manifest(config_schema={"seat.{role}.x": spec(), "{a}": spec(), "a-b_c.d": spec()}))


def test_a_schema_with_too_many_keys_is_refused():
    refused(manifest(config_schema={f"k{i}": spec() for i in range(129)}), "config_schema")
    assert check(manifest(config_schema={f"k{i}": spec() for i in range(128)}))


def test_config_schema_must_be_an_object():
    for bad in ([], "x", 3, None):
        refused({**manifest(), "config_schema": bad}, "config_schema")


@pytest.mark.parametrize("sp,value,ok", [
    ({"type": "string", "max": 3}, "abc", True), ({"type": "string", "max": 3}, "abcd", False),
    ({"type": "bool"}, "true", True), ({"type": "bool"}, "True", False), ({"type": "int", "min": 1, "max": 3}, "3", True),
    ({"type": "int", "min": 1, "max": 3}, "4", False), ({"type": "int"}, "-2", True), ({"type": "int"}, "1e3", False),
    ({"type": "enum", "values": ["a"]}, "a", True), ({"type": "enum", "values": ["a"]}, "b", False),
    ({"type": "string"}, "a\nb", False), ({"type": "string"}, 5, False)])
def test_config_value_problem_is_the_one_value_rule(sp, value, ok):
    assert (hive_modules.config_value_problem(sp, value) is None) is ok


# ── ui ────────────────────────────────────────────────────────────────────────────────────────────────

UI = {
    "schema": 1, "title": "hwatch", "summary": "Agent seats",
    "metrics": [{"id": "lag", "label": "Wake lag", "unit": "s", "from": "status", "path": "seats[*].lag"}],
    "panels": [{"id": "seats", "widget": "table", "title": "seats", "from": "status", "path": "seats",
                "columns": ["role", "runtime"]},
               {"id": "sessions", "widget": "timeline", "title": "sessions", "from": "entities", "prefix": "x-demo:session:",
                "group_by": "goal"}],
    "slots": {"agents": ["seats", "sessions"], "spend": ["budget"]}, "dimensions": ["role", "runtime"],
    "actions": [{"id": "drain", "label": "Drain", "command": ["hwatch", "wait", "--role", "{role}", "--timeout", "1"],
                 "params": {"role": {"enum_from": "status:seats[*].role"}}, "confirm": "Acknowledge?", "owner": False}],
}


def with_ui(**edits):
    ui = copy.deepcopy(UI)
    for k, v in edits.items():
        if v is None:
            ui.pop(k, None)
        else:
            ui[k] = v
    return manifest(ui=ui)


def test_the_design_ui_block_is_accepted():
    assert check(manifest(ui=UI))["ui"] == UI
    assert check(manifest(ui={"schema": 1}))


def test_unknown_widgets_slots_and_item_fields_are_accepted_but_top_level_keys_are_not():
    ui = copy.deepcopy(UI)
    ui["panels"][0]["widget"] = "hologram"
    ui["panels"][0]["future_field"] = {"anything": [1]}
    ui["slots"]["unheard-of"] = ["x"]
    assert check(manifest(ui=ui))
    refused(with_ui(typo_panels=[]), "ui")
    refused(with_ui(status={"command": "hwatch status"}), "ui")      # the manifest's `status` is the data source


@pytest.mark.parametrize("bad", [2, 0, "1", True, 1.0, None])
def test_an_unknown_ui_schema_is_refused(bad):
    refused(manifest(ui={"schema": bad}), "ui")
    refused(manifest(ui={}), "ui")


def test_ui_must_be_an_object_within_its_size():
    for bad in ([], "x", 1, None):
        refused({**manifest(), "ui": bad}, "ui")
    refused(manifest(ui={"schema": 1, "summary": "x" * 70000}), "ui")


def test_ui_over_64_kib_is_refused_even_if_every_string_is_short():
    ui = {"schema": 1, "metrics": [{"id": f"m{i}", "label": "l" * 80, "from": "status", "path": "a"} for i in range(32)],
          "panels": [{"id": f"p{i}", "widget": "w", "title": "t" * 80, "from": "status", "columns": ["c" * 64] * 32,
                      "x": "y" * 3000} for i in range(32)]}
    assert len(json.dumps(ui)) > 64 * 1024
    refused(manifest(ui=ui), "64")


UI_BAD = {
    "no id": lambda u: u["panels"][0].pop("id"), "bad id": lambda u: u["panels"][0].update(id="Bad Id"),
    "dup panel id": lambda u: u["panels"][1].update(id="seats"), "dup metric id": lambda u: u["metrics"].append(dict(u["metrics"][0])),
    "dup action id": lambda u: u["actions"].append(dict(u["actions"][0])),
    "free http source": lambda u: u["panels"][0].update(**{"from": "https://evil.example/x"}),
    "unknown source": lambda u: u["metrics"][0].update(**{"from": "sql"}),
    "path expression": lambda u: u["metrics"][0].update(path="a[?(@.x>1)]"),
    "path eval": lambda u: u["metrics"][0].update(path="a.b();"),
    "entities of another module": lambda u: u["panels"][1].update(prefix="x-other:"),
    "entities without a prefix": lambda u: u["panels"][1].pop("prefix"),
    "entities with a core prefix": lambda u: u["panels"][1].update(prefix="fact"),
    "control in a title": lambda u: u["panels"][0].update(title="a\x1b[31mb"),
    "control in a key": lambda u: u["panels"][0].update(**{"bad\nkey": 1}),
    "control nested in an unknown field": lambda u: u["panels"][0].update(future={"deep": ["a\x00b"]}),
    "title too long": lambda u: u.update(title="t" * 81), "empty title": lambda u: u.update(title=""),
    "too many panels": lambda u: u.update(panels=[{"id": f"p{i}", "widget": "w", "title": "t", "from": "status"} for i in range(33)]),
    "panels not a list": lambda u: u.update(panels={}),
    "action command is a string": lambda u: u["actions"][0].update(command="hwatch wait"),
    "action command empty": lambda u: u["actions"][0].update(command=[]),
    "action command climbs": lambda u: u["actions"][0].update(command=["../x", "{role}"]),
    "action first word is a parameter": lambda u: u["actions"][0].update(command=["{role}"]),
    "action placeholder with no parameter": lambda u: u["actions"][0].update(command=["hwatch", "{role}", "{mode}"]),
    "action parameter never used": lambda u: u["actions"][0]["params"].update(mode={"enum": ["a"]}),
    "free-text parameter": lambda u: u["actions"][0]["params"].update(role={"type": "string"}),
    "empty parameter": lambda u: u["actions"][0]["params"].update(role={}),
    "parameter pattern": lambda u: u["actions"][0]["params"].update(role={"pattern": ".*"}),
    "enum_from another source": lambda u: u["actions"][0]["params"].update(role={"enum_from": "http:x"}),
    "owner not bool": lambda u: u["actions"][0].update(owner="yes"),
    "slot ids not a list": lambda u: u["slots"].update(agents="seats"),
}


@pytest.mark.parametrize("why", sorted(UI_BAD))
def test_a_bad_ui_block_is_refused(why):
    ui = copy.deepcopy(UI)
    UI_BAD[why](ui)
    refused(manifest(ui=ui), "ui")


def test_a_deeply_nested_manifest_is_a_refusal_not_a_crash():
    raw = b'{"name":"demo","ui":' + b"[" * 100000 + b"]" * 100000 + b"}"
    with pytest.raises(ModuleError):
        validate_manifest(raw, CORE)


def test_the_ui_schema_file_uses_only_keywords_the_checker_implements():
    schema = json.loads((PROJECT / "docs" / "ui_block.schema.json").read_text())
    seen = set()

    def walk(node, in_properties=False):
        if isinstance(node, dict):
            for k, v in node.items():
                if not in_properties:
                    seen.add(k)
                walk(v, in_properties=(k == "properties"))
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(schema)
    assert seen <= hive_modules.SCHEMA_KEYWORDS, sorted(seen - hive_modules.SCHEMA_KEYWORDS)


def test_a_missing_ui_schema_file_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(hive_modules, "_ui_schema_cache", [])
    monkeypatch.setattr(hive_modules, "ui_schema_path", lambda: tmp_path / "nope.json")
    refused(manifest(ui={"schema": 1}), "ui_block.schema.json")


def test_the_mini_checker_enforces_each_keyword_it_claims():
    chk = hive_modules._schema_check
    cases = [({"type": "integer"}, True), ({"type": "integer"}, 1.5), ({"const": 1}, True), ({"enum": ["a"]}, "b"),
             ({"minLength": 2}, "a"), ({"maxLength": 1}, "ab"), ({"pattern": "a+"}, "ab"), ({"minimum": 2}, 1),
             ({"maximum": 2}, 3), ({"minItems": 1}, []), ({"maxItems": 1}, [1, 2]), ({"items": {"type": "string"}}, [1]),
             ({"minProperties": 1}, {}), ({"maxProperties": 1}, {"a": 1, "b": 2}), ({"required": ["a"]}, {}),
             ({"properties": {"a": {"type": "string"}}}, {"a": 1}), ({"additionalProperties": False}, {"a": 1}),
             ({"additionalProperties": {"type": "string"}}, {"a": 1}), ({"type": "string"}, 1), ({"type": "boolean"}, 1)]
    for schema, value in cases:
        with pytest.raises(ModuleError):
            chk(value, schema, "x")
    chk(1, {"type": "integer", "minimum": 1, "maximum": 1}, "x")


# ── `module check` ────────────────────────────────────────────────────────────────────────────────────

STATUS_OK = {"schema": 1, "state": "ok", "version": "1", "problems": [], "units": [{"name": "u", "state": "active"}], "detail": {}}
DOCTOR_OK = {"schema": 1, "results": [{"level": "ok", "check": "c", "message": "m"}]}


def publish(root, files=None, sign=True, **extra):
    body = {"run.sh": "#!/bin/sh\nexit 0\n", **(files or {})}
    for rel, text in body.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
        (root / rel).chmod(0o755)
    m = manifest(files={r: hashlib.sha256(t.encode()).hexdigest() for r, t in body.items()}, **extra)
    raw = json.dumps(m, indent=1).encode()
    (root / "module.json").write_bytes(raw)
    if sign:
        (root / "module.json.sig").write_text(base64.b64encode(ed25519.sign(raw, SEED)).decode())
    return m


def script(obj, code=0):
    return f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(obj)}\nEOF\nexit {code}\n"


def full_module(root, status=STATUS_OK, doctor=DOCTOR_OK, doctor_rc=0, status_rc=0):
    return publish(root, files={"status.sh": script(status, status_rc), "doctor.sh": script(doctor, doctor_rc)},
                   status=["status.sh"], doctor=["doctor.sh"], cli={"name": "demo", "command": ["run.sh"]})


def test_check_passes_a_conforming_module_and_runs_it(tmp_path):
    full_module(tmp_path)
    assert hive_modules.check_module(tmp_path, CORE, run=True) == ([], [hive_modules.NO_COMMANDS_WARNING])


def test_check_reports_what_install_would_refuse(tmp_path):
    publish(tmp_path, ui={"schema": 9})
    errors, _ = hive_modules.check_module(tmp_path, CORE)
    assert errors and "ui" in errors[0]
    assert hive_modules.check_module(tmp_path / "missing", CORE)[0]


def test_check_uses_the_same_validator_as_install(tmp_path, monkeypatch):
    full_module(tmp_path)
    seen = []
    real = hive_modules.validate_manifest
    monkeypatch.setattr(hive_modules, "validate_manifest", lambda raw, core: seen.append(core) or real(raw, core))
    hive_modules.check_module(tmp_path, CORE)
    assert seen == [CORE]


def test_check_catches_a_bad_signature_a_tampered_file_and_a_stray_file(tmp_path):
    full_module(tmp_path)
    (tmp_path / "module.json.sig").write_text(base64.b64encode(b"\0" * 64).decode())
    assert "signature" in hive_modules.check_module(tmp_path, CORE)[0][0]
    full_module(tmp_path)
    (tmp_path / "run.sh").write_text("#!/bin/sh\necho owned\n")
    assert "digest" in hive_modules.check_module(tmp_path, CORE)[0][0]
    full_module(tmp_path)
    (tmp_path / "stray").write_text("x")
    assert "stray" in hive_modules.check_module(tmp_path, CORE)[0][0]


def test_check_warns_on_an_unsigned_module_but_does_not_fail_it(tmp_path):
    publish(tmp_path, sign=False)
    errors, warnings = hive_modules.check_module(tmp_path, CORE)
    assert errors == [] and any("unsigned" in w for w in warnings)


def test_check_treats_a_3_0_manifest_as_a_warning_not_an_error(tmp_path):
    publish(tmp_path, contract=None, min_core="2.1", config={"a": "b"})
    errors, warnings = hive_modules.check_module(tmp_path, CORE)
    assert errors == [] and any("3.0-shaped" in w for w in warnings)


@pytest.mark.parametrize("status,rc,needle", [
    ({"schema": 1, "state": "great", "version": "1", "problems": []}, 0, "state"),
    ({"schema": 2, "state": "ok", "version": "1", "problems": []}, 0, "schema"),
    ({"schema": 1, "state": "ok", "problems": []}, 0, "version"),
    ({"schema": 1, "state": "ok", "version": "1", "problems": "none"}, 0, "problems"),
    ({"schema": 1, "state": "ok", "version": "1", "problems": [], "units": [1]}, 0, "units"),
    ({"schema": 1, "state": "ok", "version": "1", "problems": [], "detail": []}, 0, "detail"),
    ([], 0, "object"), (STATUS_OK, 3, "exited 3")])
def test_check_run_judges_the_status_envelope(tmp_path, status, rc, needle):
    full_module(tmp_path, status=status, status_rc=rc)
    errors, _ = hive_modules.check_module(tmp_path, CORE, run=True)
    assert errors and needle in " ".join(errors)


@pytest.mark.parametrize("doctor,rc,needle", [
    ({"schema": 1, "results": [{"level": "meh", "check": "c", "message": "m"}]}, 0, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": "c"}]}, 0, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": "c", "message": "m", "extra": "x"}]}, 0, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": "c", "message": "x" * 401}]}, 0, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": "c", "message": "m"}] * 101}, 0, "100"),
    ({"schema": 1, "results": "no"}, 0, "results"), ({"results": []}, 0, "schema"), ([], 0, "object"),
    ({"schema": 1, "results": [{"level": "fail", "check": "c", "message": "m"}]}, 0, "exited 0"),
    (DOCTOR_OK, 4, "exit 0")])
def test_check_run_judges_the_doctor_answer(tmp_path, doctor, rc, needle):
    full_module(tmp_path, doctor=doctor, doctor_rc=rc)
    errors, _ = hive_modules.check_module(tmp_path, CORE, run=True)
    assert errors and needle in " ".join(errors)


def test_a_doctor_may_report_a_fail_and_exit_non_zero(tmp_path):
    full_module(tmp_path, doctor={"schema": 1, "results": [{"level": "fail", "check": "c", "message": "m", "fix_hint": "do x"}]},
                doctor_rc=1)
    assert hive_modules.check_module(tmp_path, CORE, run=True)[0] == []


def test_check_run_catches_a_command_that_prints_no_json_or_is_missing(tmp_path):
    publish(tmp_path, files={"bad.sh": "#!/bin/sh\necho hello\n"}, status=["bad.sh"], doctor=["no-such-program-xyz"])
    errors, _ = hive_modules.check_module(tmp_path, CORE, run=True)
    assert any("did not print JSON" in e for e in errors) and any("not on PATH" in e for e in errors)


def test_check_run_stops_a_command_that_prints_too_much(tmp_path):
    publish(tmp_path, files={"big.sh": "#!/bin/sh\nexec yes\n"}, status=["big.sh"])
    errors, _ = hive_modules.check_module(tmp_path, CORE, run=True)
    assert any("more than" in e for e in errors)


def test_check_run_times_out(tmp_path, monkeypatch):
    monkeypatch.setattr(hive_modules, "CHECK_TIMEOUT", 1)
    publish(tmp_path, files={"slow.sh": "#!/bin/sh\nsleep 30\n"}, status=["slow.sh"])
    errors, _ = hive_modules.check_module(tmp_path, CORE, run=True)
    assert any("did not finish" in e for e in errors)


def test_check_run_gives_the_module_a_scrubbed_environment_in_a_throwaway_dir(tmp_path, monkeypatch):
    for k in ("HIVE_OWNER_SEED", "HIVE_HOME", "HIVE_KEY_DIR", "HIVE_IDENTITY_STASH", "SECRET_TOKEN"):
        monkeypatch.setenv(k, "leak")
    seen = []
    real = hive_modules._run_json

    def spy(argv, files, mod_dir, env):
        seen.append((dict(env), Path(mod_dir)))
        return real(argv, files, mod_dir, env)
    monkeypatch.setattr(hive_modules, "_run_json", spy)
    full_module(tmp_path)
    assert hive_modules.check_module(tmp_path, CORE, run=True)[0] == []
    assert len(seen) == 2
    for env, mod_dir in seen:
        assert set(env) == {"PATH", "HOME", "LANG", "HIVE_MODULE_NAME", "HIVE_MODULE_DIR", "HIVE_MODULE_KEY_DIR", "HIVE_DOCTOR_MODE"}
        assert "leak" not in " ".join(env.values())
        assert env["HIVE_MODULE_DIR"] == str(mod_dir) and tmp_path not in (mod_dir, *mod_dir.parents)
        assert env["HOME"].startswith(str(mod_dir.parent)) and env["HIVE_MODULE_KEY_DIR"].startswith(str(mod_dir.parent))


def test_check_does_not_run_anything_without_run(tmp_path):
    marker = tmp_path / "ran"
    publish(tmp_path, files={"s.sh": f"#!/bin/sh\ntouch {marker}\necho '{{}}'\n"}, status=["s.sh"], doctor=["s.sh"])
    hive_modules.check_module(tmp_path, CORE)
    assert not marker.exists()


@pytest.mark.parametrize("text,hit", [
    ("mail alice@example.com now", "email"), ("cd /home/alice/work", "home directory"), ("/Users/bob/x", "home directory"),
    ("ping @alice-dev", "@-handle"), ("see github.com/acme/secret-repo", "repository"), ("git@github.com:acme/r.git", "email")])
def test_check_lints_identifying_text_as_warnings(tmp_path, text, hit):
    publish(tmp_path, files={"README.md": text + "\n"})
    errors, warnings = hive_modules.check_module(tmp_path, CORE)
    assert errors == [] and any(hit in w for w in warnings), warnings


@pytest.mark.parametrize("text", ["cd /home/<user>/x", "/home/$USER", "/home/{user}", "github.com/<org>/<repo>", "github.com/{org}/{repo}",
                                  "a decorator @pytest.fixture is code", "no handle here", "~/.hive"])
def test_check_lint_leaves_placeholders_alone(tmp_path, text):
    publish(tmp_path, files={"README.md": text + "\n"})
    assert not [w for w in hive_modules.check_module(tmp_path, CORE)[1] if w.startswith("README.md")]


def test_check_lint_honours_deny_terms_and_skips_code_handles(tmp_path):
    publish(tmp_path, files={"README.md": "runs on Zeus\n", "x.py": "@staticmethod\n"})
    warnings = hive_modules.check_module(tmp_path, CORE, deny=["zeus"])[1]
    assert any("denied term 'zeus'" in w for w in warnings) and not any("x.py" in w for w in warnings)


def test_check_cli_exit_codes_and_json(tmp_path):
    full_module(tmp_path)

    class Lib:
        CONTRACT_VERSION = CORE
    ns = hive_modules.build_parser().parse_args(["check", str(tmp_path), "--run", "--json"])
    assert hive_modules.cmd_check(Lib, ns) == 0
    (tmp_path / "stray").write_text("x")
    assert hive_modules.cmd_check(Lib, ns) == 1
    assert hive_modules.main(Lib, ["check", str(tmp_path)]) == 1


def test_check_on_a_git_checkout_ignores_untracked_files(tmp_path):
    full_module(tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    (tmp_path / "scratch.txt").write_text("untracked")
    assert hive_modules.check_module(tmp_path, CORE)[0] == []


def test_check_on_a_git_checkout_does_not_run_its_fsmonitor_hook(tmp_path):
    full_module(tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    marker = tmp_path.parent / (tmp_path.name + "-pwned")
    subprocess.run(["git", "-C", str(tmp_path), "config", "core.fsmonitor", f"touch {marker}; false"], check=True)
    assert hive_modules.check_module(tmp_path, CORE)[0] == []
    assert not marker.exists()


# ── the `trust` tier (B9) ───────────────────────────────────────────────────────────────────────────

def test_trust_accepts_the_two_tiers_and_absence():
    for t in ("trusted", "confined"):
        assert check(manifest(trust=t))["trust"] == t
    assert "trust" not in check(manifest())
    assert hive_modules.signed_trust(check(manifest())) == "trusted"


@pytest.mark.parametrize("bad", ["root", "", "Trusted", None, 1, True, ["confined"]])
def test_trust_refuses_anything_else(bad):
    m = manifest()
    m["trust"] = bad
    refused(m, "trust")


def test_trust_needs_contract():
    m = manifest(trust="confined")
    del m["contract"]
    refused(m, "without `contract`")


def test_effective_trust_is_the_lower_and_never_above_signed():
    eff = hive_modules.effective_trust
    assert eff({}) == "trusted"
    assert eff({"trust": "confined"}) == "confined"
    assert eff({"trust_local": "confined"}) == "confined"
    assert eff({"trust": "confined", "trust_local": "trusted"}) == "confined"
    assert eff({"trust_local": "bogus"}) == "trusted"


def test_trust_record_and_summary():
    assert hive_modules._trust_record(manifest()) == {}
    assert hive_modules._trust_record(manifest(trust="trusted")) == {}
    assert hive_modules._trust_record(manifest(trust="confined")) == {"trust": "confined"}
    assert "TRUSTED" in hive_modules.trust_summary(manifest())
    assert "confined" in hive_modules.trust_summary(manifest(trust="confined"))


def test_trust_raise_on_update_needs_owner(monkeypatch):
    class Lib:
        def _owner_key_exists(self):
            return False
    with pytest.raises(ModuleError):
        hive_modules._check_trust_raise(Lib(), {"trust": "confined"}, manifest())
    hive_modules._check_trust_raise(Lib(), {"trust": "confined"}, manifest(trust="confined"))
    hive_modules._check_trust_raise(Lib(), {}, manifest(trust="confined"))
    hive_modules._check_trust_raise(Lib(), {}, manifest())


def test_trust_verb_lowers_without_owner_and_raise_needs_it(tmp_path, monkeypatch, capsys):
    saved = {}
    state = {"demo": {"version": "1"}}
    monkeypatch.setattr(hive_modules, "load_state", lambda lib: state)
    monkeypatch.setattr(hive_modules, "save_state", lambda lib, s: saved.update(s))
    monkeypatch.setattr(hive_modules, "_reapply_names", lambda lib, names: None)    # the re-render has its own test

    class Lib:
        def _owner_key_exists(self):
            return False
    ns = lambda tier: type("A", (), {"name": "demo", "tier": tier})()  # noqa: E731
    hive_modules.cmd_trust(Lib(), ns("confined"))
    assert state["demo"]["trust_local"] == "confined" and hive_modules.effective_trust(state["demo"]) == "confined"
    with pytest.raises(ModuleError):
        hive_modules.cmd_trust(Lib(), ns("trusted"))
    assert state["demo"]["trust_local"] == "confined"
    state["demo"] = {"version": "1", "trust": "confined"}
    hive_modules.cmd_trust(Lib(), ns("trusted"))
    assert hive_modules.effective_trust(state["demo"]) == "confined"


# ── config_schema help (4.1) ──────────────────────────────────────────────────────────────────────────

def test_a_config_entry_may_carry_help_text():
    m = manifest(config_schema={"k": spec(help="Plain words about the setting.")})
    assert check(m)["config_schema"]["k"]["help"] == "Plain words about the setting."


@pytest.mark.parametrize("bad", ["", "   ", "x" * 401, "two\nlines", "bell\x07", 5, ["a"], None, True])
def test_a_bad_help_is_refused(bad):
    refused(manifest(config_schema={"k": spec(help=bad)}), "help")


def test_help_may_be_exactly_the_description_length():
    assert check(manifest(config_schema={"k": spec(help="x" * 400)}))
