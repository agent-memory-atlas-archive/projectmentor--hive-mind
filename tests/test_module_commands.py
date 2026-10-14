"""4.2 declared module commands (design `module_commands_4_2.md` §2, §4.5, §5): the `commands` manifest field, `module
commands`, the install-summary table, the `module check` warning and the doctor's undo probe, and the pin that
`module run` hands `--dry-run`, `--yes`, `--` and an argument with spaces to the module as one word each."""

import base64
import hashlib
import json
import os
import stat
import sys
import time
import types
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import ed25519  # noqa: E402
import hive_module_doctor  # noqa: E402
import hive_modules  # noqa: E402
from hive_modules import ModuleError, validate_manifest  # noqa: E402

SEED = bytes(range(1, 33))
PUB = base64.b64encode(ed25519.pub_from_seed(SEED)).decode()
CORE = "4.2"

EXAMPLE = {
    "hygiene apply": {"mutates": True, "reversible": "yes", "undo": ["hygiene", "undo", "{id}"], "dry_run": True, "fleet": True},
    "hygiene undo": {"mutates": True, "reversible": "yes", "undo": ["hygiene", "apply", "{id}"], "dry_run": True},
    "hygiene list": {"mutates": False, "fleet": True},
    "restart": {"mutates": True, "reversible": "n/a", "dry_run": True},
    "stop": {"mutates": True, "reversible": "no", "dry_run": True},
}


def manifest(commands=EXAMPLE, **extra):
    base = {"name": "demo", "version": "1", "min_core": "4.2", "publisher": PUB, "files": {"run.sh": "0" * 64},
            "contract": 1, "cli": {"name": "demo", "command": ["run.sh"]}, "commands": commands}
    base.update(extra)
    return {k: v for k, v in base.items() if v is not None}


def check(m, core=CORE):
    return validate_manifest(json.dumps(m).encode(), core)


def refused(m, message):
    with pytest.raises(ModuleError) as e:
        check(m)
    assert str(e.value) == f"manifest commands {message}", str(e.value)


def entry(**kw):
    return manifest({"a b": kw})


# ── the validator: one row per rule of §2 ─────────────────────────────────────────────────────────

def test_the_five_verb_example_is_accepted_and_a_manifest_without_the_map_is_unchanged():
    assert check(manifest())["commands"] == EXAMPLE
    plain = manifest(commands=None, min_core="3.1")
    assert check(plain, "3.1") == plain


def test_commands_is_a_contract_key_and_nothing_else_changed():
    assert "commands" in hive_modules.CONTRACT_KEYS and "commands" in hive_modules.MANIFEST_KEYS
    assert hive_modules.MANIFEST_KEYS - {"commands"} == (
        hive_modules.BASE_KEYS | {"contract", "cli", "runtimes", "config_schema", "status", "doctor", "reads", "ui", "trust"})


@pytest.mark.parametrize("cmds", [[], "x", None, {f"v{i}": {"mutates": False} for i in range(65)}])
def test_not_an_object_or_over_64_verbs(cmds):
    m = manifest()
    m["commands"] = cmds
    refused(m, "must be an object of at most 64 verbs")


def test_64_verbs_are_accepted():
    check(manifest({f"v{i}": {"mutates": False} for i in range(64)}))


def test_needs_contract_and_a_cli():
    refused(manifest(contract=None), 'needs "contract": 1 and a cli')
    refused(manifest(cli=None), 'needs "contract": 1 and a cli')


def test_needs_min_core_4_2():
    refused(manifest(min_core="4.1"), "needs min_core 4.2 or newer (a 4.1 core refuses the field)")
    refused(manifest(min_core="3.1"), "needs min_core 4.2 or newer (a 4.1 core refuses the field)")
    with pytest.raises(ModuleError, match="needs core 4.2"):
        check(manifest(), "4.1")                      # a 4.1 core refuses the manifest as too new


@pytest.mark.parametrize("key", ["", "Stop", "1a", "-x", "a  b", " a", "a ", "a b c d e", "a_b", "x" * 33, "a/b"])
def test_a_bad_verb_key(key):
    with pytest.raises(ModuleError, match="a verb is 1 to 4 words of a-z, 0-9, -, separated by single spaces"):
        check(manifest({key: {"mutates": False}}))


def test_a_one_to_four_word_key_and_a_prefix_key_are_accepted():
    check(manifest({"a": {"mutates": False}, "a b": {"mutates": False}, "a b c d": {"mutates": False}, "x-1": {"mutates": False}}))


def test_unknown_entry_field():
    refused(entry(mutates=False, owner="x"), "a b: may only name: dry_run, fleet, mutates, reversible, undo")


@pytest.mark.parametrize("bad", [{}, {"mutates": "yes"}, {"mutates": 1}, {"mutates": None}])
def test_mutates_is_a_required_bool(bad):
    refused(entry(**bad), "a b: mutates must be true or false")
    refused(manifest({"a b": "x"}), "a b: mutates must be true or false")


@pytest.mark.parametrize("field,bad", [("dry_run", 1), ("dry_run", 0), ("dry_run", "true"), ("fleet", "no"), ("fleet", 1)])
def test_dry_run_and_fleet_must_be_json_booleans(field, bad):
    refused(entry(mutates=True, reversible="n/a", **{field: bad}), f"a b: {field} must be true or false")


@pytest.mark.parametrize("rev", [None, "maybe", "Yes", True, ""])
def test_a_mutating_verb_needs_a_reversible_word(rev):
    refused(entry(mutates=True, reversible=rev), "a b: reversible must be one of: yes, no, n/a")
    if rev is None:
        refused(entry(mutates=True), "a b: reversible must be one of: yes, no, n/a")


@pytest.mark.parametrize("rev", ["yes", "no", "maybe"])
def test_a_read_only_verb_is_reversible_na(rev):
    refused(entry(mutates=False, reversible=rev), "a b: a read-only verb is reversible n/a")
    check(entry(mutates=False, reversible="n/a"))


def test_undo_is_required_for_yes_and_only_then():
    refused(entry(mutates=True, reversible="yes"), "a b: undo is required for reversible yes and only then")
    refused(entry(mutates=True, reversible="no", undo=["a", "b"]), "a b: undo is required for reversible yes and only then")
    refused(entry(mutates=True, reversible="n/a", undo=["a", "b"]), "a b: undo is required for reversible yes and only then")
    refused(entry(mutates=False, undo=["a", "b"]), "a b: undo is required for reversible yes and only then")


MALFORMED = "a b: undo is an argv list of 1 to 16 words (placeholders {name}), no control characters"


@pytest.mark.parametrize("undo", [[], "a b", [""], ["a", ""], ["a", 1], ["a"] * 17, ["a", "x" * 129], ["a", "b\n"], ["a", "b\x00"],
                                  ["a", "--to\x9b2J"], ["a", "\x85--z"], ["a", "--to\u202eyes"], ["a", "--z\u200b"], ["a", "--z\u2028"],
                                  ["a", "--z\u2029"], ["a", "\x7f"],
                                  ["a", "b{id}"], ["a{id}"], ["a", "{id}x"], ["a", "{ID}"], ["a", "{}"], ["a", "{i d}"], ["a", "{id"],
                                  ["-a", "{id}"], ["a", "{" + "x" * 33 + "}"]])
def test_a_malformed_undo(undo):
    m = manifest({"a b": {"mutates": True, "reversible": "yes", "undo": undo, "dry_run": True}})
    refused(m, MALFORMED)


def test_an_empty_word_and_a_word_with_a_stray_brace_are_the_malformed_error():
    for undo in ([ "a", ""], ["a", "a{id}"]):
        refused(manifest({"a b": {"mutates": True, "reversible": "yes", "undo": undo}}), MALFORMED)


def test_undo_accepts_16_words_of_128_characters_and_a_flag_after_the_verb():
    cmds = {"a": {"mutates": True, "reversible": "yes", "undo": ["a", "--since", "{when}"] + ["w" * 128] * 13},
            "b": {"mutates": True, "reversible": "n/a"}}
    assert len(cmds["a"]["undo"]) == 16
    check(manifest(cmds))


def test_the_undo_verb_must_be_a_declared_mutating_verb():
    ro = {"a": {"mutates": True, "reversible": "yes", "undo": ["b", "{id}"]}, "b": {"mutates": False}}
    refused(manifest(ro), "a: undo names b, which is not a declared mutating verb")
    refused(manifest({"a": {"mutates": True, "reversible": "yes", "undo": ["gone", "{id}"]}}),
            "a: undo names gone, which is not a declared mutating verb")
    refused(manifest({"a": {"mutates": True, "reversible": "yes", "undo": ["{id}"]}}),
            "a: undo names , which is not a declared mutating verb")
    # leading words are the verb exactly: an extra literal word before the placeholder is not a verb of the map
    refused(manifest({"a": {"mutates": True, "reversible": "yes", "undo": ["a", "x", "{id}"]}}),
            "a: undo names a x, which is not a declared mutating verb")


def test_the_longest_matching_key_is_the_undo_verb():
    cmds = {"h": {"mutates": False}, "h u": {"mutates": True, "reversible": "n/a"},
            "h a": {"mutates": True, "reversible": "yes", "undo": ["h", "u", "{id}"]}}
    check(manifest(cmds))


def test_a_mutating_verb_takes_dry_run():
    refused(entry(mutates=True, reversible="n/a", dry_run=False), "a b: a mutating verb takes --dry-run (4.2): dry_run must be true")
    refused(entry(mutates=False, dry_run=True), "a b: dry_run applies to a mutating verb")
    check(entry(mutates=False, dry_run=False))
    check(entry(mutates=True, reversible="n/a"))


def test_an_irreversible_verb_is_never_fleet_runnable():
    refused(entry(mutates=True, reversible="no", fleet=True), "a b: an irreversible verb is never fleet-runnable")
    check(entry(mutates=True, reversible="no", fleet=False))


# ── `module commands`, the install summary ────────────────────────────────────────────────────────

def publish(root, commands=EXAMPLE, sign=True, tamper=None, seed=SEED, **extra):
    body = {"run.sh": "#!/bin/sh\nexit 0\n"}
    for rel, text in body.items():
        (root / rel).write_text(text)
        (root / rel).chmod(0o755)
    m = manifest(commands, files={r: hashlib.sha256(t.encode()).hexdigest() for r, t in body.items()}, **extra)
    raw = json.dumps(m, indent=1).encode()
    (root / "module.json").write_bytes(raw)
    if sign:
        (root / "module.json.sig").write_text(base64.b64encode(ed25519.sign(raw, seed)).decode())
    if tamper:
        (root / "run.sh").write_text(tamper)
    return m


class Lib:
    CONTRACT_VERSION = CORE
    _ensure_key_dir = staticmethod(lambda: "/nonexistent")


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A module `demo` in HIVE_MODULES_DIR with a record pinning the test publisher."""
    mods = tmp_path / "modules"
    (mods / "demo").mkdir(parents=True)
    monkeypatch.setenv("HIVE_MODULES_DIR", str(mods))
    state = tmp_path / "state.json"
    monkeypatch.setattr(hive_modules, "state_path", lambda lib: state)
    state.write_text(json.dumps({"demo": {"publisher": PUB, "version": "1"}}))
    return mods / "demo"


def run(argv, capsys):
    rc = hive_modules.main(Lib, argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_module_commands_text(installed, capsys):
    publish(installed)
    rc, out, _ = run(["commands", "demo"], capsys)
    assert rc == 0
    lines = out.splitlines()
    assert lines[0] == "demo 1 (contract 1, min_core 4.2): 5 declared verbs"
    assert lines[1] == "  hygiene list   read-only  fleet"                      # read-only verbs first
    assert lines[2] == "  hygiene apply  changes state  reversible  undo: demo hygiene undo <id>  --dry-run  fleet"
    assert lines[3] == "  hygiene undo   changes state  reversible  undo: demo hygiene apply <id>  --dry-run"
    assert lines[4] == "  restart        changes state  nothing to restore  --dry-run"
    assert lines[5] == "  stop           changes state  CANNOT BE UNDONE: needs --yes when not at a terminal  --dry-run"
    assert lines[6] == "a verb not listed here is undeclared: treat it as one that cannot be undone"


def test_module_commands_json_has_every_default_filled_in(installed, capsys):
    cmds = {"show": {"mutates": False}, "go": {"mutates": True, "reversible": "n/a"},
            "put": {"mutates": True, "reversible": "yes", "undo": ["go"], "fleet": True}}
    publish(installed, cmds)
    rc, out, _ = run(["commands", "demo", "--json"], capsys)
    assert rc == 0
    assert json.loads(out) == {
        "schema": 1, "module": "demo", "version": "1", "cli": "demo", "declared": True,
        "commands": {"show": {"mutates": False, "reversible": "n/a", "dry_run": False, "fleet": False},
                     "go": {"mutates": True, "reversible": "n/a", "dry_run": True, "fleet": False},
                     "put": {"mutates": True, "reversible": "yes", "undo": ["go"], "dry_run": True, "fleet": True}}}
    assert "undo" not in json.loads(out)["commands"]["show"]
    assert list(json.loads(out)["commands"]) == ["show", "go", "put"]            # the manifest's order


def test_module_commands_for_a_manifest_without_the_map(installed, capsys):
    publish(installed, None, min_core="3.1")
    rc, out, _ = run(["commands", "demo"], capsys)
    assert rc == 0 and out == ("demo 1: declares no commands (a 4.1 manifest); treat every verb as one that cannot be undone\n")
    rc, out, _ = run(["commands", "demo", "--json"], capsys)
    assert rc == 0 and json.loads(out) == {"schema": 1, "module": "demo", "version": "1", "cli": "demo", "declared": False, "commands": {}}


def test_module_commands_for_a_module_that_is_not_installed(installed, capsys):
    rc, _, err = run(["commands", "other"], capsys)
    assert rc == 1 and "module 'other' is not installed" in err


@pytest.mark.parametrize("how", ["tampered", "unsigned", "edited-map", "other-publisher"])
def test_module_commands_refuses_a_tree_that_does_not_verify(installed, capsys, how):
    if how == "tampered":
        publish(installed, tamper="#!/bin/sh\necho owned\n")
    elif how == "unsigned":
        publish(installed, sign=False)
    elif how == "edited-map":
        publish(installed)
        raw = (installed / "module.json").read_text().replace('"reversible": "no"', '"reversible": "yes"')
        (installed / "module.json").write_text(raw)
    else:                                   # a whole tree re-signed under a key the record does not pin
        other = bytes(range(2, 34))
        publish(installed, seed=other, publisher=base64.b64encode(ed25519.pub_from_seed(other)).decode())
    rc, out, err = run(["commands", "demo"], capsys)
    assert rc == 1 and out == "" and "hive-mind module:" in err


def test_a_disabled_module_is_refused(installed, capsys, tmp_path):
    publish(installed)
    (tmp_path / "state.json").write_text(json.dumps({"demo": {"publisher": PUB, "disabled": {"reason": "too old"}}}))
    rc, _, err = run(["commands", "demo"], capsys)
    assert rc == 1 and "disabled" in err


def test_the_install_summary_shows_the_table_and_a_4_1_manifest_prints_none(capsys):
    m = check(manifest())
    hive_modules._confirm_publisher(m, PUB)
    out = capsys.readouterr().out
    assert "  demo 1 (contract 1, min_core 4.2): 5 declared verbs\n" in out and "  stop  " in out
    hive_modules._confirm_publisher(check(manifest(None, min_core="3.1"), "3.1"), PUB)
    assert "declared verb" not in capsys.readouterr().out


# ── `module check` ────────────────────────────────────────────────────────────────────────────────

def test_check_warns_once_when_a_contract_manifest_with_a_cli_declares_no_commands(tmp_path):
    publish(tmp_path, None)
    errors, warnings = hive_modules.check_module(tmp_path, CORE)
    assert errors == [] and warnings.count(hive_modules.NO_COMMANDS_WARNING) == 1
    assert hive_modules.NO_COMMANDS_WARNING == ("manifest declares no commands (4.2): callers cannot tell which verbs change state "
                                                "or can be undone")


def test_check_has_no_warning_without_a_cli_or_without_contract(tmp_path):
    publish(tmp_path, None, cli=None)
    assert hive_modules.NO_COMMANDS_WARNING not in hive_modules.check_module(tmp_path, CORE)[1]
    publish(tmp_path, None, contract=None, cli=None, min_core="2.0")
    assert hive_modules.NO_COMMANDS_WARNING not in hive_modules.check_module(tmp_path, CORE)[1]


def test_check_json_carries_the_sentence_and_exits_0(tmp_path, capsys):
    publish(tmp_path, None)
    rc, out, _ = run(["check", str(tmp_path), "--json"], capsys)
    assert rc == 0 and hive_modules.NO_COMMANDS_WARNING in json.loads(out)["warnings"]
    rc, out, _ = run(["check", str(tmp_path)], capsys)
    assert rc == 0 and f"warning: {hive_modules.NO_COMMANDS_WARNING}" in out


def test_check_lists_the_na_verbs_in_one_warning_and_a_bad_map_is_an_error(tmp_path):
    publish(tmp_path)
    errors, warnings = hive_modules.check_module(tmp_path, CORE)
    assert errors == [] and hive_modules.NO_COMMANDS_WARNING not in warnings
    assert [w for w in warnings if "reversible n/a" in w] == [
        "verbs declared reversible n/a (nothing to restore; the core cannot check it, read them): restart"]
    publish(tmp_path, {"a": {"mutates": True, "reversible": "n/a", "dry_run": False}})
    errors, _ = hive_modules.check_module(tmp_path, CORE)
    assert errors == ["manifest commands a: a mutating verb takes --dry-run (4.2): dry_run must be true"]


# ── the doctor's undo probe ───────────────────────────────────────────────────────────────────────

def fake_cli(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def undo_manifest(n, tmp_path, body):
    tmp_path.mkdir(exist_ok=True)
    fake_cli(tmp_path / "run.sh", body)
    cmds = {}
    for i in range(n):
        cmds[f"u{i}"] = {"mutates": True, "reversible": "n/a"}
        cmds[f"f{i}"] = {"mutates": True, "reversible": "yes", "undo": [f"u{i}", "{id}"]}
    m = check(manifest(cmds))
    m["cli"] = {"name": "demo", "command": [str(tmp_path / "run.sh")]}
    return m


def probe(tmp_path, monkeypatch, m):
    monkeypatch.setenv("HIVE_MODULES_DIR", str(tmp_path.parent))
    return hive_module_doctor._undo_probe(tmp_path.name, {}, m, tmp_path / "keys")


def test_undo_verbs_are_distinct_and_in_manifest_order():
    cmds = {"a": {"mutates": True, "reversible": "yes", "undo": ["c", "{x}"]}, "b": {"mutates": True, "reversible": "yes", "undo": ["c", "{x}"]},
            "c": {"mutates": True, "reversible": "yes", "undo": ["a", "{x}"]}}
    assert hive_modules.undo_verbs(check(manifest(cmds))) == ["c", "a"]
    assert hive_modules.undo_verbs(check(manifest(None, min_core="3.1"), "3.1")) == []


def test_the_probe_runs_the_undo_verb_with_help_and_warns_on_a_failure(tmp_path, monkeypatch):
    m = undo_manifest(2, tmp_path, 'echo "$@" >> "$HIVE_MODULE_DIR/calls"; case "$1" in u1) exit 2;; esac\n')
    out = probe(tmp_path, monkeypatch, m)
    assert out == [("warn", "declared undo verb `u1` is not accepted by the module (--help exited 2)")]
    assert (tmp_path / "calls").read_text().splitlines() == ["u0 --help", "u1 --help"]


def test_the_probe_warns_on_a_missing_program_and_a_hang(tmp_path, monkeypatch):
    m = undo_manifest(1, tmp_path, "exit 0\n")
    m["cli"]["command"] = [str(tmp_path / "gone")]
    out = probe(tmp_path, monkeypatch, m)
    assert len(out) == 1 and out[0][0] == "warn" and "`u0`" in out[0][1] and "could not run" in out[0][1]
    m = undo_manifest(1, tmp_path, "sleep 30\n")
    monkeypatch.setattr(hive_modules, "DOCTOR_PROBE_TIMEOUT", 5)
    monkeypatch.setattr(hive_modules.probe_help, "__defaults__", (0.3,))
    out = probe(tmp_path, monkeypatch, m)
    assert out == [("warn", "declared undo verb `u0` is not accepted by the module (--help did not finish in 0.3 s)")]


def test_the_probe_stops_at_8_verbs_and_counts_the_rest(tmp_path, monkeypatch):
    m = undo_manifest(10, tmp_path, 'echo "$1" >> "$HIVE_MODULE_DIR/calls"; exit 1\n')
    out = probe(tmp_path, monkeypatch, m)
    assert [i for i in (tmp_path / "calls").read_text().split()] == [f"u{i}" for i in range(8)]
    assert out[-1] == ("warn", "2 declared undo verbs were not probed (the first 8 are)")
    assert len(out) == 9


def test_the_probe_environment_is_narrow(tmp_path, monkeypatch):
    m = undo_manifest(1, tmp_path, 'env | sort > "$HIVE_MODULE_DIR/env"\n')
    monkeypatch.setenv("HIVE_OWNER_PASSPHRASE", "secret")
    monkeypatch.setenv("HIVE_HOME", "/elsewhere")
    assert probe(tmp_path, monkeypatch, m) == []
    names = {line.split("=", 1)[0] for line in (tmp_path / "env").read_text().splitlines()}
    assert {n for n in names if n.startswith("HIVE_")} == {"HIVE_MODULE_NAME", "HIVE_MODULE_DIR", "HIVE_MODULE_KEY_DIR"}


@pytest.fixture
def doctor_module(tmp_path, monkeypatch):
    """A signed 4.2 module `demo`, its record and a stand-in `hv`, for `hive_module_doctor._module`."""
    mods = tmp_path / "modules"
    d = mods / "demo"
    d.mkdir(parents=True)
    monkeypatch.setenv("HIVE_MODULES_DIR", str(mods))
    fake_cli(d / "run.sh", 'echo "$@" >> "' + str(tmp_path / "calls") + '"; exit 3\n')
    cmds = {"u": {"mutates": True, "reversible": "n/a"}, "f": {"mutates": True, "reversible": "yes", "undo": ["u", "{id}"]}}
    publish_with_script(d, cmds, 'echo "$@" >> "' + str(tmp_path / "calls") + '"; exit 3\n')
    (d / "config").write_text("{}")
    hv = types.SimpleNamespace(KEY_DIR=str(tmp_path / "keys"), CONTRACT_VERSION=CORE, NODE_ID="n", HIVE_HOME=tmp_path)
    gov = {"purged": set(), "admitted": {"dev"}, "modules": {"dev": "demo"}, "config": {}}
    rec = {"publisher": PUB, "version": "1", "device_id": "dev"}
    (tmp_path / "keys" / "modules" / "demo").mkdir(parents=True)
    return hv, gov, rec, tmp_path


def publish_with_script(root, commands, script):
    (root / "run.sh").write_text("#!/bin/sh\n" + script)
    (root / "run.sh").chmod(0o755)
    m = manifest(commands, files={"run.sh": hashlib.sha256(("#!/bin/sh\n" + script).encode()).hexdigest()})
    raw = json.dumps(m, indent=1).encode()
    (root / "module.json").write_bytes(raw)
    (root / "module.json.sig").write_text(base64.b64encode(ed25519.sign(raw, SEED)).decode())
    return m


@pytest.mark.parametrize("mode,probed", [("manual", True), ("install", True), ("update", True), ("timer", False), ("boot", False)])
def test_the_doctor_probes_only_in_manual_install_and_update(doctor_module, monkeypatch, mode, probed):
    hv, gov, rec, tmp_path = doctor_module
    monkeypatch.setenv("HIVE_DOCTOR_MODE", mode)
    r = hive_module_doctor._module(hv, gov, "demo", rec, [], (True, 1), 0)
    assert (tmp_path / "calls").exists() == probed, r
    assert ("declared undo verb `u`" in r["detail"]) == probed
    assert r["status"] == ("warn" if probed else "ok"), r


def test_the_doctor_runs_no_module_code_for_another_publisher(doctor_module, monkeypatch):
    hv, gov, rec, tmp_path = doctor_module
    monkeypatch.setenv("HIVE_DOCTOR_MODE", "manual")
    rec["publisher"] = base64.b64encode(ed25519.pub_from_seed(bytes(range(2, 34)))).decode()
    r = hive_module_doctor._module(hv, gov, "demo", rec, [], (True, 1), 0)
    assert r["status"] == "fail" and not (tmp_path / "calls").exists()


def test_doctor_fix_runs_nothing_new(doctor_module, monkeypatch):
    hv, gov, rec, tmp_path = doctor_module
    assert "_undo_probe" not in open(hive_module_doctor.__file__).read().split("def fix(")[1]


# ── `module run` hands the module its words untouched (§5.1) ──────────────────────────────────────

@pytest.mark.parametrize("dash", [False, True])
def test_module_run_passes_flags_dashes_and_spaces_through_one_word_each(installed, tmp_path, monkeypatch, capsys, dash):
    out = tmp_path / "argv"
    publish_with_script(installed, {"show": {"mutates": False}}, f'for a in "$@"; do printf "%s\\n" "$a"; done > {out}\nexit 7\n')
    words = ["stop", "--dry-run", "--yes", "--", "--json", "two words", "-x", ""]
    monkeypatch.setattr(hive_modules, "module_env", lambda lib, name, path: dict(os.environ))
    rc, _, _ = run(["run", "demo", *(["--"] if dash else []), *words], capsys)
    assert rc == 7                                              # the module's own exit status
    assert out.read_text().split("\n")[:-1] == words


# ── `module check --run` probes each declared verb with --help (§5.3) ─────────────────────────────

HELP_CMDS = {
    "show": {"mutates": False},
    "good": {"mutates": True, "reversible": "n/a", "dry_run": True},
    "nodry": {"mutates": True, "reversible": "n/a", "dry_run": True},
    "bad": {"mutates": True, "reversible": "n/a", "dry_run": True},
    "stop": {"mutates": True, "reversible": "no", "dry_run": True},
    "halt": {"mutates": True, "reversible": "no", "dry_run": True},
}
HELP_SCRIPT = '''echo "$@" >> "$HIVE_MODULE_DIR/calls"
case "$1" in
  show) echo "usage: show";;
  good) echo "usage: good [--dry-run]";;
  nodry) echo "usage: nodry";;
  bad) echo "usage: bad [--dry-run]"; exit 2;;
  stop) echo "usage: stop [--yes] [--dry-run]. This cannot be undone.";;
  halt) echo "usage: halt [--dry-run]";;
esac
'''


def calls(root):
    return (root / "calls").read_text().splitlines() if (root / "calls").exists() else []


def test_check_run_probes_every_declared_verb_with_help_and_warns(tmp_path):
    publish_with_script(tmp_path, HELP_CMDS, HELP_SCRIPT)
    errors, warnings = hive_modules.check_module(tmp_path, CORE, run=True)
    assert errors == []
    mine = [w for w in warnings if w.startswith("declared verb")]
    assert mine == [
        "declared verb `nodry` is a verb that changes state, and its `--help` does not mention: --dry-run",
        "declared verb `bad`: `--help` exited 2, not 0",
        "declared verb `halt` is an irreversible verb, and its `--help` does not mention: This cannot be undone., --yes",
    ]
    assert not [w for w in warnings if "`show`" in w or "`good`" in w or "`stop`" in w]


def test_check_run_runs_nothing_but_help_and_check_without_run_runs_nothing(tmp_path):
    log = tmp_path / "log"
    publish_with_script(tmp_path, HELP_CMDS, f'echo "$@" >> {log}\ncase "$*" in *--help) exit 0;; esac\nexit 9\n')
    hive_modules.check_module(tmp_path, CORE)
    assert not log.exists()
    hive_modules.check_module(tmp_path, CORE, run=True)
    lines = log.read_text().splitlines()
    assert lines == [f"{v} --help" for v in HELP_CMDS]


def test_check_run_has_no_help_probe_without_a_map_or_a_cli(tmp_path):
    log = tmp_path / "log"
    publish_with_script(tmp_path, None, f'echo "$@" >> {log}\n')
    hive_modules.check_module(tmp_path, CORE, run=True)
    assert not log.exists()


def test_check_run_stops_at_the_total_and_names_the_verbs_it_did_not_run(tmp_path, monkeypatch):
    log = tmp_path / "log"
    publish_with_script(tmp_path, HELP_CMDS, f'echo "$@" >> {log}\nsleep 30\n')
    monkeypatch.setattr(hive_modules, "HELP_PROBE_TIMEOUT", 0.4)
    monkeypatch.setattr(hive_modules, "HELP_PROBE_TOTAL", 1.0)
    _, warnings = hive_modules.check_module(tmp_path, CORE, run=True)
    mine = [w for w in warnings if w.startswith(("declared verb", "stopped probing"))]
    ran = [line.split()[0] for line in log.read_text().splitlines()]
    assert 1 <= len(ran) < len(HELP_CMDS)
    assert mine[:len(ran)] == [f"declared verb `{v}`: `--help` did not finish in time" for v in ran]
    assert mine[len(ran):] == [f"stopped probing declared verbs after 1.0 s; not run: {', '.join(list(HELP_CMDS)[len(ran):])}"]


def test_check_run_notes_a_missing_program(tmp_path):
    out = hive_modules.help_warnings({"cli": {"name": "d", "command": ["/nonexistent/prog"]}, "files": {},
                                      "commands": {"show": {"mutates": False}}}, tmp_path, {"PATH": os.environ["PATH"]})
    assert len(out) == 1 and out[0].startswith("declared verb `show`: `--help` could not run")


# ── probe_help: no stdin, its own session, the whole group killed (the #502 verdict gaps) ─────────

def help_script(tmp_path, body):
    fake_cli(tmp_path / "p.sh", body)
    return [str(tmp_path / "p.sh"), "--help"]


def test_probe_help_gives_the_child_no_stdin(tmp_path):
    argv = help_script(tmp_path, 'if read x; then exit 9; fi\nexit 0\n')
    r, w = os.pipe()
    os.write(w, b"typed\n")
    saved = os.dup(0)
    try:
        os.dup2(r, 0)
        assert hive_modules.probe_help(argv, dict(os.environ), tmp_path) == (0, "")
    finally:
        os.dup2(saved, 0)
        for fd in (saved, r, w):
            os.close(fd)


def test_probe_help_runs_the_child_in_its_own_session(tmp_path):
    out = tmp_path / "sid"
    argv = help_script(tmp_path, f"sed 's/.*) //' /proc/$$/stat | cut -d' ' -f4 > {out}\n")
    assert hive_modules.probe_help(argv, dict(os.environ), tmp_path) == (0, "")
    sid = int(out.read_text())
    assert sid != os.getsid(0) and sid > 0


def alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0] != "Z"
    except OSError:
        return False


def wait_dead(pid):
    for _ in range(60):
        if not alive(pid):
            return True
        time.sleep(0.05)
    return False


def test_probe_help_kills_the_whole_group_at_the_deadline(tmp_path):
    pidfile = tmp_path / "grandchild"
    argv = help_script(tmp_path, f"sleep 30 &\necho $! > {pidfile}\nwait\n")
    pid = None
    try:
        rc, why = hive_modules.probe_help(argv, dict(os.environ), tmp_path, timeout=0.5)
        assert rc is None and why == "did not finish in 0.5 s"
        pid = int(pidfile.read_text())
        assert wait_dead(pid), "the grandchild outlived the probe"
    finally:
        if pid and alive(pid):
            os.kill(pid, 9)


def test_check_run_kills_the_whole_group_of_a_help_probe_that_hangs(tmp_path, monkeypatch):
    pidfile = tmp_path / "grandchild"
    publish_with_script(tmp_path, {"show": {"mutates": False}}, f"sleep 30 &\necho $! > {pidfile}\nwait\n")
    monkeypatch.setattr(hive_modules, "HELP_PROBE_TIMEOUT", 0.5)
    pid = None
    try:
        _, warnings = hive_modules.check_module(tmp_path, CORE, run=True)
        assert "declared verb `show`: `--help` did not finish in time" in warnings
        pid = int(pidfile.read_text())
        assert wait_dead(pid), "the grandchild outlived the probe"
    finally:
        if pid and alive(pid):
            os.kill(pid, 9)
