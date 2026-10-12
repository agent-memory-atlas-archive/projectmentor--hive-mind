"""`hive-mind module add | remove | update | list | quota` — the module lifecycle (2.1, plan PR 6, M1).

Control plane only: it runs inside `hivemind_ctl.py`, where the owner key is loaded, and `hv` never imports it
(`tests/test_control_plane.py` holds that edge shut). A module is installed outside the checkout, under
`$HIVE_MODULES_DIR` (default `~/.hive/modules/<name>/`), so `hive-mind reset` and `hv verify` never touch it.

**Trust.** A module runs code on this machine, so nothing is installed until its manifest checks out. The
manifest is `module.json`, signed by the module's *publisher key* (`module.json.sig`, Ed25519 over the exact
bytes). It names every file with its sha256, and the fetched tree must hold exactly those files and no others.
The publisher key is not the release key (`hivemind.pub` never signs modules): it is shown at `add` and pinned
in `$HIVE_HOME/.modules.json` once the owner confirms it (trust on first use), and an `update` signed by a
different key is refused. What is installed is the bytes that were hashed: files are copied into a staging
directory and hashed again there, so a repo that changes between the check and the copy installs nothing.

The platform is checked first. Where there is no module backend (everything but Linux with a user supervisor
in 2.1) `add` says so and exits non-zero before it fetches, mints or installs anything.

**Without the owner key (M1b).** A device that does not hold the owner key can still run a module the owner admits.
`module add` there fetches, verifies, stages and mints the module's key, writes a pending record beside the staging
directory, prints the owner's `hive-mind group admit <device> --module <name> --principal <p>` line with the
publisher fingerprint and the commit that was verified, and stops: no unit, no `.modules.json` row, no admit. Once the
owner's admit has reached this node, a second `module add` installs the staged tree (re-checked against the signed
manifest and the digest recorded at the first run); `module add --abort` removes the staging and the key.
`update` needs no owner key (it checks the tree and the pinned publisher as before and changes no membership or
quota), `remove` deletes locally and prints the owner's `group revoke` line, and `quota` stays owner-only.

Units (M2, PR 7) are rendered from the manifest's `service` block into `hive-module-<name>.service` (and `.timer`
when `interval` is set) in the operator's systemd user directory, installed on `add`, re-applied on `update` and
stopped and removed on `remove`. Hooks (M4, PR 8) and the doctor checks (M7, PR 9) read what this records.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import ed25519
import vocabulary

MANIFEST, SIGNATURE = "module.json", "module.json.sig"
STATE_FILE = ".modules.json"
NOT_SUPPORTED = "module management is not supported on this platform yet (2.1 ships on Linux only)"
HOOK_EVENTS = ("session-start", "user-prompt", "precompact", "sessionend", "notification", "stop")
BASE_KEYS = {"name", "version", "min_core", "publisher", "files", "service", "hooks", "config", "quota"}
# Manifest contract 1 (3.1): optional, and only under `contract`. A manifest without `contract` is a 2.1/3.0 manifest.
CONTRACT_KEYS = ("cli", "runtimes", "config_schema", "status", "doctor", "reads", "ui")
MANIFEST_KEYS = BASE_KEYS | {"contract", *CONTRACT_KEYS}
CONTRACTS = (1,)                                    # the manifest contracts this core knows
CONTRACT_MIN_CORE = {1: (3, 1)}                     # the oldest core a manifest of that contract may name in `min_core`
QUOTA_KEYS = ("per_hour", "per_day", "entry_bytes", "lifetime")
QUOTA_DEFAULTS = {"per_hour": 60, "per_day": 500, "entry_bytes": 16 * 1024, "lifetime": 50000}
MAX_FILES, MAX_FILE_BYTES, MAX_MANIFEST_BYTES = 500, 8 * 1024 * 1024, 256 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ModuleError(Exception):
    """A refusal the operator reads: nothing was installed, minted or signed for it."""


# ── places ──────────────────────────────────────────────────────────────────────────────────────────

def modules_dir():
    return Path(os.environ.get("HIVE_MODULES_DIR") or Path.home() / ".hive" / "modules")


def state_path(hv):
    return hv.HIVE_HOME / ".modules.json"


def load_state(lib):
    try:
        data = json.loads(state_path(lib).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(lib, state):
    path = state_path(lib)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=STATE_FILE + ".")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def platform_supported():
    """(ok, why). The module backend is Linux with a user supervisor; Termux and WSL-less Linux kernels without
    systemd are not it, and say so before anything is touched."""
    if not sys.platform.startswith("linux"):
        return False, NOT_SUPPORTED
    if os.environ.get("TERMUX_VERSION") or "com.termux" in os.environ.get("PREFIX", ""):
        return False, NOT_SUPPORTED
    return True, ""


# ── the manifest ────────────────────────────────────────────────────────────────────────────────────

def fingerprint(pub_b64):
    """What the operator compares: the first 16 hex of the sha256 of the publisher's public key."""
    return hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:16]


def _safe_rel(rel):
    p = Path(rel)
    return (isinstance(rel, str) and rel and not p.is_absolute() and ".." not in p.parts and "\\" not in rel
            and "\x00" not in rel and not rel.startswith("-") and rel not in (MANIFEST, SIGNATURE, "config")
            and ".git" not in p.parts)


def _core_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        raise ModuleError(f"min_core {v!r} is not a dotted version")


MAX_STOP_GRACE = 3600       # seconds a service may take to drain on stop before systemd kills it


def validate_manifest(raw, core_version):
    """Parse and check a manifest's shape; returns the dict. Refuses anything it does not understand rather than
    ignoring it, because this is the text that decides what code gets installed."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ModuleError("manifest is too large")
    try:
        m = json.loads(raw)
    except (ValueError, RecursionError) as e:
        raise ModuleError(f"manifest is not JSON: {e}")
    if not isinstance(m, dict):
        raise ModuleError("manifest is not an object")
    extra = set(m) - MANIFEST_KEYS
    if extra:
        raise ModuleError(f"manifest names fields this node does not know: {', '.join(sorted(map(str, extra)))}")
    if not vocabulary.valid_module_name(m.get("name")):
        raise ModuleError(f"manifest name {m.get('name')!r} is not a valid module name")
    if not isinstance(m.get("version"), str) or not m["version"] or len(m["version"]) > 64:
        raise ModuleError("manifest needs a version string")
    if _core_tuple(m.get("min_core", "0")) > _core_tuple(core_version):
        raise ModuleError(f"module needs core {m['min_core']} or newer; this node is on {core_version}")
    try:
        if len(base64.b64decode(m.get("publisher", ""), validate=True)) != 32:
            raise ValueError
    except Exception:
        raise ModuleError("manifest publisher is not a base64 Ed25519 public key")
    files = m.get("files")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ModuleError(f"manifest files must name 1 to {MAX_FILES} files")
    for rel, digest in files.items():
        if not _safe_rel(rel):
            raise ModuleError(f"manifest file path {rel!r} is not allowed")
        if not isinstance(digest, str) or not _HEX64.match(digest):
            raise ModuleError(f"manifest digest for {rel!r} is not a sha256")
    svc = m.get("service")
    if svc is not None:
        cmd = svc.get("command") if isinstance(svc, dict) else None
        if (not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) and a for a in cmd)
                or svc.get("restart", "on-failure") not in ("no", "on-failure", "always")
                or not (svc.get("interval") is None or (isinstance(svc["interval"], int) and svc["interval"] >= 60))
                or not (svc.get("stop_grace") is None or (isinstance(svc["stop_grace"], int) and not isinstance(svc["stop_grace"], bool)
                                                         and 1 <= svc["stop_grace"] <= MAX_STOP_GRACE))
                or set(svc) - {"command", "restart", "interval", "stop_grace"}):
            raise ModuleError("manifest service needs a command list, restart no|on-failure|always, optional interval >= 60, "
                              f"optional stop_grace 1 to {MAX_STOP_GRACE} seconds")
        if not cmd[0].startswith("/") and ".." in Path(cmd[0]).parts:
            raise ModuleError("manifest service command may not leave the module's directory")
        if any(ord(c) < 0x20 for a in cmd for c in a):
            raise ModuleError("manifest service command arguments may not hold control characters")
    hooks = m.get("hooks", [])
    if not isinstance(hooks, list) or any(h not in HOOK_EVENTS for h in hooks):
        raise ModuleError(f"manifest hooks must be a list of: {', '.join(HOOK_EVENTS)}")
    for h in hooks:
        if f"hooks/{h}" not in files:
            raise ModuleError(f"manifest hook {h!r} has no hooks/{h} file in `files`")
    for rel in files:
        if rel.startswith("hooks/") and rel[len("hooks/"):] not in hooks:
            raise ModuleError(f"manifest file {rel!r} is a hook the manifest's `hooks` list does not declare")
    cfg = m.get("config", {})
    if not isinstance(cfg, dict) or not all(vocabulary.split_module_name(f"x-{m['name']}:{k}") and isinstance(v, str)
                                            and len(v) <= vocabulary.MODULE_VALUE_MAX for k, v in cfg.items()):
        raise ModuleError("manifest config must map valid key names to string defaults")
    quota = m.get("quota", {})
    if not isinstance(quota, dict) or set(quota) - set(QUOTA_KEYS):
        raise ModuleError(f"manifest quota may only name: {', '.join(QUOTA_KEYS)}")
    for k, v in quota.items():
        if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > QUOTA_DEFAULTS[k]:
            raise ModuleError(f"manifest quota {k}={v!r}: a manifest may ask for less than the default "
                              f"({QUOTA_DEFAULTS[k]}), never more; only the owner raises a limit")
    _validate_contract(m)
    return m


# ── manifest contract 1 (3.1) ───────────────────────────────────────────────────────────────────────

MAX_ARGV, MAX_ARG = 64, 1024
CLI_NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
CLI_RESERVED = frozenset({"hv", "hive-mind", "hive-dispatch", "hive-sync", "hive-doctor", "hive-module", "hive-installer",
                          "hivemind", "module", "modules"})
RUNTIME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_RUNTIMES = 16
READ_ROUTES = ("overview", "tags", "related", "audit", "peers", "verify", "node")
CONFIG_TYPES, CONFIG_SCOPES = ("string", "int", "bool", "enum"), ("node", "fleet", "fleet-node")
CONFIG_SPEC_KEYS = {"type", "default", "scope", "description", "max", "min", "values", "required_at_install",
                    "secret", "identifying"}
MAX_SCHEMA_KEYS, MAX_DESCRIPTION, MAX_ENUM_VALUES, MAX_ENUM_VALUE = 128, 400, 64, 80
_SEGMENT_WORD = re.compile(r"\{[a-z][a-z0-9_]{0,31}\}\Z")
_INT_TEXT = re.compile(r"-?[0-9]{1,18}\Z")
UI_SCHEMA_FILE = "ui_block.schema.json"
UI_SCHEMAS = (1,)                                   # the `ui.schema` versions this core knows
MAX_UI_BYTES = 64 * 1024
_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _has_control(text):
    return any(ord(c) < 0x20 or ord(c) == 0x7f for c in text)


def _check_argv(label, cmd):
    """An argv list with `service.command`'s rules: strings, no control characters, and a relative first word may not
    leave the module's directory. It is run without a shell."""
    if (not isinstance(cmd, list) or not cmd or len(cmd) > MAX_ARGV
            or not all(isinstance(a, str) and a and len(a) <= MAX_ARG for a in cmd)):
        raise ModuleError(f"manifest {label} needs a list of 1 to {MAX_ARGV} non-empty strings of at most {MAX_ARG} characters")
    if not cmd[0].startswith("/") and ".." in Path(cmd[0]).parts:
        raise ModuleError(f"manifest {label} may not leave the module's directory")
    if any(_has_control(a) for a in cmd):
        raise ModuleError(f"manifest {label} arguments may not hold control characters")


def _config_key_ok(module, key):
    """A `config_schema` key: a `x-<module>:` local name, where a whole dot-segment `{word}` stands for any one
    segment (`seat.{role}.runtime`)."""
    if not isinstance(key, str):
        return False
    probe = ".".join("w" if _SEGMENT_WORD.match(seg) else seg for seg in key.split("."))
    return vocabulary.split_module_name(f"x-{module}:{probe}") is not None


def config_value_problem(spec, value):
    """None when `value` (a string, as the journal and the node file hold it) fits the schema entry `spec`, else why."""
    if not isinstance(value, str) or len(value) > vocabulary.MODULE_VALUE_MAX or _has_control(value):
        return "not a string of printable characters within the value limit"
    kind = spec["type"]
    if kind == "string":
        return None if len(value) <= spec.get("max", vocabulary.MODULE_VALUE_MAX) else f"longer than {spec['max']}"
    if kind == "bool":
        return None if value in ("true", "false") else "not true or false"
    if kind == "enum":
        return None if value in spec["values"] else f"not one of {', '.join(spec['values'])}"
    if not _INT_TEXT.match(value):
        return "not an integer"
    n = int(value)
    if "min" in spec and n < spec["min"] or "max" in spec and n > spec["max"]:
        return f"outside {spec.get('min', '-inf')}..{spec.get('max', 'inf')}"
    return None


def _check_config_entry(module, key, spec):
    where = f"manifest config_schema {key!r}"
    if not _config_key_ok(module, key):
        raise ModuleError(f"{where}: not a valid config key name")
    if not isinstance(spec, dict) or set(spec) - CONFIG_SPEC_KEYS:
        raise ModuleError(f"{where} is an object that may only name: {', '.join(sorted(CONFIG_SPEC_KEYS))}")
    kind = spec.get("type")
    if kind not in CONFIG_TYPES:
        raise ModuleError(f"{where}: type must be one of {', '.join(CONFIG_TYPES)}")
    scope = spec.get("scope", "node")
    if scope not in CONFIG_SCOPES:
        raise ModuleError(f"{where}: scope must be one of {', '.join(CONFIG_SCOPES)}")
    desc = spec.get("description")
    if not isinstance(desc, str) or not desc.strip() or len(desc) > MAX_DESCRIPTION or _has_control(desc):
        raise ModuleError(f"{where}: description is required (a string of at most {MAX_DESCRIPTION} characters)")
    for flag in ("required_at_install", "secret", "identifying"):
        if flag in spec and not isinstance(spec[flag], bool):
            raise ModuleError(f"{where}: {flag} must be true or false")
    allowed = {"string": {"max"}, "int": {"min", "max"}, "bool": set(), "enum": {"values"}}[kind]
    for bound in ("min", "max", "values"):
        if bound in spec and bound not in allowed:
            raise ModuleError(f"{where}: {bound} does not apply to type {kind}")
    if kind == "string" and "max" in spec and not (_is_int(spec["max"]) and 1 <= spec["max"] <= vocabulary.MODULE_VALUE_MAX):
        raise ModuleError(f"{where}: max must be 1 to {vocabulary.MODULE_VALUE_MAX}")
    if kind == "int":
        for bound in ("min", "max"):
            if bound in spec and not (_is_int(spec[bound]) and abs(spec[bound]) < 10 ** 18):
                raise ModuleError(f"{where}: {bound} must be an integer")
        if "min" in spec and "max" in spec and spec["min"] > spec["max"]:
            raise ModuleError(f"{where}: min is above max")
    if kind == "enum":
        vals = spec.get("values")
        if (not isinstance(vals, list) or not 1 <= len(vals) <= MAX_ENUM_VALUES or len(set(map(str, vals))) != len(vals)
                or not all(isinstance(v, str) and v and len(v) <= MAX_ENUM_VALUE and not _has_control(v) for v in vals)):
            raise ModuleError(f"{where}: an enum needs 1 to {MAX_ENUM_VALUES} distinct strings in `values`")
    if spec.get("secret") and scope != "node":
        raise ModuleError(f"{where}: a secret key is node-scoped (a fleet value is journaled for every device)")
    if "default" in spec:
        if spec.get("identifying") or spec.get("secret"):
            raise ModuleError(f"{where}: a key marked identifying or secret may not ship a default")
        problem = config_value_problem(spec, spec["default"])
        if problem:
            raise ModuleError(f"{where}: default is {problem}")


def _check_ui(m):
    ui = m["ui"]
    if not isinstance(ui, dict) or len(json.dumps(ui, ensure_ascii=False).encode()) > MAX_UI_BYTES:
        raise ModuleError(f"manifest ui must be an object of at most {MAX_UI_BYTES // 1024} KiB")
    if ui.get("schema") not in UI_SCHEMAS or not _is_int(ui.get("schema")):
        raise ModuleError(f"manifest ui schema must be one this node knows ({', '.join(map(str, UI_SCHEMAS))})")
    todo = [ui]
    while todo:                                             # text is shown as text, but never carries control characters
        node = todo.pop()
        for k, v in (node.items() if isinstance(node, dict) else enumerate(node)):
            if isinstance(k, str) and _has_control(k) or isinstance(v, str) and _has_control(v):
                raise ModuleError("manifest ui holds a string with control characters")
            if isinstance(v, (dict, list)):
                todo.append(v)
    _schema_check(ui, load_ui_schema(), "manifest ui")
    for group in ("metrics", "panels", "actions"):
        ids = [x["id"] for x in ui.get(group, [])]
        if len(set(ids)) != len(ids):
            raise ModuleError(f"manifest ui {group} repeat an id")
    own = f"x-{m['name']}:"
    for item in (*ui.get("metrics", []), *ui.get("panels", [])):
        if item.get("from") == "entities" and not str(item.get("prefix", "")).startswith(own):
            raise ModuleError(f"manifest ui {item['id']!r} reads entities, so it needs a `prefix` starting {own!r}: "
                              "a module's page shows its own entities")
    for act in ui.get("actions", []):
        _check_argv(f"ui action {act['id']!r} command", act["command"])
        used = {n for a in act["command"] for n in _PLACEHOLDER.findall(a)}
        params = set(act.get("params", {}))
        if _PLACEHOLDER.search(act["command"][0]):
            raise ModuleError(f"manifest ui action {act['id']!r}: the command itself may not be a parameter")
        if used != params:
            raise ModuleError(f"manifest ui action {act['id']!r}: the parameters {sorted(params)} and the placeholders "
                              f"{sorted(used)} in its command must match")


def _validate_contract(m):
    """The contract-1 fields (3.1). A manifest without `contract` is a 2.1/3.0 manifest and may name none of them."""
    new = [k for k in CONTRACT_KEYS if k in m]
    if "contract" not in m:
        if new:
            raise ModuleError(f"manifest names {', '.join(new)} without `contract`: declare `\"contract\": 1`")
        return
    contract = m["contract"]
    if not _is_int(contract) or contract not in CONTRACTS:
        raise ModuleError(f"manifest contract {contract!r} is not one this node knows (it knows: {', '.join(map(str, CONTRACTS))})")
    if "config" in m:
        raise ModuleError("manifest names both `contract` and `config`: under a contract, `config_schema` replaces `config`")
    if "min_core" not in m or _core_tuple(m["min_core"]) < CONTRACT_MIN_CORE[contract]:
        need = ".".join(map(str, CONTRACT_MIN_CORE[contract]))
        raise ModuleError(f"a contract {contract} manifest needs min_core {need} or newer")
    cli = m.get("cli")
    if "cli" in m:
        if (not isinstance(cli, dict) or set(cli) != {"name", "command"} or not isinstance(cli["name"], str)
                or not CLI_NAME.match(cli["name"])):
            raise ModuleError("manifest cli needs exactly a name (a-z, 0-9, -; 2 to 32 characters, starting with a letter) and a command")
        if cli["name"] in CLI_RESERVED or cli["name"].startswith("hive-"):
            raise ModuleError(f"manifest cli name {cli['name']!r} is a name the core uses")
        _check_argv("cli command", cli["command"])
    for field in ("status", "doctor"):
        if field in m:
            _check_argv(field, m[field])
    if "runtimes" in m:
        rt = m["runtimes"]
        if (not isinstance(rt, list) or len(rt) > MAX_RUNTIMES or len(set(map(str, rt))) != len(rt)
                or not all(isinstance(r, str) and RUNTIME_NAME.match(r) and r not in (".", "..") for r in rt)):
            raise ModuleError(f"manifest runtimes must be at most {MAX_RUNTIMES} distinct program names (letters, digits, . _ -; "
                              "no slash: a module names programs, never directories)")
    if "reads" in m:
        rd = m["reads"]
        if not isinstance(rd, list) or len(set(map(str, rd))) != len(rd) or not all(r in READ_ROUTES for r in rd):
            raise ModuleError(f"manifest reads must be distinct names from: {', '.join(READ_ROUTES)}")
    if "config_schema" in m:
        cs = m["config_schema"]
        if not isinstance(cs, dict) or len(cs) > MAX_SCHEMA_KEYS:
            raise ModuleError(f"manifest config_schema must be an object of at most {MAX_SCHEMA_KEYS} keys")
        for key, spec in cs.items():
            _check_config_entry(m["name"], key, spec)
    if "ui" in m:
        _check_ui(m)


# A deliberately small JSON Schema subset, enough for docs/ui_block.schema.json (the one definition of the `ui` block)
# without a dependency. `tests/test_manifest_contract.py` fails if that file uses a keyword this does not implement.
SCHEMA_KEYWORDS = frozenset({"$schema", "$id", "title", "description", "type", "const", "enum", "properties", "required",
                             "additionalProperties", "items", "minItems", "maxItems", "minLength", "maxLength", "pattern",
                             "minimum", "maximum", "minProperties", "maxProperties"})
_SCHEMA_TYPES = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
                 "string": lambda v: isinstance(v, str), "integer": _is_int, "boolean": lambda v: isinstance(v, bool)}
_ui_schema_cache = []


def ui_schema_path():
    return Path(__file__).resolve().parent / "docs" / UI_SCHEMA_FILE


def load_ui_schema():
    """The `ui` block's JSON Schema, shipped in the core's own tree. Fails closed if it is not there."""
    if not _ui_schema_cache:
        try:
            _ui_schema_cache.append(json.loads(ui_schema_path().read_text()))
        except (OSError, ValueError):
            raise ModuleError(f"this core is missing docs/{UI_SCHEMA_FILE}: cannot check a manifest's ui block")
    return _ui_schema_cache[0]



def _schema_check(value, schema, path):
    t = schema.get("type")
    if t is not None and not _SCHEMA_TYPES[t](value):
        raise ModuleError(f"{path} must be of type {t}")
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        raise ModuleError(f"{path} must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ModuleError(f"{path} must be one of {', '.join(map(str, schema['enum']))}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise ModuleError(f"{path} must be {schema.get('minLength', 0)} to {schema.get('maxLength', 'any')} characters")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ModuleError(f"{path} is not in the form {schema['pattern']}")
    if _is_int(value) and ("minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]):
        raise ModuleError(f"{path} is out of range")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise ModuleError(f"{path} must hold {schema.get('minItems', 0)} to {schema.get('maxItems', 'any number of')} items")
        for i, item in enumerate(value):
            if "items" in schema:
                _schema_check(item, schema["items"], f"{path}[{i}]")
    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", len(value)):
            raise ModuleError(f"{path} must hold {schema.get('minProperties', 0)} to {schema.get('maxProperties', 'any number of')} fields")
        for req in schema.get("required", ()):
            if req not in value:
                raise ModuleError(f"{path} needs {req!r}")
        props, extra = schema.get("properties", {}), schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                _schema_check(v, props[k], f"{path}.{k}")
            elif extra is False:
                raise ModuleError(f"{path} names {k!r}, which this node does not know")
            elif isinstance(extra, dict):
                _schema_check(v, extra, f"{path}.{k}")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_tree(root, core_version, tracked=None, ignore=()):
    """Verify the module tree at `root`: the manifest is well-formed, the signature is valid under the manifest's
    own publisher key, every listed file is present, regular and matches its digest, and nothing else is there.
    `tracked` is the set of git-tracked paths when `root` is a checkout (an untracked stray file is not part of
    what was published). Returns the manifest. Raises ModuleError; touches nothing."""
    root = Path(root)
    try:
        raw = (root / MANIFEST).read_bytes()
    except OSError:
        raise ModuleError(f"no {MANIFEST} in the module repository")
    try:
        sig = base64.b64decode("".join((root / SIGNATURE).read_text().split()), validate=True)
    except Exception:
        raise ModuleError(f"no valid {SIGNATURE} in the module repository")
    m = validate_manifest(raw, core_version)
    if not ed25519.verify(raw, sig, base64.b64decode(m["publisher"])):
        raise ModuleError("the manifest signature is not valid under its publisher key: refusing")
    _verify_files(root, m, tracked, ignore)
    return m


def _verify_files(root, m, tracked=None, ignore=()):
    """The tree at `root` holds exactly the manifest's files (plus the manifest, its signature and `ignore`), each a
    regular file under the size cap with the listed digest. Raises ModuleError."""
    present = set(tracked) if tracked is not None else {
        str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    extra = {p for p in present if p not in m["files"] and p not in (MANIFEST, SIGNATURE, *ignore)}
    if extra:
        raise ModuleError(f"the repository holds files the manifest does not list: {', '.join(sorted(extra)[:5])}")
    for rel, digest in sorted(m["files"].items()):
        p = root / rel
        st = os.lstat(p) if os.path.lexists(p) else None
        if st is None:
            raise ModuleError(f"manifest lists {rel!r}, which is missing")
        if not os.path.isfile(p) or os.path.islink(p):
            raise ModuleError(f"{rel!r} is not a regular file (links are refused)")
        if st.st_size > MAX_FILE_BYTES:
            raise ModuleError(f"{rel!r} is over {MAX_FILE_BYTES} bytes")
        if _sha256_file(p) != digest:
            raise ModuleError(f"{rel!r} does not match its manifest digest: refusing")


def _fetch(repo, dest):
    """Clone `repo` (a path or URL) into `dest`, and return (tracked files, commit). Uses the operator's own git
    credentials; the `ext::` transport, which runs commands, is off."""
    if not repo or repo.startswith("-"):
        raise ModuleError(f"{repo!r} is not a repository")
    env = dict(os.environ, GIT_ALLOW_PROTOCOL="file:https:ssh:git")
    try:
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--", repo, str(dest)], env=env,
                       check=True, capture_output=True, text=True, timeout=300)
        ls = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(dest), "ls-files", "-z"], check=True, capture_output=True, timeout=30)
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True, timeout=30).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise ModuleError(f"could not fetch {repo}: {(e.stderr or '').strip().splitlines()[-1:] or 'git failed'}")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ModuleError(f"could not fetch {repo}: {e}")
    return [n.decode() for n in ls.stdout.split(b"\x00") if n], head


def _stage(src, manifest, staging):
    """Copy the listed files into `staging` and hash them again there: what is installed is what was hashed."""
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for rel in [*manifest["files"], MANIFEST, SIGNATURE]:
        dst = staging / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src / rel, dst)
        os.chmod(dst, 0o755 if os.access(src / rel, os.X_OK) else 0o644)
    for rel, digest in manifest["files"].items():
        if _sha256_file(staging / rel) != digest:
            raise ModuleError(f"{rel!r} changed while it was being copied: refusing")


def _confirm_publisher(manifest, expected, pinned=None):
    """Trust on first use. The operator must name the key they checked (`--publisher`) or confirm it at a
    prompt; there is no bare --yes, because a flag that skips the look is not a pin. A pinned key must match."""
    pub = manifest["publisher"]
    if pinned is not None:
        if pub != pinned:
            raise ModuleError(f"the update is signed by publisher {fingerprint(pub)}, but this module is pinned to "
                              f"{fingerprint(pinned)}: refusing. Remove and re-add it to change publishers.")
        return
    print(f"module {manifest['name']} {manifest['version']} is signed by publisher key {pub} (fingerprint {fingerprint(pub)})")
    if expected is not None:
        if expected != pub:
            raise ModuleError(f"--publisher does not match the manifest's publisher key ({fingerprint(pub)}): refusing")
        return
    if not sys.stdin.isatty():
        raise ModuleError("pin this publisher key by passing it: --publisher <key> (shown above)")
    if input("Trust this publisher for this module and pin it? [y/N] ").strip().lower() not in ("y", "yes"):
        raise ModuleError("publisher not confirmed: nothing installed")


# ── the owner steps ─────────────────────────────────────────────────────────────────────────────────

def _gov(lib):
    import merkle
    return lib._governance_state(merkle.read_all_entries(lib.JOURNAL_DIR))


def _require_owner(lib, acts=()):
    """Unlock the owner key before anything is fetched into place, so a locked key or a non-owner device
    refuses with nothing written. `acts` are the acts the command will make: with the unlock agent covering all of
    them (`owner_agent.gate_ok`) the gate passes without a prompt (#295); otherwise it unlocks, as ever."""
    if not lib._owner_key_exists():
        raise ModuleError("this device does not hold the owner key: run module commands on the owner machine")
    if not lib._owner_gate(acts):
        raise ModuleError("the owner key could not be unlocked")


def _operator_principal(lib, given):
    if given:
        return given
    p = (_gov(lib).get("principals") or {}).get(lib.NODE_ID)
    if not p:
        raise ModuleError("this device has no principal: pass --principal <the operator's principal>, so the "
                          "module falls under cap_self")
    return p


def _device_state(lib, device_id):
    gov = _gov(lib)
    if device_id in gov["purged"]:
        return "purged"
    return "admitted" if device_id in gov["admitted"] else "revoked"


# ── the non-owner install (M1b) ─────────────────────────────────────────────────────────────────────

def _pending_path(name):
    return modules_dir() / f".{name}.pending.json"


def _read_pending(name):
    try:
        rec = json.loads(_pending_path(name).read_text())
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) and rec.get("device_id") else None


def _admit_line(rec, name):
    return f"hive-mind group admit {rec['device_id']} --module {name} --principal {rec['principal']}"


def _clear_pending(lib, name):
    """Remove everything a staged, not yet installed module left: the staging directory, the pending record and the
    minted key."""
    shutil.rmtree(modules_dir() / f".{name}.staging", ignore_errors=True)
    _pending_path(name).unlink(missing_ok=True)
    shutil.rmtree(Path(lib._ensure_key_dir()) / "modules" / name, ignore_errors=True)


def _abort_add(lib, name):
    if name in load_state(lib):
        raise ModuleError(f"module {name!r} is installed: use `hive-mind module remove {name}`")
    if _read_pending(name) is None:
        raise ModuleError(f"module {name!r} has no pending add")
    _clear_pending(lib, name)
    print(f"aborted the pending add of module {name}: its staging and key are removed")


def _stage_for_owner(lib, args, name, root):
    """First run of `module add` on a device without the owner key: verify, stage, mint, print the owner's line and
    install nothing."""
    principal = _operator_principal(lib, args.principal)
    with tempfile.TemporaryDirectory(prefix="hive-module-") as tmp:
        src = Path(tmp) / "src"
        tracked, head = _fetch(args.source, src)
        manifest = check_tree(src, lib.CONTRACT_VERSION, tracked)
        if manifest["name"] != name:
            raise ModuleError(f"the repository holds module {manifest['name']!r}, not {name!r}")
        _confirm_publisher(manifest, args.publisher)
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        staging = root / f".{name}.staging"
        minted = False
        try:
            _stage(src, manifest, staging)
            device_id, _pub = lib.mint_module_key(name)
            minted = True
            rec = {"device_id": device_id, "principal": principal, "publisher": manifest["publisher"],
                   "version": manifest["version"], "source": args.source, "commit": head,
                   "manifest_sha256": _sha256_file(staging / MANIFEST), "staged_at": int(time.time())}
            _pending_path(name).write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n")
        except (ModuleError, FileExistsError, OSError, ValueError, RuntimeError) as e:
            shutil.rmtree(staging, ignore_errors=True)
            _pending_path(name).unlink(missing_ok=True)
            if minted:
                shutil.rmtree(Path(lib._ensure_key_dir()) / "modules" / name, ignore_errors=True)
            raise ModuleError(str(e))
    print(f"module {name} {manifest['version']} is staged on this device and NOT installed: it has no admit yet.\n"
          f"On the owner machine, after checking commit {head} of {args.source} "
          f"(publisher {fingerprint(manifest['publisher'])}), run:\n  {_admit_line(rec, name)}\n"
          f"When that has reached this node, run `hive-mind module add {name} --from {args.source}` again to install it, "
          f"or `hive-mind module add --abort {name}` to drop it.")


def _complete_add(lib, args, name, root, rec):
    """Second run: the owner's admit has projected here, so install the staged tree. The tree is re-checked against
    the signed manifest and against the digest of the manifest this node verified at the first run."""
    if args.source != rec["source"]:
        raise ModuleError(f"module {name!r} is staged from {rec['source']}, not {args.source}: finish that add, or "
                          f"`hive-mind module add --abort {name}`")
    if args.publisher is not None and args.publisher != rec["publisher"]:
        raise ModuleError("--publisher does not match the publisher key pinned at the first run: refusing")
    gov = _gov(lib)
    dev = rec["device_id"]
    if gov["modules"].get(dev) != name or dev not in gov["admitted"] or dev in gov["purged"]:
        raise ModuleError(f"the owner has not admitted {dev} as module {name} on this node yet (it may not have synced). "
                          f"On the owner machine: {_admit_line(rec, name)}")
    staging = root / f".{name}.staging"
    key = Path(lib._ensure_key_dir()) / "modules" / name / "device-key"
    if not key.exists():
        raise ModuleError(f"the module's key is gone: `hive-mind module add --abort {name}` and start again")
    try:
        derived = lib._device_id_for_pub(ed25519.pub_from_seed(base64.b64decode(key.read_text().strip())))
    except Exception:
        derived = None
    if derived != dev:       # the admitted id must be the one this key file really is
        raise ModuleError(f"the module's key no longer matches the device id {dev} the owner admitted: "
                          f"`hive-mind module add --abort {name}` and start again")
    manifest = check_tree(staging, lib.CONTRACT_VERSION)
    if _sha256_file(staging / MANIFEST) != rec["manifest_sha256"]:       # the bytes include the publisher key
        raise ModuleError("the staged tree is not the one this node verified: refusing. "
                          f"`hive-mind module add --abort {name}` and start again")
    if (root / name).exists():
        raise ModuleError(f"module {name!r} is already installed: use `hive-mind module update {name}`")
    state = load_state(lib)
    renamed = False
    try:
        _write_config(staging, manifest.get("config", {}))
        os.rename(staging, root / name)
        renamed = True
        note = install_units(lib, name, manifest)
        state[name] = {"version": manifest["version"], "publisher": manifest["publisher"], "device_id": dev,
                       "source": rec["source"], "commit": rec["commit"], "installed_at": int(time.time()),
                       "quota": dict(manifest.get("quota") or {}), "owner_quota": {}}
        save_state(lib, state)
    except BaseException:
        try:
            remove_units(name)
        except ModuleError:                          # still draining: the add's own error is the one to show
            pass
        if renamed and not staging.exists():
            os.rename(root / name, staging)          # the pending add stays whole, so it can be run again
            (staging / "config").unlink(missing_ok=True)       # staging is again exactly the tree that was verified
        raise
    _pending_path(name).unlink(missing_ok=True)
    print(f"installed module {name} {manifest['version']} (device {dev}, principal {gov['principals'].get(dev)}); "
          + (f"service {unit_names(name)[0]}" + (" with a timer" if manifest["service"].get("interval") else "")
             if manifest.get("service") else "no service")
          + (f" ({note})" if note else "") + "; hooks: " + (", ".join(manifest.get("hooks") or []) or "none"))


# ── the unit (M2) ───────────────────────────────────────────────────────────────────────────────────

def unit_dir():
    return Path.home() / ".config" / "systemd" / "user"


def unit_names(name):
    return f"hive-module-{name}.service", f"hive-module-{name}.timer"


def _base_timeout():
    """Seconds a quick `systemctl` call may take (30; HIVE_SYSTEMCTL_TIMEOUT lets a test shrink it)."""
    try:
        return float(os.environ.get("HIVE_SYSTEMCTL_TIMEOUT") or 30)
    except ValueError:
        return 30


def _stop_timeout(grace):
    """A call that stops a unit waits out its `stop_grace` drain, plus the usual allowance."""
    return (grace or 0) + _base_timeout()


def _unit_grace(path):
    """The TimeoutStopSec a rendered unit file declares, or 0 (the file is missing, unreadable or has none)."""
    try:
        for line in Path(path).read_text().splitlines():
            if line.startswith("TimeoutStopSec="):
                return int(line.split("=", 1)[1])
    except (OSError, ValueError):
        pass
    return 0


def _systemctl(*args, timeout=None, timed_out=None):
    """Run `systemctl --user ...`; False when there is no user manager or the call fails. Never raises. A call
    that outlives `timeout` fails too, and sets `timed_out[0]` when the caller passed a list to say so."""
    try:
        return subprocess.run(["systemctl", "--user", *args], capture_output=True,
                              timeout=timeout or _base_timeout()).returncode == 0
    except subprocess.TimeoutExpired:
        if timed_out is not None:
            timed_out[:] = [True]
        return False
    except (OSError, subprocess.SubprocessError):
        return False


def user_systemd():
    """Whether a user systemd manager is reachable: a runtime dir, and `is-system-running` answering (a `degraded`
    manager still manages units). Never raises."""
    if not os.environ.get("XDG_RUNTIME_DIR"):
        return False
    try:
        r = subprocess.run(["systemctl", "--user", "is-system-running"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 or r.stdout.strip() in ("running", "degraded", "starting", "initializing", "stopping")


def _quote(arg):
    """One ExecStart word: systemd splits on whitespace and expands `%` and `$`, so quote and double them."""
    esc = arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{esc}"'


def _env(key, value):
    """One `Environment="K=V"` line: the quotes keep a space in the value, `%` is doubled against specifiers."""
    esc = f"{key}={value}".replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'Environment="{esc}"'


def render_units(name, manifest, module_dir, key_dir):
    """{filename: text} for a module's unit(s), or {} when its manifest has no `service` block.

    It runs as the operator's user (a user unit), in the module's own directory, with the module's own key
    directory and nothing of the owner's in its environment. The command's first word is made absolute: a path
    inside the module (one it ships, or any relative path) is anchored to its directory and any other bare name is
    looked up by `env`. Unlike the sync unit it
    has no `ExecStartPre` that kills by command line (such a pattern could match another module)."""
    svc = manifest.get("service")
    if not svc:
        return {}
    cmd = list(svc["command"])
    if not cmd[0].startswith("/"):
        own = "/" in cmd[0] or cmd[0] in manifest.get("files", {})
        cmd = [str(module_dir / cmd[0]), *cmd[1:]] if own else ["/usr/bin/env", *cmd]
    interval, restart = svc.get("interval"), svc.get("restart", "on-failure")
    service, timer = unit_names(name)
    lines = ["[Unit]", f"Description=Hive Mind module {name}", "After=network.target hive-sync.service", ""]
    lines += ["[Service]", f"Type={'oneshot' if interval else 'simple'}", f"WorkingDirectory={str(module_dir).replace('%', '%%')}",
              "ExecStart=" + " ".join(_quote(a) for a in cmd),
              _env("HIVE_MODULE_NAME", name), _env("HIVE_MODULE_DIR", module_dir),
              _env("HIVE_MODULE_KEY_DIR", key_dir), "NoNewPrivileges=yes",
              "StandardOutput=journal", "StandardError=journal"]
    grace = svc.get("stop_grace")
    if grace:                           # SIGTERM the main process only, let it drain, SIGKILL the group after `grace`
        lines += [f"TimeoutStopSec={grace}", "KillMode=mixed"]
    if not interval:                    # a timer re-fires a oneshot; a daemon is kept up by its restart policy
        lines += [f"Restart={restart}", "RestartSec=5"] + ([] if grace else ["KillMode=control-group"])
        lines += ["", "[Install]", "WantedBy=default.target"]
    out = {service: "\n".join(lines) + "\n"}
    if interval:
        out[timer] = "\n".join(["[Unit]", f"Description=Run Hive Mind module {name} every {interval}s", "",
                                 "[Timer]", f"OnBootSec={interval}", f"OnUnitActiveSec={interval}",
                                 "", "[Install]", "WantedBy=timers.target"]) + "\n"
    return out


def _write_units(lib, name, manifest, only_changed=False):
    """Stop whatever is installed, then write the module's unit files (and drop a timer it no longer declares).
    Returns the unit to enable and start (the timer when there is one), or None when there is nothing to start:
    no service block, or `only_changed` and the files are already what the manifest renders."""
    keep = render_units(name, manifest, modules_dir() / name, Path(lib._ensure_key_dir()) / "modules" / name)
    if not keep:
        remove_units(name)
        return None
    d = unit_dir()
    if only_changed and all((d / f).exists() and (d / f).read_text() == keep.get(f) for f in unit_names(name)
                            if f in keep) and not any((d / f).exists() for f in unit_names(name) if f not in keep):
        return None
    d.mkdir(parents=True, exist_ok=True)
    for fname in unit_names(name)[::-1]:                    # a daemon that becomes a timer must not keep running
        if (d / fname).exists():
            late = [False]
            if not _systemctl("disable", "--now", fname, timeout=_stop_timeout(_unit_grace(d / fname)), timed_out=late) and late[0]:
                raise ModuleError(f"{fname} did not stop in time: it is still draining. Wait for it, then run this again")
            if fname not in keep:
                (d / fname).unlink()
    for fname, text in keep.items():
        (d / fname).write_text(text)
    return next(f for f in unit_names(name)[::-1] if f in keep)


def _start_unit(unit):
    """Enable and (re)start `unit`; a note for the operator when systemd would not."""
    if not _systemctl("enable", unit):
        return "the unit is written, but systemd would not enable it"
    late = [False]
    if not _systemctl("restart", unit, timeout=_stop_timeout(_unit_grace(unit_dir() / unit)), timed_out=late):
        if late[0]:
            return f"the unit is enabled, but systemd had not finished restarting it in time (is it still draining?): check `systemctl --user status {unit}`"
        return "the unit is enabled, but systemd would not start it"
    return ""


def install_units(lib, name, manifest):
    """Write the module's unit files and, where a user systemd manager is reachable, enable and (re)start them.
    Without one the files are still written; returns a note for the operator."""
    unit = _write_units(lib, name, manifest)
    if unit is None:
        return ""
    if not _systemctl("show-environment"):
        return "no user systemd manager is reachable: the unit is written, not started"
    _systemctl("daemon-reload")
    return _start_unit(unit)


def remove_units(name):
    """Stop, disable and delete the module's units. Safe when there are none. Waits out a `stop_grace` drain; a
    unit still draining after that raises ModuleError with its unit file kept, so nothing of the module is
    deleted under it."""
    service, timer = unit_names(name)
    d = unit_dir()
    if not any((d / f).exists() for f in (service, timer)):
        return
    for f in (timer, service):
        late = [False]
        if not _systemctl("disable", "--now", f, timeout=_stop_timeout(_unit_grace(d / f)), timed_out=late) and late[0]:
            raise ModuleError(f"{f} did not stop in time: it is still draining, so nothing was deleted. Wait for it, then run this again")
        (d / f).unlink(missing_ok=True)
    # an older renderer wrote Persistent=true, which left this stamp: it marks OnBootSec as elapsed, so a re-added timer never fires
    (Path.home() / ".local" / "share" / "systemd" / "timers" / f"stamp-{timer}").unlink(missing_ok=True)
    _systemctl("daemon-reload")
    _systemctl("reset-failed", service)


def main_unit(name):
    """The unit that is the module's switch: the timer when it has one, else the service."""
    service, timer = unit_names(name)
    return timer if (unit_dir() / timer).exists() else service


def unit_enabled(name):
    """Whether systemd has the module's main unit enabled (False without a user manager)."""
    return _systemctl("is-enabled", main_unit(name))


def service_state(name):
    """'none' without a unit, else systemd's word for it ('active', 'inactive', 'failed') or 'installed'."""
    service, timer = unit_names(name)
    d = unit_dir()
    if not (d / service).exists():
        return "none"
    unit = main_unit(name)
    try:
        r = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True, timeout=10)
        word = r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        word = ""
    return word if word in ("active", "inactive", "failed", "activating") else "installed"


# ── verbs ───────────────────────────────────────────────────────────────────────────────────────────

def _write_config(dest_dir, defaults):
    """Per-node config (M3): `<module dir>/config`, local and never journaled. Existing values survive an update;
    only keys the file lacks take the manifest's default."""
    path = dest_dir / "config"
    have = {}
    try:
        have = json.loads(path.read_text())
    except (OSError, ValueError):
        pass
    have = have if isinstance(have, dict) else {}
    merged = {**defaults, **have}
    path.write_text(json.dumps(merged, indent=1, sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def _config_path(lib, name):
    if name not in load_state(lib):
        raise ModuleError(f"module {name!r} is not installed")
    return modules_dir() / name / "config"


def _read_config(path):
    try:
        have = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise ModuleError(f"{path} is not readable JSON ({e}): fix or remove it first")
    if not isinstance(have, dict):
        raise ModuleError(f"{path} is not a JSON object: fix or remove it first")
    return have


def _save_config(path, have):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(have, indent=1, sort_keys=True) + "\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def cmd_config(lib, args):
    """`module config <name> set|unset|list`: edit the per-node config file (local, never journaled, kept by update).
    No owner key is needed: it is this node's own file."""
    path = _config_path(lib, args.name)
    have = _read_config(path)
    if args.action == "list":
        for k in sorted(have):
            print(f"{k}={have[k]}")
        return
    if not vocabulary.split_module_name(f"x-{args.name}:{args.key}"):
        raise ModuleError(f"bad config key {args.key!r}: 1 to {vocabulary.MODULE_KEY_MAX} letters, digits, . _ - "
                          "starting with a letter or digit")
    if args.action == "set":
        if args.value is None:
            raise ModuleError("config set needs a value")
        if len(args.value) > vocabulary.MODULE_VALUE_MAX:
            raise ModuleError(f"config value is longer than {vocabulary.MODULE_VALUE_MAX} characters")
        have[args.key] = args.value
        print(f"{args.name}: set {args.key}={args.value}")
    else:
        if args.key not in have:
            raise ModuleError(f"{args.name} has no config key {args.key!r}")
        del have[args.key]
        print(f"{args.name}: unset {args.key}")
    _save_config(path, have)


def cmd_add(lib, args):
    ok, why = platform_supported()
    if not ok:
        raise ModuleError(why)
    name = args.name
    if not vocabulary.valid_module_name(name):
        raise ModuleError(f"{name!r} is not a valid module name")
    if args.abort:
        return _abort_add(lib, name)
    if not args.source:
        raise ModuleError("module add needs --from <repository> (or --abort to drop a pending add)")
    state = load_state(lib)
    root = modules_dir()
    if name in state or (root / name).exists():
        raise ModuleError(f"module {name!r} is already installed: use `hive-mind module update {name}`")
    pending = _read_pending(name)
    if not lib._owner_key_exists():
        if pending is not None:
            return _complete_add(lib, args, name, root, pending)
        return _stage_for_owner(lib, args, name, root)
    if pending is not None:
        raise ModuleError(f"module {name!r} has a pending add from a device without the owner key: "
                          f"`hive-mind module add --abort {name}` first")
    _require_owner(lib, [("admit", name), ("revoke", None)])
    principal = _operator_principal(lib, args.principal)
    with tempfile.TemporaryDirectory(prefix="hive-module-") as tmp:
        src = Path(tmp) / "src"
        tracked, head = _fetch(args.source, src)
        manifest = check_tree(src, lib.CONTRACT_VERSION, tracked)
        if manifest["name"] != name:
            raise ModuleError(f"the repository holds module {manifest['name']!r}, not {name!r}")
        _confirm_publisher(manifest, args.publisher)
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        staging = root / f".{name}.staging"
        try:
            _stage(src, manifest, staging)
            device_id, _pub = lib.mint_module_key(name)
        except (ModuleError, FileExistsError, OSError, ValueError, RuntimeError) as e:
            shutil.rmtree(staging, ignore_errors=True)
            raise ModuleError(str(e))
        try:
            try:
                lib.admit_cmd(argparse.Namespace(device_id=device_id, principal=principal, module=name))
            except SystemExit:
                pass              # a refused admit: the check below reports it as a ModuleError
            gov = _gov(lib)
            if gov["modules"].get(device_id) != name or device_id not in gov["admitted"]:
                raise ModuleError("the owner could not admit the module's device: nothing installed")
            _write_config(staging, manifest.get("config", {}))
            os.rename(staging, root / name)
            note = install_units(lib, name, manifest)
            state[name] = {"version": manifest["version"], "publisher": manifest["publisher"], "device_id": device_id,
                           "source": args.source, "commit": head, "installed_at": int(time.time()),
                           "quota": dict(manifest.get("quota") or {}), "owner_quota": {}}
            save_state(lib, state)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            _undo_add(lib, name, device_id)
            raise
    print(f"installed module {name} {manifest['version']} (device {device_id}, principal {principal}); "
          + (f"service {unit_names(name)[0]}" + (" with a timer" if manifest["service"].get("interval") else "")
             if manifest.get("service") else "no service")
          + (f" ({note})" if note else "") + "; hooks: " + (", ".join(manifest.get("hooks") or []) or "none"))


def _undo_add(lib, name, device_id):
    """A failed add leaves nothing: the key goes, and a device that was admitted is revoked."""
    try:
        if _device_state(lib, device_id) == "admitted":
            lib._group_change("revoke", device_id)
    except Exception:
        pass
    try:
        still = _device_state(lib, device_id) == "admitted"
    except Exception:
        still = False
    if still:        # the revoke could not be signed (cancelled prompt, agent gone): never silent
        print(f"device {device_id} is still admitted as a module device: run `hive-mind group revoke {device_id}`",
              file=sys.stderr)
    shutil.rmtree(Path(lib._ensure_key_dir()) / "modules" / name, ignore_errors=True)
    shutil.rmtree(modules_dir() / name, ignore_errors=True)
    try:
        remove_units(name)
    except ModuleError:
        pass


def cmd_remove(lib, args):
    state = load_state(lib)
    rec = state.get(args.name)
    if rec is None:
        raise ModuleError(f"module {args.name!r} is not installed")
    device_id = rec["device_id"]
    if not lib._owner_key_exists():
        return _remove_without_owner(lib, args.name, device_id, state)
    _require_owner(lib, [("revoke", device_id)] if _device_state(lib, device_id) == "admitted" else [])
    if _device_state(lib, device_id) == "admitted":
        lib._group_change("revoke", device_id)
    if _device_state(lib, device_id) == "admitted":
        raise ModuleError("the owner could not revoke the module's device: nothing removed")
    remove_units(args.name)                       # stop it before its files and key go
    shutil.rmtree(modules_dir() / args.name, ignore_errors=True)
    shutil.rmtree(Path(lib._ensure_key_dir()) / "modules" / args.name, ignore_errors=True)
    state.pop(args.name)
    save_state(lib, state)
    print(f"removed module {args.name}; its device {device_id} is revoked and its entries stay in the journal")


def _remove_without_owner(lib, name, device_id, state):
    """Remove on a device without the owner key: stop the unit, delete the tree and the key, and say what only the
    owner can finish. The device id stays admitted until the owner's revoke."""
    remove_units(name)                            # stop it before its files and key go
    shutil.rmtree(modules_dir() / name, ignore_errors=True)
    _clear_pending(lib, name)
    shutil.rmtree(Path(lib._ensure_key_dir()) / "modules" / name, ignore_errors=True)
    state.pop(name)
    save_state(lib, state)
    if _device_state(lib, device_id) == "admitted":
        print(f"removed module {name} from this node; its device {device_id} STAYS ADMITTED until the owner revokes it. "
              f"On the owner machine run:\n  hive-mind group revoke {device_id}")
    else:
        print(f"removed module {name} from this node; its device {device_id} is already {_device_state(lib, device_id)}")


def cmd_update(lib, args):
    ok, why = platform_supported()
    if not ok:
        raise ModuleError(why)
    state = load_state(lib)
    rec = state.get(args.name)
    if rec is None:
        raise ModuleError(f"module {args.name!r} is not installed")
    source = args.source or rec["source"]            # no owner key needed: it admits, revokes and re-limits nothing
    root = modules_dir()
    with tempfile.TemporaryDirectory(prefix="hive-module-") as tmp:
        src = Path(tmp) / "src"
        tracked, head = _fetch(source, src)
        manifest = check_tree(src, lib.CONTRACT_VERSION, tracked)
        if manifest["name"] != args.name:
            raise ModuleError(f"the repository holds module {manifest['name']!r}, not {args.name!r}")
        _confirm_publisher(manifest, args.publisher, pinned=rec["publisher"])
        staging, old = root / f".{args.name}.staging", root / f".{args.name}.old"
        try:
            _stage(src, manifest, staging)
        except (ModuleError, OSError):
            shutil.rmtree(staging, ignore_errors=True)
            raise
        live = root / args.name
        swapped = False
        try:
            _write_config(staging, {**manifest.get("config", {}),
                                    **(json.loads((live / "config").read_text()) if (live / "config").exists() else {})})
            shutil.rmtree(old, ignore_errors=True)
            os.rename(live, old)                  # two renames: a crash between them leaves the old copy at `.old`
            swapped = True                        # only now is `.old` this update's; a stale one is never rolled back
            os.rename(staging, live)
            note = install_units(lib, args.name, manifest)
        except BaseException:
            if swapped:
                shutil.rmtree(live, ignore_errors=True)
                os.rename(old, live)
                try:                                  # put the old unit back beside the old files
                    install_units(lib, args.name, json.loads((live / MANIFEST).read_text()))
                except (OSError, ValueError, KeyError):
                    pass
            shutil.rmtree(staging, ignore_errors=True)
            raise
        shutil.rmtree(old, ignore_errors=True)
        rec.update(version=manifest["version"], source=source, commit=head,
                   quota=dict(manifest.get("quota") or {}))     # the owner's own limits (owner_quota) are kept
        save_state(lib, state)
    print(f"updated module {args.name} to {manifest['version']}; its key, device and pinned publisher are unchanged"
          + (f" ({note})" if note else ""))


def _installed_signature(lib, name):
    """'valid' when the installed tree still matches its signed manifest, else why not."""
    d = modules_dir() / name
    try:
        check_tree(d, lib.CONTRACT_VERSION, ignore=("config",))     # `config` is the node's own, not published
    except ModuleError as e:
        return f"INVALID ({e})"
    return "valid"


def _quota_use(lib, device_id):
    now = time.time()
    try:
        times = json.loads((Path(lib.HIVE_HOME) / ".module-quota.json").read_text()).get(device_id, [])
    except (OSError, ValueError, AttributeError):
        times = []
    times = [t for t in times if isinstance(t, (int, float)) and now - 86400 < t <= now]
    life = sum(1 for n, _ in lib.journal_keys() if n == device_id)
    return f"{sum(1 for t in times if t > now - 3600)}/h {len(times)}/d {life} total"


def cmd_list(lib, args):
    state = load_state(lib)
    if not state:
        print("No modules installed.")
        return
    print(f"{'NAME':<16}{'VERSION':<10}{'PUBLISHER':<18}{'SIGNATURE':<10}{'SERVICE':<14}{'DEVICE':<10}QUOTA USE")
    for name, rec in sorted(state.items()):
        sig = _installed_signature(lib, name)
        print(f"{name:<16}{rec['version']:<10}{fingerprint(rec['publisher']):<18}{sig.split(' ')[0]:<10}"
              f"{service_state(name):<14}{_device_state(lib, rec['device_id']):<10}{_quota_use(lib, rec['device_id'])}")
        if sig != "valid":
            print(f"  ! {sig}")


def cmd_quota(lib, args):
    """The owner's way to raise or lower one limit. A manifest may only ask for less; this is how it goes up."""
    state = load_state(lib)
    rec = state.get(args.name)
    if rec is None:
        raise ModuleError(f"module {args.name!r} is not installed")
    _require_owner(lib)                           # nothing is signed: the agent's public-key check is enough
    mine = dict(rec.get("owner_quota") or {})
    for k in QUOTA_KEYS:
        v = getattr(args, k)
        if v is not None:
            if v < 0:
                raise ModuleError(f"{k} must be >= 0")
            mine[k] = v
    rec["owner_quota"] = mine
    save_state(lib, state)
    eff = {**QUOTA_DEFAULTS, **(rec.get("quota") or {}), **mine}
    print(f"{args.name} limits: " + ", ".join(f"{k}={eff[k]}" for k in QUOTA_KEYS))


def cmd_reapply(lib, args):
    """Internal, run by `hive-mind update` after a core update: render every installed module's units again, write
    the files that changed, reload systemd once and restart only those units. It never fails: a module that cannot
    be re-applied is a warning that names it."""
    if not platform_supported()[0]:
        return
    pending = []
    for name in sorted(load_state(lib)):
        try:
            manifest = check_tree(modules_dir() / name, lib.CONTRACT_VERSION, ignore=("config",))
            unit = _write_units(lib, name, manifest, only_changed=True)
        except (ModuleError, OSError, ValueError, KeyError) as e:
            print(f"hive-mind module: warning: {name}: units not re-applied ({e})", file=sys.stderr)
            continue
        if unit:
            pending.append((name, unit))
    if not pending:
        return
    if not _systemctl("show-environment"):
        print("hive-mind module: warning: no user systemd manager is reachable: units written, not restarted",
              file=sys.stderr)
        return
    _systemctl("daemon-reload")
    for name, unit in pending:
        note = _start_unit(unit)
        if note:
            print(f"hive-mind module: warning: {name}: {note}", file=sys.stderr)


# ── `module check`: the publisher's conformance run ─────────────────────────────────────────────────

CHECK_TIMEOUT, CHECK_OUTPUT_CAP = 20, 64 * 1024
STATUS_STATES = ("ok", "degraded", "down", "unknown")
DOCTOR_LEVELS = ("ok", "warn", "fail")
_TEXT_LIMIT = 1024 * 1024
_CODE_SUFFIXES = {".py", ".sh", ".js", ".ts", ".rb", ".pl", ".rs", ".go", ".c", ".h", ".java"}
_LINTS = (
    ("an email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+[A-Za-z]"), False),
    ("a home directory", re.compile(r"/(?:home|Users)/(?![<{$%]|user\b|you\b|name\b|username\b)[A-Za-z0-9._-]+"), False),
    ("an @-handle", re.compile(r"(?<![\w@.])@[A-Za-z0-9][A-Za-z0-9-]{1,38}\b(?!\.[a-z])"), True),
    ("a repository", re.compile(r"github\.com[/:](?![<{$%])[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"), False),
)


def status_problems(obj):
    """Why `obj` is not the fixed `status` envelope, as a list of lines (empty when it is)."""
    if not isinstance(obj, dict):
        return ["status did not print a JSON object"]
    out = []
    if obj.get("schema") != 1 or not _is_int(obj.get("schema")):
        out.append("status `schema` must be 1")
    if obj.get("state") not in STATUS_STATES:
        out.append(f"status `state` must be one of {', '.join(STATUS_STATES)}")
    if not isinstance(obj.get("version"), str):
        out.append("status `version` must be a string")
    if not isinstance(obj.get("problems"), list) or not all(isinstance(p, str) for p in obj["problems"]):
        out.append("status `problems` must be a list of strings")
    units = obj.get("units", [])
    if not isinstance(units, list) or not all(isinstance(u, dict) and isinstance(u.get("name"), str)
                                              and isinstance(u.get("state"), str) for u in units):
        out.append("status `units` must be a list of {name, state}")
    if not isinstance(obj.get("detail", {}), dict):
        out.append("status `detail` must be an object")
    return out


def doctor_problems(obj, returncode):
    """Why `obj` and the exit code are not a conforming `doctor` answer (empty when they are)."""
    if not isinstance(obj, dict):
        return ["doctor did not print a JSON object"]
    out = []
    if obj.get("schema") != 1 or not _is_int(obj.get("schema")):
        out.append("doctor `schema` must be 1")
    results = obj.get("results")
    if not isinstance(results, list) or len(results) > 100:
        return out + ["doctor `results` must be a list of at most 100 results"]
    failed = False
    for i, r in enumerate(results):
        if not (isinstance(r, dict) and r.get("level") in DOCTOR_LEVELS and isinstance(r.get("check"), str)
                and isinstance(r.get("message"), str) and isinstance(r.get("fix_hint", ""), str)
                and set(r) <= {"level", "check", "message", "fix_hint"}
                and all(len(v) <= 400 for v in r.values())):
            out.append(f"doctor result {i} must be {{level: ok|warn|fail, check, message, fix_hint?}} with strings of at most 400 characters")
        else:
            failed = failed or r["level"] == "fail"
    if (returncode != 0) != failed:
        out.append("doctor must exit 0 unless a result is `fail`" if returncode else "doctor reported a `fail` but exited 0")
    return out


def lint_identifying(root, manifest, deny=()):
    """Warnings (not a gate, not a claim): text in the manifest or a shipped file that looks like it names a person,
    host, account or repository. A placeholder (`<user>`, `{org}`, `$HOME`) is not flagged."""
    found = []
    deny = [d.lower() for d in deny if d]
    for rel in [MANIFEST, *sorted(manifest["files"])]:
        path = root / rel
        try:
            if path.stat().st_size > _TEXT_LIMIT:
                continue
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for what, rx, skip_code in _LINTS:
            if skip_code and path.suffix in _CODE_SUFFIXES:
                continue
            for hit in sorted({m.group(0) for m in rx.finditer(text)})[:3]:
                found.append(f"{rel}: looks like {what}: {hit}")
        low = text.lower()
        found += [f"{rel}: holds the denied term {d!r}" for d in deny if d in low]
    return found[:50]


def _run_json(argv, files, mod_dir, env):
    """Run one manifest argv in the throwaway module dir; (returncode, parsed JSON or None, problem or None)."""
    first = argv[0]
    if first.startswith("/"):
        cmd = list(argv)
    elif "/" in first or first in files:
        cmd = [str(mod_dir / first), *argv[1:]]
    else:
        found = shutil.which(first, path=env["PATH"])
        if not found:
            return None, None, f"{first!r} is not on PATH"
        cmd = [found, *argv[1:]]
    try:
        proc = subprocess.Popen(cmd, cwd=str(mod_dir), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        return None, None, f"could not run: {e}"
    timer = threading.Timer(CHECK_TIMEOUT, lambda: _kill_group(proc))
    timer.start()
    try:
        out = proc.stdout.read(CHECK_OUTPUT_CAP + 1)
        if len(out) > CHECK_OUTPUT_CAP:
            _kill_group(proc)
            return None, None, f"printed more than {CHECK_OUTPUT_CAP} bytes"
        proc.wait()
    finally:
        timer.cancel()
        proc.stdout.close()
    if proc.returncode in (-signal.SIGKILL, -signal.SIGTERM):
        return None, None, f"did not finish in {CHECK_TIMEOUT} seconds"
    try:
        return proc.returncode, json.loads(out), None
    except ValueError:
        return proc.returncode, None, "did not print JSON"


def _kill_group(proc):
    if proc.poll() is None:                 # never signal a group whose leader is reaped: the id may be someone else's
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass


def check_module(root, core_version, run=False, deny=()):
    """Everything `module check` reports: (errors, warnings). Errors are what `install` would refuse or what a
    contract-1 module must answer; warnings are the publisher's to read. Validates through `validate_manifest`, the
    code `install` uses, and runs nothing unless `run`."""
    root = Path(root)
    errors, warnings = [], []
    try:
        raw = (root / MANIFEST).read_bytes()
    except OSError:
        return [f"no {MANIFEST} in {root}"], warnings
    try:
        m = validate_manifest(raw, core_version)
    except ModuleError as e:
        return [str(e)], warnings
    if (root / SIGNATURE).exists():
        try:
            sig = base64.b64decode("".join((root / SIGNATURE).read_text().split()), validate=True)
            if not ed25519.verify(raw, sig, base64.b64decode(m["publisher"])):
                errors.append("the manifest signature is not valid under its publisher key")
        except Exception:
            errors.append(f"{SIGNATURE} is not a valid signature file")
    else:
        warnings.append(f"no {SIGNATURE}: unsigned, so `module add` would refuse it")
    tracked = None
    if (root / ".git").exists():
        try:
            ls = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(root), "ls-files", "-z"],
                                check=True, capture_output=True, timeout=30)
            tracked = [n.decode() for n in ls.stdout.split(b"\x00") if n]
        except (OSError, subprocess.SubprocessError):
            warnings.append("could not list the git-tracked files; checked every file on disk")
    try:
        _verify_files(root, m, tracked, ignore=("config",))
    except ModuleError as e:
        errors.append(str(e))
    if "contract" not in m:
        warnings.append("no `contract`: a 3.0-shaped manifest, which installs with none of the 3.1 slots")
    else:
        for field in ("status", "doctor"):
            if run and field not in m:
                warnings.append(f"no `{field}` command: nothing to run for it")
        if "doctor" not in m:
            warnings.append("no `doctor`: every contract-1 module should provide its own")
    warnings += lint_identifying(root, m, deny)
    if run and not errors and "contract" in m:
        with tempfile.TemporaryDirectory(prefix="hive-module-check-") as tmp:
            tmp = Path(tmp)
            mod_dir, keys, home = tmp / "module", tmp / "keys", tmp / "home"
            for d in (keys, home):
                d.mkdir(mode=0o700)
            for rel in [*m["files"], MANIFEST, SIGNATURE]:
                if (root / rel).is_file():
                    (mod_dir / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(root / rel, mod_dir / rel)
                    os.chmod(mod_dir / rel, 0o755 if os.access(root / rel, os.X_OK) else 0o644)
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8",
                   "HIVE_MODULE_NAME": m["name"], "HIVE_MODULE_DIR": str(mod_dir), "HIVE_MODULE_KEY_DIR": str(keys),
                   "HIVE_DOCTOR_MODE": "manual"}
            for field, judge in (("status", lambda rc, obj: ([] if rc == 0 else [f"status exited {rc}, not 0"]) + status_problems(obj)),
                                 ("doctor", lambda rc, obj: doctor_problems(obj, rc))):
                if field not in m:
                    continue
                rc, obj, why = _run_json(m[field], m["files"], mod_dir, env)
                errors += [f"{field} {why}"] if why else [f"{p}" for p in judge(rc, obj)]
    return errors, warnings


def cmd_check(lib, args):
    errors, warnings = check_module(args.dir, lib.CONTRACT_VERSION, run=args.run, deny=args.deny or ())
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors, "warnings": warnings}, indent=1))
    else:
        for w in warnings:
            print(f"warning: {w}")
        for e in errors:
            print(f"error: {e}")
        print(f"{args.dir}: {'FAILED' if errors else 'ok'} ({len(errors)} error(s), {len(warnings)} warning(s))")
    return 1 if errors else 0


def build_parser():
    p = argparse.ArgumentParser(prog="hive-mind module", description="Install and manage modules (Linux, 2.1).")
    sub = p.add_subparsers(dest="verb", required=True)
    a = sub.add_parser("add", help="fetch, verify and install a module, mint its device key and admit it (without the owner key: stage it and print the owner's admit line)")
    a.add_argument("name")
    a.add_argument("--from", dest="source", help="the module's git repository (path or URL); required except with --abort")
    a.add_argument("--abort", action="store_true", help="drop a staged add that is waiting for the owner's admit")
    a.add_argument("--publisher", help="the publisher key you checked (base64); pins it without a prompt")
    a.add_argument("--principal", help="the operator's principal for the module's device (default: this device's)")
    r = sub.add_parser("remove", help="revoke the module's device and delete it (its entries stay in the journal)")
    r.add_argument("name")
    u = sub.add_parser("update", help="re-verify and swap atomically; the publisher key must match the pin")
    u.add_argument("name")
    u.add_argument("--from", dest="source", help="a different repository (default: where it came from)")
    u.add_argument("--publisher", help="ignored unless it equals the pinned key")
    sub.add_parser("list", help="installed modules: version, publisher, signature, service, device, quota use")
    sub.add_parser("reapply", help=argparse.SUPPRESS)           # internal: `hive-mind update` re-renders the units
    q = sub.add_parser("quota", help="the owner raises or lowers a module's limits")
    q.add_argument("name")
    for k in QUOTA_KEYS:
        q.add_argument(f"--{k.replace('_', '-')}", dest=k, type=int)
    c = sub.add_parser("config", help="set, unset or list a module's per-node config (local, kept by update)")
    c.add_argument("name")
    c.add_argument("action", choices=("set", "unset", "list"))
    c.add_argument("key", nargs="?")
    c.add_argument("value", nargs="?")
    k = sub.add_parser("check", help="check a module directory against the module contract (what `add` would refuse; for publishers and CI)")
    k.add_argument("dir")
    k.add_argument("--run", action="store_true", help="also run its `status` and `doctor` commands in a throwaway directory and check what they print")
    k.add_argument("--deny", action="append", metavar="TERM", help="warn on a file that holds TERM (a host, user or organisation name); repeatable")
    k.add_argument("--json", action="store_true", help="print {ok, errors, warnings} as JSON")
    return p


VERBS = {"add": cmd_add, "remove": cmd_remove, "update": cmd_update, "list": cmd_list, "quota": cmd_quota,
         "reapply": cmd_reapply, "config": cmd_config, "check": cmd_check}


def main(lib, argv):
    """Run `hive-mind module <argv>` against the control-plane library `lib`. Returns an exit status."""
    args = build_parser().parse_args(argv)
    if args.verb == "config":
        extra = args.key if args.action == "list" else args.value if args.action == "unset" else None
        if extra is not None or (args.action != "list" and args.key is None):
            print(f"hive-mind module: config {args.action} takes the wrong arguments", file=sys.stderr)
            return 2
    try:
        rc = VERBS[args.verb](lib, args)
        return rc if args.verb == "check" else 0
    except ModuleError as e:
        print(f"hive-mind module: {e}", file=sys.stderr)
        return 1
