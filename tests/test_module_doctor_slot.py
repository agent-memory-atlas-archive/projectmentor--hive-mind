"""3.1 doctor slot (#294 PR 4, design `module_contract_3_1.md` §7, §13). A contract-1 module's own `doctor` runs in
`hv doctor` under `modules:<name>`, at the end of `module add` and `update`, and from the timer; its results are
capped, cleaned and cached; every way it can misbehave is a `warn`, a `fail` it reports stays a `fail`; its
environment holds no owner or identity variable; and `--fix` never runs module code."""

import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import _planes  # noqa: E402
import hive_module_doctor  # noqa: E402
import hive_modules  # noqa: E402
from test_module_doctor import _doctor, _mod, listener  # noqa: E402,F401
from test_module_lifecycle import LINUX_ONLY, OTHER_SEED, _add, _publish, hive, units  # noqa: E402,F401
from test_module_runtimes_launcher import V31, bindir  # noqa: E402,F401
from test_succession import _run  # noqa: E402


def doctor_script(results, rc=0, extra=""):
    body = json.dumps({"schema": 1, "results": results})
    return f"#!/bin/sh\n{extra}\ncat <<'JSON'\n{body}\nJSON\nexit {rc}\n"


def publish(tmp_path, script, **kw):
    return _publish(tmp_path / "repo", files={"run.sh": "#!/bin/sh\nexit 0\n", "hooks/stop": "#!/bin/sh\nexit 0\n",
                                              "doctor.sh": script}, **{**V31, "doctor": ["doctor.sh"], **kw})


def cache(home, name="demo"):
    return home / ".module-doctor" / f"{name}.json"


def ok(check="deps", message="all there"):
    return {"level": "ok", "check": check, "message": message}


# ── what the core makes of one run ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("obj,rc,why,words", [
    (None, None, "did not finish in 20 seconds", "did not finish"),
    (None, None, "could not run: boom", "could not run"),
    (None, None, "'nosuch' is not on PATH", "not on PATH"),
    (None, None, "printed more than 65536 bytes", "printed more than"),
    (None, 1, "did not print JSON", "did not print JSON"),
    ([], 0, None, "JSON object"),
    ({"schema": 2, "results": []}, 0, None, "schema"),
    ({"schema": 1, "results": "x"}, 0, None, "list"),
    ({"schema": 1, "results": []}, 3, None, "exited 3"),
    ({"schema": 1, "results": [ok()]}, 2, None, "exited 2"),
    ({"schema": 1, "results": [{"level": "bad", "check": "c", "message": "m"}]}, 0, None, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": "c", "message": "m", "extra": 1}]}, 0, None, "result 0"),
    ({"schema": 1, "results": [{"level": "ok", "check": 1, "message": "m"}]}, 0, None, "result 0"),
    ({"schema": 1, "results": ["x"]}, 0, None, "result 0"),
])
def test_every_failure_mode_is_a_warn_that_names_the_problem(obj, rc, why, words):
    out = hive_modules.doctor_results(rc, obj, why)
    assert out and all(r["level"] == "warn" for r in out if words in r["message"]) and any(words in r["message"] for r in out)
    assert not any(r["level"] == "fail" for r in out)


def test_a_reported_fail_stays_a_fail_and_a_zero_exit_does_not_hide_it():
    bad = {"level": "fail", "check": "key", "message": "no key", "fix_hint": "make one"}
    assert hive_modules.doctor_results(1, {"schema": 1, "results": [ok(), bad]}, None)[1] == bad
    assert hive_modules.doctor_results(0, {"schema": 1, "results": [bad]}, None) == [bad]
    assert hive_modules.doctor_worst([ok(), bad]) == "fail" and hive_modules.doctor_worst([]) == "ok"


def test_caps_and_cleaning():
    many = {"schema": 1, "results": [ok(f"c{i}") for i in range(150)]}
    out = hive_modules.doctor_results(0, many, None)
    assert len(out) == 101 and out[-1]["level"] == "warn" and "first 100" in out[-1]["message"]
    nasty = {"level": "warn", "check": "a\x1b[31mb", "message": "x" * 900 + "‮", "fix_hint": "line\none​"}
    r = hive_modules.doctor_results(0, {"schema": 1, "results": [nasty]}, None)[0]
    assert r["check"] == "a[31mb" and len(r["message"]) == 400 and "‮" not in r["message"]
    assert r["fix_hint"] == "line one"


# ── running it ────────────────────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_the_environment_holds_the_modules_own_variables_and_no_owner_or_identity_one(hive, tmp_path, bindir, monkeypatch):
    script = doctor_script([], extra=f"env | cut -d= -f1 | sort | tr '\\n' ',' > '{tmp_path}/seen'")
    pub = publish(tmp_path, script)
    _add(hive, tmp_path / "repo", pub)
    for var in ("HIVE_OWNER_PASSPHRASE", "HIVE_OWNER_SEED", "HIVE_OWNER_KEY_PASSPHRASE", "HIVE_KEY_DIR", "HIVE_IDENTITY_STASH", "HIVE_NODE_ID"):
        monkeypatch.setenv(var, "secret")
    rec = json.loads((hive / ".modules.json").read_text())["demo"]
    manifest = json.loads((tmp_path / "modules" / "demo" / "module.json").read_text())
    monkeypatch.setenv("HIVE_MODULES_DIR", str(tmp_path / "modules"))
    hive_modules.run_doctor("demo", rec, manifest, tmp_path / "keys", "boot")
    seen = (tmp_path / "seen").read_text().strip(",").split(",")
    hive_vars = sorted(v for v in seen if v.startswith("HIVE_"))
    assert hive_vars == ["HIVE_DOCTOR_MODE", "HIVE_MODULE_DIR", "HIVE_MODULE_KEY_DIR", "HIVE_MODULE_NAME"]
    assert "secret" not in "".join(seen)


@LINUX_ONLY
def test_hv_doctor_merges_the_modules_results_and_caches_them(hive, tmp_path, bindir, listener):
    pub = publish(tmp_path, doctor_script([ok(), {"level": "warn", "check": "token", "message": "expires soon", "fix_hint": "renew"}]))
    _add(hive, tmp_path / "repo", pub)
    r, c = _mod(hive)
    assert c["status"] == "warn" and "token: expires soon (renew)" in c["detail"]
    doc = json.loads(cache(hive).read_text())
    assert doc["schema"] == 1 and doc["module"] == "demo" and doc["mode"] == "manual" and doc["worst"] == "warn"
    assert [x["check"] for x in doc["results"]] == ["deps", "token"] and isinstance(doc["at"], int)
    assert stat.S_IMODE(cache(hive).stat().st_mode) == 0o600 and stat.S_IMODE(cache(hive).parent.stat().st_mode) == 0o700


@LINUX_ONLY
def test_a_module_that_reports_fail_fails_its_line_and_a_clean_one_stays_ok(hive, tmp_path, bindir, listener):
    pub = publish(tmp_path, doctor_script([{"level": "fail", "check": "key", "message": "config key missing"}], rc=1))
    _add(hive, tmp_path / "repo", pub)
    r, c = _mod(hive)
    assert c["status"] == "fail" and "config key missing" in c["detail"] and r.returncode != 0


@LINUX_ONLY
def test_a_crashing_doctor_is_a_warn_and_the_core_checks_still_run(hive, tmp_path, bindir, listener):
    pub = publish(tmp_path, "#!/bin/sh\nexit 3\n")
    _add(hive, tmp_path / "repo", pub)
    r, checks = _doctor(hive)
    c = checks["modules:demo"]
    assert c["status"] == "warn" and "did not print JSON" in c["detail"]
    assert checks["sync-daemon"]["status"] == _doctor(hive)[1]["sync-daemon"]["status"] and "authenticity" in checks     # the core checks still ran


@LINUX_ONLY
def test_timer_mode_reaches_the_module_and_the_cache(hive, tmp_path, bindir, listener, monkeypatch):
    pub = publish(tmp_path, doctor_script([], extra=f"printf \"$HIVE_DOCTOR_MODE\" > '{tmp_path}/mode'"))
    _add(hive, tmp_path / "repo", pub)
    monkeypatch.setenv("HIVE_DOCTOR_MODE", "timer")
    _mod(hive)
    assert (tmp_path / "mode").read_text() == "timer"
    assert json.loads(cache(hive).read_text())["mode"] == "timer"
    monkeypatch.setenv("HIVE_DOCTOR_MODE", "bogus")
    _mod(hive)
    assert (tmp_path / "mode").read_text() == "manual"


@LINUX_ONLY
def test_a_manifest_that_does_not_verify_never_runs_module_code(hive, tmp_path, bindir, listener):
    pub = publish(tmp_path, doctor_script([], extra=f"touch '{tmp_path}/ran'"))
    _add(hive, tmp_path / "repo", pub)
    ran = tmp_path / "ran"
    ran.unlink(missing_ok=True)
    cache(hive).unlink()
    (tmp_path / "modules" / "demo" / "doctor.sh").write_text(f"#!/bin/sh\ntouch '{tmp_path}/ran'\n")
    r, c = _mod(hive)
    assert c["status"] == "fail" and not ran.exists() and not cache(hive).exists()


@LINUX_ONLY
def test_a_tree_validly_signed_by_another_key_never_runs_its_doctor(hive, tmp_path, bindir, listener):
    script = doctor_script([], extra=f"touch '{tmp_path}/ran'")
    _add(hive, tmp_path / "repo", publish(tmp_path, script))
    (tmp_path / "ran").unlink(missing_ok=True)
    cache(hive).unlink(missing_ok=True)
    other = publish(tmp_path / "other", script, seed=OTHER_SEED)         # same files, a valid manifest under a key that is not the pin
    for f in ("module.json", "module.json.sig"):
        shutil.copy(tmp_path / "other" / "repo" / f, tmp_path / "modules" / "demo" / f)
    r, c = _mod(hive)
    assert c["status"] == "fail" and "pinned" in c["detail"] and not (tmp_path / "ran").exists() and not cache(hive).exists()


@pytest.mark.parametrize("script", [
    "sleep 60 &\necho '{\"schema\":1,\"results\":[]}'\n",                          # a background child keeps the pipe open
    "setsid sleep 60 &\necho '{\"schema\":1,\"results\":[]}'\nsleep 60\n",           # a child that left the process group
    "setsid sleep 60 &\nsleep 60\n",
])
def test_a_child_holding_the_pipe_does_not_extend_the_timeout(tmp_path, monkeypatch, script):
    mod = tmp_path / "mod"
    mod.mkdir()
    (mod / "doc.sh").write_text("#!/bin/sh\n" + script)
    (mod / "doc.sh").chmod(0o755)
    monkeypatch.setattr(hive_modules, "CHECK_TIMEOUT", 2)
    t0 = time.monotonic()
    rc, obj, why = hive_modules._run_json(["doc.sh"], {"doc.sh": "x"}, mod, {"PATH": "/usr/bin:/bin"})
    assert time.monotonic() - t0 < 10
    assert why is None or "did not finish" in why


@LINUX_ONLY
def test_a_manifest_without_contract_or_doctor_changes_nothing(hive, tmp_path, listener):
    _add(hive, tmp_path / "repo", _publish(tmp_path / "repo"))
    r, c = _mod(hive)
    assert "doctor" not in c["detail"] and not cache(hive).exists()


@LINUX_ONLY
def test_a_missing_runtime_is_a_core_warn(hive, tmp_path, bindir, listener, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    pub = publish(tmp_path, doctor_script([ok()]), runtimes=["zzzprog"])
    _add(hive, tmp_path / "repo", pub)
    r, c = _mod(hive)
    assert c["status"] == "warn" and "runtime zzzprog is not on the module's PATH" in c["detail"]


# ── install, update, remove ─────────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_install_and_update_run_it_print_it_and_never_roll_back(hive, tmp_path, bindir):
    script = doctor_script([{"level": "fail", "check": "key", "message": "no key", "fix_hint": "run setup"}], rc=1,
                           extra=f"printf \"$HIVE_DOCTOR_MODE\" >> '{tmp_path}/modes'")
    pub = publish(tmp_path, script)
    r = _add(hive, tmp_path / "repo", pub)                                    # no flag: still exit 0
    assert "doctor fail: key: no key (run setup)" in r.stdout
    assert (tmp_path / "modes").read_text() == "install"
    assert json.loads(cache(hive).read_text())["mode"] == "install"
    (tmp_path / "modes").unlink()
    pub = publish(tmp_path, script, version="1.1.0")
    u = _run(hive, "module", "update", "demo", "--from", str(tmp_path / "repo"), "--require-healthy", check=False)
    assert u.returncode == 1 and "updated module demo to 1.1.0" in u.stdout and "doctor fail" in u.stdout
    assert (tmp_path / "modes").read_text() == "update"
    assert json.loads((hive / ".modules.json").read_text())["demo"]["version"] == "1.1.0"      # kept


@LINUX_ONLY
def test_require_healthy_passes_for_a_clean_doctor_and_remove_drops_the_cache(hive, tmp_path, bindir):
    pub = publish(tmp_path, doctor_script([ok()]))
    r = _add(hive, tmp_path / "repo", pub, "demo", True, "--require-healthy")
    assert r.returncode == 0 and "doctor ok: deps: all there" in r.stdout and cache(hive).exists()
    _run(hive, "module", "remove", "demo")
    assert not cache(hive).exists()


# ── --fix, the cache file and the timer ─────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_fix_never_runs_module_code(hive, tmp_path, bindir, monkeypatch):
    pub = publish(tmp_path, doctor_script([ok()]), service={"command": ["run.sh"], "restart": "always"})
    _add(hive, tmp_path / "repo", pub)
    boom = lambda *a, **k: (_ for _ in ()).throw(AssertionError("fix ran module code"))
    for fn in ("run_doctor", "doctor_after", "_run_json"):
        monkeypatch.setattr(hive_modules, fn, boom)
    monkeypatch.setenv("HIVE_MODULES_DIR", str(tmp_path / "modules"))
    hive_module_doctor.fix(_planes.load_hv(hive))
    src = Path(hive_module_doctor.__file__).read_text().split("def fix(", 1)[1]
    assert "run_doctor" not in src and "_own_doctor" not in src


def test_the_cache_is_not_written_through_a_link_or_a_shared_directory(tmp_path):
    results = [ok()]
    assert hive_modules.write_doctor_cache(tmp_path, "demo", "manual", "1", results) and hive_modules.read_doctor_cache(tmp_path, "demo")["worst"] == "ok"
    other = tmp_path / "o"
    other.mkdir()
    (other / ".module-doctor").symlink_to(tmp_path / ".module-doctor")
    assert not hive_modules.write_doctor_cache(other, "demo", "manual", "1", results)
    assert hive_modules.read_doctor_cache(other, "demo") is None
    shared = tmp_path / "s"
    (shared / ".module-doctor").mkdir(parents=True)
    (shared / ".module-doctor").chmod(0o777)
    assert not hive_modules.write_doctor_cache(shared, "demo", "manual", "1", results)
    assert not hive_modules.write_doctor_cache(tmp_path, "../x", "manual", "1", results)


def test_a_hand_edited_cache_is_cleaned_on_read_and_junk_is_none(tmp_path):
    hive_modules.write_doctor_cache(tmp_path, "demo", "manual", "1", [ok()])
    path = tmp_path / ".module-doctor" / "demo.json"
    doc = json.loads(path.read_text())
    doc["results"] = [{"level": "warn", "check": "a\x1b[2J", "message": "m‮"}, "junk", {"level": "boom", "check": "c", "message": "m"}]
    path.write_text(json.dumps(doc))
    got = hive_modules.read_doctor_cache(tmp_path, "demo")
    assert got["results"] == [{"level": "warn", "check": "a[2J", "message": "m"}]
    path.write_text("[1]")
    assert hive_modules.read_doctor_cache(tmp_path, "demo") is None


def test_the_doctor_timer_sets_the_mode_on_every_platform():
    for rel, needle in (("scripts/platform/linux/_units.sh", "Environment=HIVE_DOCTOR_MODE=timer"),
                        ("scripts/platform/macos/_launchd.sh", "<key>HIVE_DOCTOR_MODE</key><string>timer</string>"),
                        ("scripts/platform/termux/_runit.sh", "export HIVE_DOCTOR_MODE=timer")):
        assert needle in (PROJECT / rel).read_text()
