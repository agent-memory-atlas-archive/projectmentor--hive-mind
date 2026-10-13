"""S3 for fixtures (slice B of docs/design/integration_tests_4x.md): a module signed by a throwaway test publisher, installed by
the real `hive-mind module add` on a real node, checked, health-reported and removed; and each refusal the contract documents.
The publisher-isolation tests are the point of the slice: the throwaway key is never written, pinned or admitted anywhere
but the test node that installed the module.

The plan says `module install` and a "genesis allowlist"; the core's command for a first install is `module add`, and a publisher
is pinned per module in the node's `.modules.json` (trust on first use, or `--publisher`), not in genesis. The tests drive what exists."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _realhome                                              # noqa: E402  (tests/_realhome.py)

from hivefleet import CORE                                    # noqa: E402
from hivefleet.modules import ctl, make_owner, module_add, module_env, modules_state   # noqa: E402
from hivefleet.publisher import ThrowawayPublisher            # noqa: E402

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="module management is Linux-only (2.1)")]

MAX_SCAN = 5_000_000


def _files(root):
    root = Path(root)
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for p in root.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_SCAN:
                yield p
        except OSError:
            continue


def _holding(roots, needles):
    """The files under `roots` (files or directories) that contain any of `needles` (bytes)."""
    hits = []
    for root in roots:
        for p in _files(root):
            try:
                blob = p.read_bytes()
            except OSError:
                continue
            if any(n in blob for n in needles):
                hits.append(str(p))
    return hits


def test_a_fixture_module_installs_checks_reports_and_removes(fleet, publisher, tmp_path):
    node = fleet[0]
    make_owner(node)
    repo = publisher.build()
    r = ctl(node, "module", "check", repo, "--run")
    assert r.returncode == 0 and "0 error(s), 0 warning(s)" in r.stdout, r.stdout + r.stderr
    r = module_add(node, repo, publisher.pub)
    assert r.returncode == 0 and "installed module fixture 1.0.0" in r.stdout, r.stdout + r.stderr
    rec = modules_state(node)["fixture"]
    assert rec["publisher"] == publisher.pub and rec["version"] == "1.0.0"
    assert (node.dir / "modules" / "fixture" / "module.json").exists()
    listed = ctl(node, "module", "list").stdout
    assert "fixture" in listed and "valid" in listed and "admitted" in listed
    r = ctl(node, "module", "status", "fixture")
    assert r.returncode == 0 and "fixture: ok (1.0.0)" in r.stdout
    doc = node.run([sys.executable, CORE / "hv", "doctor", "--format", "json"], env=module_env(node))
    checks = {c["name"]: c for c in json.loads(doc.stdout)["checks"]}
    assert checks["modules:fixture"]["status"] == "ok", checks["modules:fixture"]
    r = ctl(node, "module", "remove", "fixture")
    assert r.returncode == 0 and "removed module fixture" in r.stdout
    assert "fixture" not in modules_state(node) and not (node.dir / "modules" / "fixture").exists()


@pytest.mark.parametrize("how, message", [
    ("tamper", "run.sh"),
    ("unlisted", "extra.sh"),
    ("wrong_signer", "signature is not valid"),
    ("min_core_too_high", "needs core 99.0 or newer"),
])
def test_a_module_the_contract_refuses_installs_nothing(fleet, publisher, tmp_path, how, message):
    node = fleet[0]
    make_owner(node)
    other = ThrowawayPublisher(tmp_path / "other-publisher")
    files = {"run.sh": "#!/bin/sh\nexit 0\n", "status.sh": '#!/bin/sh\nprintf \'{"schema":1,"state":"ok","version":"1.0.0","problems":[]}\\n\'\n'}
    kw = {"tamper": dict(files=files, tamper="run.sh"), "unlisted": dict(unlisted="extra.sh"),
          "wrong_signer": dict(sign_with=other), "min_core_too_high": dict(min_core="99.0")}[how]
    repo = publisher.build(**kw)
    before = sorted(p.read_text() for p in (node.home / "journal").glob("*.jsonl"))
    r = module_add(node, repo, publisher.pub)
    assert r.returncode == 1 and r.stderr.startswith("hive-mind module:") and message in r.stderr, r.stdout + r.stderr
    assert not (node.dir / "modules" / "fixture").exists() and not (node.home / ".modules.json").exists()
    assert sorted(p.read_text() for p in (node.home / "journal").glob("*.jsonl")) == before   # nothing admitted


def test_a_publisher_other_than_the_pinned_one_is_refused(fleet, publisher, tmp_path):
    node = fleet[0]
    make_owner(node)
    other = ThrowawayPublisher(tmp_path / "other-publisher")
    repo = publisher.build()
    r = module_add(node, repo, other.pub)
    assert r.returncode == 1 and "does not match" in r.stderr, r.stderr
    assert not (node.dir / "modules" / "fixture").exists()


def test_the_throwaway_key_is_pinned_only_on_the_node_that_installed_the_module(fleet_factory, publisher):
    fleet = fleet_factory(2)
    installer, bystander = fleet
    make_owner(installer)
    make_owner(bystander)
    repo = publisher.build()
    assert module_add(installer, repo, publisher.pub).returncode == 0
    assert modules_state(installer)["fixture"]["publisher"] == publisher.pub
    assert _holding([installer.dir], [publisher.pub.encode()])                  # positive control: the scan finds it where it belongs
    assert _holding([bystander.dir], [publisher.pub.encode()]) == []
    r = ctl(bystander, "module", "add", "fixture", "--from", repo)            # no --publisher, no tty: not trusted by default
    assert r.returncode == 1 and "--publisher" in r.stderr, r.stderr
    assert not (bystander.home / ".modules.json").exists()


def test_the_throwaway_seed_and_key_never_reach_the_real_account(fleet, publisher, tmp_path):
    node = fleet[0]
    make_owner(node)
    assert module_add(node, publisher.build(), publisher.pub).returncode == 0
    assert ctl(node, "module", "remove", "fixture").returncode == 0
    # The seed (raw, base64, hex) is in no file the run wrote: node directories, fixture repos (including .git), the temp dir.
    assert _holding([tmp_path], publisher.seed_forms()) == []
    # The public key is absent from every non-test hive: the real account's hive, its identity stash and key directories.
    real = _realhome.session_paths()
    non_test = [real["hive"] / ".modules.json", real["hive"] / ".peers.json", real["hive"] / "journal", real["stash"],
                real["key_dir"], real["keys_root"], real["home"] / ".hive" / "modules"]
    assert _holding(non_test, [publisher.pub.encode(), *publisher.seed_forms()]) == []


def test_the_publisher_object_does_not_leak_its_seed(tmp_path):
    import pickle
    pub = ThrowawayPublisher(tmp_path / "p")
    assert not any(f in repr(pub).encode() for f in pub.seed_forms())
    with pytest.raises(TypeError):
        pickle.dumps(pub)
    assert list((tmp_path / "p").iterdir()) == []                              # constructing it writes nothing
