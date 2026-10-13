"""3.1 PR 6 (design §5): the read routes `overview`, `tags`, `related`, `audit`, `peers`, `verify`, `node`, served to a module
only if its signed manifest names them in `reads`. Same harness as `test_module_api`: the real handler over loopback HTTP, a
journal with real signatures, and the `.modules.json` row the installer writes."""
import json
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
import hive_module_api as api  # noqa: E402
import hive_modules  # noqa: E402
import test_links as TL  # noqa: E402
from test_unforget import _act  # noqa: E402
from test_module_api import Hive, T  # noqa: E402

ALL = list(api.READ_ROUTES)


@pytest.fixture
def hive(tmp_path, monkeypatch):
    h = Hive(tmp_path, monkeypatch)
    hv = h.hv
    o = (h.owner[0], h.owner[1])
    h.tagged = TL._entry(hv, h.plain, "fact", {"content": "the nightly job uses rsync", "tags": ["backup"], "importance": 0.5,
                                               "source": "manual"}, T % 20)
    h.tagged2 = TL._entry(hv, h.plain, "fact", {"content": "rsync keeps hardlinks", "tags": ["backup"], "importance": 0.5,
                                                "source": "manual"}, T % 21)
    h.tagged_gone = TL._entry(hv, h.plain, "fact", {"content": "the backup key is under the mat", "tags": ["backup"],
                                                    "importance": 0.5, "source": "manual"}, T % 22)
    forget = _act(hv, h.plain, h.tagged_gone, T % 23, owner=o)
    h.entries = h.entries + [h.tagged, h.tagged2, h.tagged_gone, forget]
    TL._project(hv, tmp_path, h.entries).close()
    declare(h, "hwatch", ALL)
    yield h
    h.close()


def declare(h, module, reads):
    path = h.hv.HIVE_HOME / ".modules.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    rec = state.setdefault(module, {"version": "1", "quota": {}, "owner_quota": {}})
    rec.pop("reads", None)
    if reads is not None:
        rec["reads"] = reads
    path.write_text(json.dumps(state))


def local_id(h, entry):
    conn = h.hv.get_conn()
    try:
        return conn.execute("SELECT local_id FROM journal_index WHERE sid = ?", (h.hv._short_id(entry["node_id"], entry["seq"]),)).fetchone()[0]
    finally:
        conn.close()


def test_the_two_route_lists_agree():
    assert api.READ_ROUTES == hive_modules.READ_ROUTES


def test_an_undeclared_route_is_403_and_logged_once(hive, capsys):
    declare(hive, "hwatch", ["tags"])
    for _ in range(2):
        for n in ALL:
            code, body = hive.get(f"/v1/{n}")
            if n == "tags":
                assert code == 200
            else:
                assert (code, body["detail"], body["route"]) == (403, "read-not-declared", n)
    err = capsys.readouterr().err
    assert err.count("read /v1/overview") == 1 and "read /v1/tags" not in err


def test_a_module_with_no_reads_gets_none_and_another_modules_list_is_not_its_own(hive):
    declare(hive, "hwatch", None)
    declare(hive, "other", ["overview"])
    assert all(hive.get(f"/v1/{n}")[0] == 403 for n in ALL)
    assert hive.get("/v1/overview", dev="other")[0] == 200
    assert hive.get("/v1/tags", dev="other")[0] == 403


@pytest.mark.parametrize("bad", ["overview", {"tags": 1}, [3], ["nope"], ["overview", "nope"]])
def test_a_malformed_or_unknown_record_serves_only_the_known_names(hive, bad):
    declare(hive, "hwatch", bad)
    want = ["overview"] if bad == ["overview", "nope"] else []
    assert api.declared_reads("hwatch") == want


def test_a_missing_or_garbled_state_file_serves_no_read(hive):
    (hive.hv.HIVE_HOME / ".modules.json").write_text("{not json")
    assert hive.get("/v1/tags")[0] == 403
    (hive.hv.HIVE_HOME / ".modules.json").unlink()
    assert hive.get("/v1/tags")[0] == 403


def test_dropping_a_route_takes_effect_on_the_next_request(hive):
    assert hive.get("/v1/tags")[0] == 200
    declare(hive, "hwatch", ["overview"])
    assert hive.get("/v1/tags")[0] == 403


def test_the_root_lists_reads_only_when_declared(hive):
    assert hive.get("/v1/")[1]["reads"] == ALL
    declare(hive, "hwatch", None)
    assert "reads" not in hive.get("/v1/")[1]


def test_overview_tags_verify_and_peers_answer_what_the_api_twin_does(hive):
    hv = hive.hv
    code, ov = hive.get("/v1/overview")
    assert code == 200 and ov == hv.api_overview()
    assert hive.get("/v1/tags") == (200, hv.api_tags())
    assert "backup" in hive.get("/v1/tags")[1]["tags"]
    code, v = hive.get("/v1/verify")
    assert code == 200 and set(v) >= {"ok", "level", "lines"}
    code, p = hive.get("/v1/peers?probe=0")
    assert code == 200 and isinstance(p["peers"], list)


def test_related_leaves_forgotten_facts_out_and_answers_empty_for_a_forgotten_source(hive):
    hv = hive.hv
    src = local_id(hive, hive.tagged)
    code, body = hive.get(f"/v1/related?id={src}")
    assert code == 200
    texts = [r["content"] for r in body["related"]]
    assert texts == ["rsync keeps hardlinks"] and body["tags"] == ["backup"]
    # the twin the dashboard uses does show the forgotten one, so the filter is what hides it
    assert "the backup key is under the mat" in [r["content"] for r in hv.api_related("fact", src)["related"]]
    gone = local_id(hive, hive.tagged_gone)
    assert hive.get(f"/v1/related?id={gone}") == (200, {"related": [], "tags": []})


@pytest.mark.parametrize("q", ["", "?id=", "?id=abc", "?id=-1", "?id=1.5", "?id=" + "9" * 40, "?id=1&kind=idea"])
def test_related_refuses_a_bad_id_or_kind(hive, q):
    assert hive.get("/v1/related" + q)[0] == 400


def test_audit_leaves_a_forgotten_volatile_fact_out(hive):
    hv = hive.hv
    blob = json.dumps(hive.get("/v1/audit")[1])
    assert "volatile secret" not in blob and "backup key" not in blob
    assert "volatile secret" in json.dumps(hv.api_audit())      # the unfiltered twin shows it: the filter is the difference


def test_node_resolves_only_an_admitted_reachable_peer(hive, monkeypatch):
    monkeypatch.setattr(hive.hv, "api_node_addr", lambda n: "100.64.0.9:9876" if n == hive.plain["id"] else None)
    assert hive.get(f"/v1/node?node={hive.plain['id']}") == (200, {"node": hive.plain["id"], "addr": "100.64.0.9:9876"})
    assert hive.get("/v1/node?node=k1:nobody")[0] == 404
    assert hive.get("/v1/node")[0] == 400 and hive.get("/v1/node?node=" + "x" * 200)[0] == 400


def test_reads_are_get_only(hive):
    code, body = hive.get("/v1/tags", method="POST", body=b"{}")
    assert code == 405 and body["error"] == "/v1/tags takes GET"


def test_the_read_bucket_is_per_device_429_with_retry_after_and_leaves_the_write_quota_alone(hive, monkeypatch):
    monkeypatch.setattr(api, "READ_BURST", 3)
    monkeypatch.setattr(api, "_read_buckets", {})
    declare(hive, "other", ["tags"])
    assert [hive.get("/v1/tags")[0] for _ in range(3)] == [200, 200, 200]
    code, body = hive.get("/v1/tags")
    assert code == 429 and body["retry_after"] >= 1
    assert hive.get("/v1/tags", dev="other")[0] == 200            # another device has its own bucket
    assert hive.get("/v1/")[1]["quota"]["used"] == {"per_hour": 0, "per_day": 0, "lifetime": 0}


def test_the_bucket_refills(monkeypatch):
    monkeypatch.setattr(api, "_read_buckets", {})
    monkeypatch.setattr(api, "READ_BURST", 2)
    assert api._read_take("d", 100.0) is None and api._read_take("d", 100.0) is None
    wait = api._read_take("d", 100.0)
    assert wait and wait > 0
    assert api._read_take("d", 100.0 + 1 / api.READ_RATE) is None


def test_an_undeclared_read_does_not_spend_a_token(hive, monkeypatch):
    monkeypatch.setattr(api, "READ_BURST", 1)
    monkeypatch.setattr(api, "_read_buckets", {})
    declare(hive, "hwatch", ["tags"])
    for _ in range(5):
        assert hive.get("/v1/overview")[0] == 403
    assert hive.get("/v1/tags")[0] == 200


def test_the_reads_record_and_summary_are_empty_without_reads():
    assert hive_modules._reads_record({"name": "x"}) == {} and hive_modules.reads_summary({"name": "x"}) == ""
    assert hive_modules._reads_record({"reads": []}) == {}
    assert hive_modules._reads_record({"reads": ["tags"]}) == {"reads": ["tags"]}
    line = hive_modules.reads_summary({"reads": ["overview", "tags", "peers", "node", "verify"]})
    assert "peers [tailnet addresses] [node-local]" in line and "node [tailnet addresses]" in line
    assert "overview [node-local]" in line and "verify [node-local]" in line and "tags," in line
