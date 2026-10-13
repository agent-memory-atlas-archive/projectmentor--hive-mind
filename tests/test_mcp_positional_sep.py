"""SECREV C MCP-01: the MCP server puts `--` before every positional it passes to `hv`, so a value that starts
with `-` (a memory beginning "--source x", a search for "-v") is the value, never a flag."""
import importlib.util
import sys
import types
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent


@pytest.fixture
def mcp_mod(monkeypatch):
    fastmcp = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda f: f

    fastmcp.FastMCP = FastMCP
    for name in ("mcp", "mcp.server"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp)
    monkeypatch.setenv("HIVE_HOME", str(PROJECT))
    spec = importlib.util.spec_from_file_location("hive_mcp_sep", PROJECT / "integrations" / "mcp" / "hive_mcp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    seen = []
    monkeypatch.setattr(mod, "_run_hv", lambda args, **k: seen.append(list(args)) or "[]")
    return mod, seen


HOSTILE = "--source attacker"


@pytest.mark.parametrize("tool,kwargs", [
    ("hive_remember", {"content": HOSTILE, "tags": "a", "supports": "h:x"}),
    ("hive_propose", {"content": HOSTILE, "tags": "a"}),
    ("hive_decide", {"content": HOSTILE, "rationale": "r"}),
    ("hive_retract", {"fact_id": HOSTILE, "reason": "r"}),
    ("hive_search", {"query": HOSTILE}),
])
def test_the_positional_follows_a_double_dash_and_ends_the_argv(mcp_mod, tool, kwargs):
    mod, seen = mcp_mod
    getattr(mod, tool)(**kwargs)
    argv = seen[-1]
    assert argv[-2:] == ["--", HOSTILE], argv
    assert argv.count("--") == 1 and HOSTILE not in argv[:-1]
