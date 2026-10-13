"""Doc-sync for the module docs: every `hive-mind module <verb>` and `hv config <verb>` the module docs show is a verb
the code has, and every `--flag` on those lines is one the code mentions. Offline, no HIVE_HOME needed."""

import re
from pathlib import Path

import hive_modules

PROJECT = Path(__file__).resolve().parent.parent
DOCS = [PROJECT / "README.md", PROJECT / "docs" / "MODULES.md"]
CODE = (PROJECT / "hive_modules.py").read_text() + (PROJECT / "hivemind" / "parts" / "17_cli.py").read_text()

# `hv config` parsers are added in hivemind/parts/17_cli.py; schema/show come from a loop there.
HV_CONFIG = {"identity", "schema", "show", "node", "confidence", "quorum", "set"}
MODULE_CONFIG_ACTIONS = {"list", "get", "set", "unset", "validate", "schema"}


def _uses(prefix):
    """Yield (doc, line, the words after `prefix`) for each line that shows the command."""
    for doc in DOCS:
        for line in doc.read_text().splitlines():
            m = re.search(rf"{re.escape(prefix)}\s+([a-z][a-z-]*)(.*)", line.replace("`", " "))
            if m:
                yield doc.name, line.strip(), m.group(1), m.group(2)


def test_every_documented_module_verb_exists():
    verbs = [verb for _, _, verb, _ in _uses("hive-mind module")]
    assert len(verbs) > 10
    for doc, line, verb, _ in _uses("hive-mind module"):
        assert verb in hive_modules.VERBS, f"{doc}: `hive-mind module {verb}` is not a verb: {line}"


def test_documented_module_flags_exist_in_code():
    for doc, line, _, rest in _uses("hive-mind module"):
        for flag in re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", rest):
            assert flag in CODE or flag[2:].replace("-", "_") in CODE, f"{doc}: {flag} is not in the code: {line}"


def test_every_documented_module_config_action_exists():
    for doc, line, verb, rest in _uses("hive-mind module config <name>"):
        assert verb in MODULE_CONFIG_ACTIONS, f"{doc}: `module config <name> {verb}` is not an action: {line}"


def test_every_documented_hv_config_verb_exists():
    verbs = [verb for _, _, verb, _ in _uses("hv config")]
    assert {"schema", "show", "node"} <= set(verbs)
    for doc, line, verb, _ in _uses("hv config"):
        assert verb in HV_CONFIG, f"{doc}: `hv config {verb}` is not a verb: {line}"


def test_removed_commands_are_named_with_their_replacements():
    text = (PROJECT / "docs" / "MODULES.md").read_text()
    assert "are removed in 4.0" in text and "`hdash dash`" in text and "`hwatch telemetry`" in text
