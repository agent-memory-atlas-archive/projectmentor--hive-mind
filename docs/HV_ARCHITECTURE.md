# Architecture: two planes over one library

Since 2.0 (public #136), HiveMind has two commands over one library:

- **`hv`**, the agent **data plane**. Agents and adapters call it to remember, search, decide, sync and
  check health. It cannot produce an owner signature by any route.
- **`hive-mind`**, the owner/operator **control plane**. The owner key is loaded here and governance is
  signed here. It is also the installer front door (`install`, `update`, `reset`, `status`, `invite`,
  `uninstall`).

The split is by **authority**, not by module. `hv` is still one executable Python file (about 9,200
lines) that holds every command's structure, every flag and the whole projection. What moved out is the
ability to sign as the owner.

## Why split at all

An agent runs `hv` constantly, in a working tree other tools also read. Before 2.0, the same binary could
mint, read and use the owner key, so any agent that could run `hv` could, in principle, act as the owner.
Requirement S2 of #136 is that the agent's command cannot owner-sign at all. Using owner authority is now
an explicit act: typing `hive-mind`.

## The files

| File | Plane | What it holds |
|---|---|---|
| `hv` | both (library) | Every command's structure, the parser (`build_parser`), `dispatch`, the journal, the projection, doctor, sync client code. On the data plane, each owner step is a **placeholder** that refuses. |
| `hivemind_ctl.py` | control | The `hive-mind` entry point. Loads `hv` as a library, installs the owner steps, routes only control-plane commands, and refuses the rest with the `hv` form to type. |
| `hivemind_owner.py` | control | Every owner step: reading the seed, producing an `owner_sig`, writing owner-key material, and the commands that exist only to do those things (`owner init`, `group admit`, `config set`, `unforget`, …). |
| `ownerkey.py` | control | The one module that reads the owner seed and produces a governance signature. It holds no path constants: every caller passes paths in. |
| `commandmap.py` | both (table) | Which commands `hive-mind` routes (`CONTROL_PLANE`), what stays on `hv` (`STAYS`), and the policy-refusal text (`FLAG_CONDITIONAL`). No secrets, no imports. |
| `vocabulary.py` | both (table) | The reserved core names; `docs/NAMESPACES.md` is generated from it. No imports. |
| `hive_sync_daemon.py`, `sync_client.py`, `sync_common.py` | data | The sync daemon and client. They load `hv` as a library (`sync_common.load_hv`) and never load the control plane. |
| `merkle.py`, `ed25519.py`, `x25519.py`, `chacha20poly1305.py` | both | Journal hashing and the one canonicaliser (`merkle._canonical`), plus the bundled pure-Python crypto. A build without them refuses to run. |
| `scripts/installer/dispatcher.sh` | control | The `hive-mind` command on `PATH`. Installer verbs run their scripts; everything else `exec`s `hivemind_ctl.py`. It never reads the key or passes a seed. |

`hive-mind` is a `.sh` dispatcher plus a `.py` module rather than an extensionless binary on purpose: the
signed source manifest covers tracked files by suffix and special-cases only the name `hv`, so an
extensionless second entry point would have shipped **unsigned**, and it is the file on the owner-key path.

## How the control plane gets its owner steps

`hivemind_ctl.install(lib)` runs `hivemind_owner.py` **into the library's own namespace**, in the
`hive-mind` process only. Each definition there replaces the `hv` placeholder of the same name. So:

- a command's structure is written once, in `hv`, and its flags once, in `hv`'s parser (S1);
- the owner step keeps the name, globals and signed bytes it always had;
- on the data plane the placeholder raises `NotOnDataPlane` and `hv` refuses, exit **2**, having acted on
  nothing.

`hv` has its own parser: `build_parser(plane="data")` does not define the commands that live on the control plane, and
`hivemind_ctl` builds `build_parser(plane="control")`, the full one, so every flag is still defined once. A control-plane
command typed on `hv` is argparse's unknown command (exit 2, nothing written), and `hv` does not name where it went.
`commandmap.CONTROL_PLANE` is the routing table `hive-mind` reads, nothing more.

Two refusals remain, because they are current verbs refused by hive policy, not moved commands:
`capsule put|rotate|rm` under `capsule_putters=owner` and `wire --add` under `cell_writers=owner`. `hv` says which
policy needs the owner-signed write and the `hive-mind` form to run on the owner machine, and exits 2.

Through 2.x `hv` printed the `hive-mind` form for every moved command (exit 2); 3.0 removed those pointers and closed
the contract §7 amendment that allowed them (`docs/AGENT_INTEGRATION.md` §7).

## What stays on `hv`, and why

`commandmap.STAYS` records the commands that deliberately did not move, so a later tidy-up cannot take a
capability with it:

- **Reads**: `owner show`, `owner elections`, `group list`, `doctor`.
- **Device-signed dead-man recovery**: `owner propose-election --pub` and `owner vote`. An admitted member
  running only `hv` must be able to elect a new owner when the owner has gone dark. Moving these would make
  recovery need the very binary the split keeps off agent nodes.
- **`hv retract`** without `--owner`: peer negative evidence, not governance.
- **Links**: `remember`, `decide` and `entity` run on both planes. Through `hv` their links are
  device-signed; through `hive-mind`, with source `manual`, they are owner-signed (decision
  `h:34cc1dbcd3`, #114).
- **`hv doctor --fix`**, which the 15-minute timer runs, keeps every data-plane repair (daemon, bind,
  device-key permissions, peer addresses, the Claude wiring). The repairs that touch operator state move
  to `hive-mind doctor --fix`: the owner key's permissions and location, the genesis pin, and closing the
  pre-genesis forget grandfather (4c).

## Keys

Private keys live outside the working tree (2.0 PR 3a, private #27), in a 0700 key directory:
`$HIVE_KEY_DIR`, else the path recorded in `$HIVE_HOME/.key-dir`, else
`~/.hive/keys/<sha256 of the checkout's path, 16 hex>`. It holds `device-key` (0600), the owner key and
`owner-pub` (0644). Keys at the pre-2.0 root paths still load, with a `keyperm` warning, and each plane's
`doctor --fix` moves its own.

The owner key is **sealed at rest** (2.0 PR 3b) as `owner-key.sealed`: scrypt, then ChaCha20-Poly1305.
`hive-mind` unlocks it at most once per command, from the terminal or `$HIVE_OWNER_KEY_PASSPHRASE`, which
is deliberately separate from `$HIVE_OWNER_PASSPHRASE` (export and escrow). The device key is not sealed:
every entry is device-signed unattended.

`hv` never opens either form of the owner key. Whether this device holds it is answered from file metadata
and the public `owner-pub` sidecar alone, with four honest answers: `absent`, `unknown` (the key directory
cannot be searched), `present` and `held`.

## How S2 is enforced

The split is checkable rather than promised. The import-graph, owner-signature, seed-reader and adapter
checks each have tests in the suite that build a mutant and show the check failing on it. The mutants for the
other checks were run by hand when each landed, and are recorded on its pull request.

- **Import graph** (`tests/test_s2_split.py`): `hv`'s transitive imports never reach `ownerkey` or the
  control plane, whether directly, transitively or by a dynamic import. An `hv` process never has the
  signer loaded; a `hive-mind` process does.
- **No owner signature within `hv`'s reach**: a static check that no `owner_sig` is produced anywhere `hv`
  can reach, including by an inline signer that imports nothing.
- **The two planes agree** (`tests/test_control_plane.py`): every `CONTROL_PLANE` target is a real control-plane
  command, every `STAYS` entry is a real `hv` command and is refused on the control plane, and the
  dead-man verbs never move. `tests/test_removed_aliases.py` and `tests/test_removed_pointers.py` pin the 3.0 removals: each retired alias and each formerly pointing argv is an unknown command, exit 2, with nothing written.
- **Every placeholder is replaced** on the control plane, and no adapter (MCP, Hermes) reaches the control
  plane or an owner signature.
- **One seed reader** (`tests/test_ownerkey_boundary.py`): `ownerkey` never imports `hv`, owns no hive
  location, never touches `sys.path`, and is the only place the seed is read; `merkle._canonical` is the
  only canonicaliser.

## What the split did not change

- **No journal or wire change** (S7). Every signature has the same bytes, and a mixed 1.x/2.0 fleet
  converges. `_verify_governance` stays on the data plane, because every node projects governance,
  including agent nodes that can never sign.
- **Extensions talk to the core from outside.** This is the internal layout of the core, not a plugin
  design: a module never imports the core's internals.

## The parts (3.1)

`hv` is split into ordered **part files**, `hivemind/parts/NN_<name>.py`, that `hv` executes into its own single
namespace (3.1 PRs 1 and 2; plan in the private design notes, "3.1 plan" section 2). Nothing a user or a node can observe
changes: one runtime namespace, the same names, the same `__file__`. A part is not a module and cannot be imported.

- **`PARTS` in `hv` is the whole list**: a tuple of package-relative paths. The loader (a `for` over it, marked
  `# --- part loader (3.1)` in `hv`) reads each file as bytes, compiles it under its own path (so a traceback names
  the part) and executes it into `hv`'s globals. There is no glob, no configuration path and nothing under
  `HIVE_HOME`; paths resolve through the real path of `hv`, so an installed `hv` runs the installed parts and a symlinked
  `hv` works. It is the only `exec` in the tree, and a test says so.
- **Guards read what runs.** The tests that scan `hv` for a property (S2's import graph, `owner_sig` writes, the seed
  reader, the sealed-key opener, the control-plane and module-management imports) read `hv` plus each part named in
  `PARTS`, through `tests/_source.py`; none reads `hv` alone. `tests/test_hv_parts.py` plants a violation in a part and
  shows each of those guards failing.
- **The parts, in load order** (the order in `PARTS`; each is under 1,500 lines):
  `01_identity` (key directories, device and node ids, owner seal/unseal), `02_store_journal` (schema, FTS, journal
  signing and append, timestamp bounds, quarantine, arrivals, feed), `03_ingest` (`append_foreign_entries`, the
  first-pull door), `04_projection` (persistence, confidence, governance state, genesis pin, content evidence),
  `05_trust_validation` (trust velocity, salience, entity verdicts, module policy, payload validators),
  `06_links_forget` (links, refs, supersede and resolve, forget authorisation), `07_data_commands` (`remember`,
  `retract`, `search`, `propose`, `decide`), `08_read_api` (`api_*`, `dash`, the probe and fleet-contract block),
  `09_entity_store_ops` (`entity`, `rebuild`, `stats`, `merkle`, `sync`), `10_agent_loop` (nudge, audit, whoami,
  digest), `11_release_node` (`version`, `verify`, identity commands, daemon management, `wire`), `12_capsules_keys`
  (`capsule`, key-file hygiene), `13_doctor_status` (`_doctor_status` and helpers), `14_peers` (peer candidates,
  address proving), `15_doctor_control_join` (`doctor`, `owner`, `group`, `admit`, `migrate`, `config`, `peers`,
  `discover`, `join`), `16_telemetry`, `17_cli` (`build_parser`, dispatch). `hv` keeps the header, the loader and the
  `if __name__ == "__main__":` footer.
- **What guards the split**: the move PRs were checked against their base byte for byte; that gate is retired, since
  there is no old `hv` left to compare with. What stays are the structural checks (list equals directory, size cap, the
  namespace is the old one plus `PARTS`, every code object comes from `hv` or a listed part, undefined names via
  pyflakes).

## Still one namespace

`hv` stays one runtime namespace for the reasons it always did: it is a signed artifact that runs on the Python 3
standard library alone, is updated by `git pull`, and has one dispatch surface. The split removed the
largest reason to break it up, owner authority, by moving that out. The seams that remain, in order of
safety, if the navigation cost ever outweighs that simplicity:

1. **Confidence and corroboration scoring**: mostly pure functions over parsed entries.
2. **Advisories**: small and self-contained (see [ADVISORIES.md](ADVISORIES.md)).
3. **Journal I/O** (`append_journal`, `append_foreign_entries`, `init_db`): cohesive, but this is where the
   shared SQLite connection (`get_conn()`) couples most commands.
4. **The governance projection** (`_governance_state`): the most interdependent block, last.

Before any of those, thread the database connection and the governance projection through explicitly
rather than as implicit globals; until then a split mostly moves the coupling around.

The original peer-to-peer sync design, from June 2026, is kept as history in
[history/P2P_DESIGN.md](history/P2P_DESIGN.md). Where it and the code disagree, the code, this page,
[SYNC_API.md](SYNC_API.md), [INTERNALS.md](INTERNALS.md) and [THREAT_MODEL.md](THREAT_MODEL.md) are
authoritative.
