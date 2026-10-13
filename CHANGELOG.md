# Changelog

HiveMind is versioned by its **agent contract** (`hv version`), `MAJOR.MINOR`. A MINOR is additive
for the adapter surface — the verbs, flags and outputs an agent calls keep working — while a MAJOR
means adapters must re-integrate (see [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md) §7,
which also records what each version means for an adapter).

Git tags are `vMAJOR.MINOR.PATCH`. `vX.Y.0` marks the commit on `main` that completed contract
`X.Y`, so the tag contains everything that version shipped. Fixes and documentation that follow
without changing the contract are tagged `vX.Y.1`, `vX.Y.2`, … Dates are when each version was
introduced (a contract) or tagged (a patch).

## 3.1.0 — 2026-10-13 · `v3.1.0`

- `CONTRACT_VERSION` moves from the body of `hv` into its header, and a permanent test checks that `_update.sh` still reads the contract major from `hv`'s text (3.1 split, PR 0b; no behaviour change).
- `hv` gains a part loader and its first part, `hivemind/parts/01_identity.py` (key directories, device and node ids, owner seal and unseal): the same code, run into `hv`'s one namespace from the list `PARTS`. The static guards that scan `hv` now read `hv` and its parts (3.1 split, PR 1; no behaviour change).
- `hv`'s body moves into `hivemind/parts/02_store_journal.py` through `17_cli.py`, run into `hv`'s one namespace in order by the part loader; `hv` is now its header, the loader and the `__main__` footer. The same code in the same order; no behaviour change (3.1 split, PR 2).
- **3.1: module manifest contract 1.** A signed `module.json` may now declare `"contract": 1` and the optional fields `cli`, `runtimes`, `config_schema` (replacing `config`), `status`, `doctor`, `reads` and `ui`; the validator refuses a malformed field, a contract-1 field without `contract`, an unknown `contract`, a `min_core` below 3.1, and a default on an `identifying` or `secret` config key. A manifest without `contract` is accepted unchanged. New `hive-mind module check <dir> [--run] [--deny TERM] [--json]` runs the same validator for publishers and CI, lints shipped files for identifying text (warnings only), and with `--run` checks the `status` and `doctor` shapes in a throwaway directory. `docs/ui_block.schema.json` defines the `ui` block. A 3.0 node refuses a contract-1 manifest as unknown fields. The behaviour that acts on these fields (config schema, runtimes and the CLI launcher, the module doctor, read routes) is described in the entries below.
- **3.1: per-module configuration (`config_schema`).** A contract-1 module's config keys are now typed, scoped (`node`, `fleet`, `fleet-node`) and checked: `hive-mind module config <name>` gains `get`, `validate`, `--fleet`, `--fleet-node <device>`, `--stdin`, `--merged` and `--json`, shows each value's source (node, fleet-node, fleet or default) and masks a `secret` key everywhere and never takes it from the command line. `set` to the current value signs nothing. `module add` and `update` take `--set`, `--set-fleet`, `--set-env` and `--non-interactive`, and refuse a missing `required_at_install` key (asking on a terminal) before anything is fetched into place, minted or signed; `update` asks only for keys the new schema added. `hv doctor` reports a value that breaks the schema as a warning that names the key and the rule, never the value. The config file is now written through a 0600 temp file. A module without `contract` behaves exactly as before; fleet keys are the existing owner-signed `x-<module>:` entries and `fleet-node` keys a naming convention over them, so no journal, projection or sync format changes.
- **3.1: runtimes, the unit PATH, the CLI launcher, `module run` and `module status`.** A contract-1 module's `runtimes` (program names, never paths) are resolved at `add`, `update` and `reapply` to directories only you or root can write, recorded in `.modules.json`, and become the `PATH` of its unit, so a service finds `claude` or `grok` without the login shell. A program that is not found warns and the install completes; `hive-mind module runtime <name> <program> <dir>` points at it. A module's `cli` is written as a small launcher beside `hive-mind`, rendered by the core with every word quoted, that unsets the owner's secrets and exports the module's environment; it refuses a name the core or another module uses, a file that is not the module's own, or a bin directory others can write, before anything is installed, and `remove` and `update` clean it up. `hive-mind module run <name> [--] <args>` runs the same command without the launcher, and `hive-mind module status <name> [--json]` prints the module's status envelope (`unknown` with the reason when it does not answer). A manifest without `contract` gets no `PATH` line, no launcher and no new state, exactly as before; no journal, projection or sync format changes.
- **Module doctor slot (3.1, #294 PR 4).** `hv doctor` runs a contract-1 module's own `doctor` (an argv, no shell; 20 s, 64 KiB, 100 results, 400 characters a string, narrow environment with `HIVE_DOCTOR_MODE`) for a module signed by its pinned publisher, merges the results into `modules:<name>` (a timeout, crash or malformed answer is a warn; a reported fail is a fail), caches them in `$HIVE_HOME/.module-doctor/<name>.json`, and also runs at the end of `module add`/`update` (`--require-healthy` exits 1 on a fail) and from the doctor timer (`HIVE_DOCTOR_MODE=timer`). A declared runtime missing from the module's PATH is a core warn. The fix step of `hv doctor --fix` never runs module code (its check pass does run the doctor).
- **3.1: `hive-mind module install`, the idempotent reconcile.** `hive-mind module install <name> [--from <repo>]` installs a module, updates it when the repository has a new commit, and does nothing when it is already there (no files rewritten, nothing signed); `--from` defaults to where it was installed from. It exits 0 converged, 1 refused with nothing changed, 2 usage, 3 waiting for the owner's admit (a device without the owner key stages the add and prints the owner's `group admit` line), 4 installed but the doctor reported `fail` (`--require-healthy`), 5 owner key locked. `--json` prints one result object and, like `--non-interactive`, never prompts: a sealed owner key that the unlock agent or the passphrase variable does not open is exit 5 with nothing written. `add` and `update` are unchanged; no journal, projection, signing or sync format changes.
- **3.1: module read routes and `reads`.** The module API gains seven read-only `GET` routes for a dashboard module: `/v1/overview`, `/v1/tags`, `/v1/related`, `/v1/audit`, `/v1/peers`, `/v1/verify` and `/v1/node`. A module is served one only if its signed manifest names it in `reads` (anything else is `403`, logged); `module add` and `update` list the declared routes before you confirm, marking those that carry tailnet addresses or node-local state, and record them in `.modules.json`. Each device has a read bucket of its own (`429` with `Retry-After`) that never touches the write quota; `related` and `audit` leave owner-forgotten facts out; `GET /v1/` gains a `reads` key only for a module that declares some. A manifest without `contract` is served exactly what it was. Provisional tier; see `docs/MODULE_API.md` and the threat model.
- **3.1: manifest `trust` field.** A contract-1 manifest may sign `"trust": "trusted"` or `"confined"` (absent means `trusted`, so hwatch, hdash and every existing module are unchanged). `module add` and `update` print the tier (`trusted` loudly), `module list` shows it, and `hive-mind module trust <name> [confined]` lowers it on one node; clearing that lowering, or an update that signs a higher tier than the node held, needs the owner key. Additive: no entry, projection or sync change. The confined unit hardening is not in this change, so `confined` does not isolate a module yet.
- **3.1: `hive-mind update` brings installed modules along.** Each module goes to the newest signed version at its recorded source that the new core admits (same tree check and pinned publisher as `module update`, only a strictly newer version, or a republish of the same version string); its files and units swap together. If the update fails but the installed version still admits the core, it keeps running with a loud warning; if no version admits the core, the module is disabled loudly (units stopped, hooks and command off, `hv doctor` `modules:<name>` `disabled-incompatible`) and `hive-mind module update <name>` brings it back. The core update always succeeds; a second run changes nothing. `hive-mind module refresh --check` shows the plan. No journal, signing or sync format change.
- `hive-mind owner unlock|lock|status` (#295, contract §12 PR 8): a per-user owner-unlock agent. One passphrase prompt per session; the agent holds the seed in memory only and signs just `admit` of a module device (named with `--module`), `revoke` of a module device it admitted that session, and `set-config` under `x-<module>:`; anything else falls back to the passphrase prompt. `module add|remove|quota` and `config set x-<module>:…` use it, a `config set` that changes nothing signs nothing, and a failed `module add` whose revoke cannot be signed now says the device is still admitted. No journal, signature or sync change; see THREAT_MODEL for the residuals and operator rule.
- Session telemetry leaves core for the hwatch module (#294 PR 9): `hwatch telemetry record|report|list` keeps the same local store (`$HIVE_HOME/.telemetry/telemetry.db`), and `hv telemetry` forwards to it through `hive-mind module run`, removed in 4.0. `record` (the session hooks, the Hermes plugin, the MCP tool) is silent and exits 0 when hwatch is not installed; `report` and `list` print the install line and exit 1. `hivemind/parts/16_telemetry.py` is gone; `/api/telemetry` still answers, now reading the store read-only. hwatch's manifest becomes contract 1, so it needs a 3.1 core.
- **The dashboard is the `hdash` module.** The page and `dashboard/` moved, unchanged, to [`projectmentor/hive-mind-dash`](https://github.com/projectmentor/hive-mind-dash) (#294 PR 10). The sync daemon no longer serves the page (it answers 404 for `/`, `/app.js` and the other assets) and keeps `/api/*` exactly as before. `hv dash [--print]` forwards to the module (`hive-mind module run hdash -- dash`) and, when it is not installed, prints `hive-mind module install hdash --from https://github.com/projectmentor/hive-mind-dash` and exits 1; the forwarder is removed in 4.0. The module serves the page on `127.0.0.1:9896` (config `port`).
- Signing goes through one seam, `hivemind/crypto/signer.py`: entry, owner-governance, Hive-Auth and hello signing call `Signer.sign(bytes)` instead of taking a raw seed, with one backend (today's key file). Behaviour-neutral: the same bytes are signed and the signatures are unchanged. `ownerkey.sign_governance`, `sync_common.signed_request_headers` and `sync_common.sign_hello` now take a signer. Module signing and capsule decryption are unchanged.
- Make `hivemind` and `hivemind.crypto` regular packages (`__init__.py`) so a same-named package on `sys.path` cannot shadow the signer seam import.
- `hv doctor rebuild` builds the store from the journal into a new file and swaps it in, whatever `schema_version` or table shapes the old `store.db` has, so a store a newer `hv` wrote (or a damaged one) recovers. Any other `hv` command now names a store written by a newer schema instead of the generic "store is busy" message, and `hv doctor` flags it under `database`.
- `hv doctor --boot` and `hive-doctor-boot.service` (#344): after a reboot the node waits (bounded) for the sync daemon, checks the platform (linger; on WSL the Windows logon task that starts the distro, which `hive-mind update` now installs), runs `--fix`, rechecks, and records one `boot` fact per boot saying what is up, what was fixed and what needs the operator.
- `hv wire` no longer passes a credential to a shell command line, and credential names are validated; `hive-mind module config` takes a secret value from stdin, a file or a prompt instead of argv, and masks it in `list`.
- The Claude Code integration installer (`integrations/claude-code/install.sh`, run by `hive-mind install`/`update`) now merges a marked, versioned auto-mode operator profile (`autoMode.environment`) into `~/.claude/settings.json`, so `--permission-mode auto` stops refusing the operator's routine watchers. It is idempotent, never touches user entries or an unparseable file, and uninstall removes only the marked lines (#343; seat profiles, the doctor drift check and the classifier smoke test remain).
- `hive-mind config set forget_writers legacy` now exits 1 when it refuses (it exited 0), and `hv entity add --attr k=v` (not JSON) is a usage error (exit 2) naming the JSON form instead of a traceback (#368).
- The S2 exec ban also catches the file-running APIs (`runpy`, `importlib` loaders, `imp`, `zipimport`, `marshal`, `ctypes`, `__import__` and the rest), with a planted probe per API; tests only, no behaviour change (#378).
- Tests: the signer-seam only-caller guard now follows names bound to the `ed25519` module or its `sign` attribute (aliases, `getattr`, walrus), with planted alias probes (#386).
- The `hv-move-gate` CI job and `scripts/common/hv_move_gate.py` are retired now the 3.1 split is done; docs and comments that cited `hv` line numbers or described `hv` as one file point at `hivemind/parts/` (#380).
- Document the S2 exec ban's limits in `docs/THREAT_MODEL.md`: what a static name list cannot catch, and that only a writer of signed core can plant it (#384); docs only.
- `hv module config set` never echoes the value (matches main, #399): it prints `set <key>` or `<key> is already set`; `owner unlock` names its passphrase variable as a literal. Clears CodeQL clear-text-logging alerts 14–18.
- Tests: three macOS-only test failures fixed (boot-unit uninstall tests now pose as Linux via a `uname` shim; owner-agent wrong-uid test tolerates EPIPE).
- **3.1: contract 3.1.** `CONTRACT_VERSION` is `3.1`, additive for the adapter surface: no verb, flag or output an adapter calls changes, so an adapter written for 3.0 keeps working. A module author gains manifest contract 1 (`cli`, `runtimes`, `config_schema`, `status`, `doctor`, `reads`, `ui`, `trust`), and the dashboard and session telemetry are now the `hdash` and `hwatch` modules. `docs/CONTRACT_HISTORY.md` has the entry.

## 3.0.1 — 2026-10-11 · `v3.0.1`

- Fix: `hive-mind migrate forget` now routes through the dispatcher (it printed the usage and exited), and the update-gate and `migrate forget` notices tell the owner `hv sync now` instead of `hive-mind sync`, which does not run (#370).
- Docs: `docs/AGENT_INTEGRATION.md` §7 puts the 2.0 amendment's four 1.x aliases in the past tense (3.0 removed them), `docs/CONTRACT.md` is titled for contract 3.0, and the 3.0.0 heading below is dated by its tag (#367).

## 3.0.0 — 2026-10-11 · `v3.0.0`

- Tests only (release 3.0 PR 1): the frozen 2.4 `_content_evidence` oracle (`tests/oracles/content_evidence_2_4.py`) and the forget corpus (`tests/forget_corpus.py`), with a test that the oracle equals the live function on every corpus journal under `forget_writers` absent, `legacy` and `owner`.
- Removed the retired 2.x exit-2 aliases (3.0, #151): `hv rebuild`, `hv merkle`, `hv key`, `hv doctor wire-agent`, `hv doctor migrate-identity` and `hv migrate-device-identity` are now unknown commands (argparse exit 2, nothing on stdout, nothing written) instead of pointers naming a replacement. `commandmap.RENAMED`, `renamed()` and `renamed_text()` are gone, and `hive-mind` no longer suggests a renamed `hv` command. Use `hv doctor rebuild`, `hv doctor merkle`, `hv config identity` and `hv wire claude`.
- Release 3.0 PR 2: `hive-mind migrate forget` re-issues, owner-signed and idempotently, every forget that only the pre-genesis grandfather keeps in effect, and `migrate forget --check` lists them (exit 0 only when none) without writing; `hv search`, `hv feed` and the session-start nudge print a one-line notice while a migration is owed. `forget-authz` is unchanged.
- Release 3.0 PR 3: `hive-mind update` runs the forget-migration gate as step 0 of the re-exec'd script, before any unit, restart, rebuild or wiring. An open pre-genesis grandfather is migrated on the owner's `y`; otherwise the update exits 1 and, when this update's own switch is identified, returns the tree to the pre-switch commit with `git reset --keep` (local edits kept), else leaves HEAD where it is. The refused tree is byte-identical, the daemon is not restarted, and there is no skip flag.
- **3.0: the pre-genesis forget grandfather is gone (#151, PR 4).** An unsigned owner forget positioned before the genesis owner no longer hides a fact, whatever `forget_writers` says, and `forget_writers=legacy` is refused (`owner` is still accepted, so `migrate forget` and old runbooks work). The pre-owner source-tag forget is unchanged. `hv doctor` `forget-authz` now fails only while the migration set (the facts the last 2.x hid by such a forget alone) is not empty, and passes on an empty set with the key unset, `legacy` or `owner`; `hive-mind update` step 0 refuses on the same set. `hive-mind unforget` accepts a fact in the set. THREAT_MODEL records the residuals (dangling late arrival, a plant on a closed hive, the update-gate windows) and that the re-exec'd process runs step 0 before its own fetch. Tests: the frozen 2.4 oracle differential (migrated equals the oracle, unmigrated differs by exactly the migration set, an arm-restored mutant fails), and the #341 fixes in `tests/test_update_gate.py`.
- Removed the exit-2 pointers for commands that moved to `hive-mind` in 2.0 (3.0, #151): `hv` now has a data-plane parser (`build_parser(plane="data")`) that does not define `owner init|export|import|…`, `group admit|revoke|deny|change|purge|retire`, `config set`, `admit`, `unforget`, `migrate forget`, `retract --owner` or `owner propose-election --mint`, so each is argparse's unknown command or unrecognized argument (exit 2, nothing on stdout, nothing written) and `hv` no longer names where it went. `hive-mind` routes them as before, with the full parser. `commandmap.MOVED` is now `CONTROL_PLANE` (a routing table), and `pointer_text`, `POINTER_EXIT` and the pointer handling in `hv.main` are gone. The two policy refusals (`capsule put|rotate|rm` under `capsule_putters=owner`, `wire --add` under `cell_writers=owner`) stay as policy messages that name the policy and the `hive-mind` form to run on the owner machine. Contract §7's 2.0 amendment is closed in `docs/AGENT_INTEGRATION.md`, `docs/HV_ARCHITECTURE.md` and `docs/CLI_REFERENCE.md`.
- **3.0: `entities` is keyed by the journal ref of the entry that created it (#151, PR 7).** The store's `entities` table gains `ref_node`/`ref_seq` (unique) and `name` loses its `UNIQUE`, the first step of splitting an entity's identity from its name. Behaviour is identical: every entry is still read by name, the first applied entry for a name creates the entity and its ref is the identity, and nothing new is written to the journal. A store without `meta.schema_version` 3 has `entities`, `entity_facts`, `links` and `journal_index` dropped once and is rebuilt from the journal by the next store command or `hv doctor rebuild`; a store already at version 3 is not touched. Tests: the entity corpus is byte-identical against a frozen 2.4 `persist_entity` (including a lower `node_id` arriving later), the identity equals `_index_lookup`, and the migration is a no-op the second time.
- Docs: `README.md` and `docs/WORKING_TOGETHER.md` now say agents, hive and devices instead of helpers, notebook and computers, matching the site (#339).
- Docs: the README says contract 2.4 for modules and lists `hive-mind group` and `hive-mind module` in the command table; `scripts/README.md` names `gen_namespaces.py`, the smoke helpers and the reset and invite steps.
- `hive-mind group admit` exits 1, with the message on stderr, when it refuses and writes no act: a purged device, an invalid module name, or no owner key on this device. It used to exit 0, so a caller that trusts the exit code recorded the refusal as done (#350).
- `hive-mind status` probes each peer's `/sync/hello` with a signed request, so a peer in sync read-auth `enforce` shows as reachable instead of "unreachable (HTTP Error 401)"; an unsigned 401 now reads "reachable, read-auth required" (#349).
- **3.0: an entity is its creating entry, and `hv entity` can say which one (#151, PR 8).** An `entity` entry may now carry `new_identity: true` (it creates an entity, whatever the name) or `identity_ref` (`[node_id, seq]` of the entry that created the entity it updates); an entry with neither, which is every one a 2.x node wrote, is read by name exactly as before. `hv entity add --name X` updates the one entity named X, creates it when there is none, and exits 1 listing the `h:` ids when two share the name; `--new` creates a second one of a taken name; `--entity ID` (an `h:` id or `node_id:seq`) names one entity for `add`, `show`, `link`, `join` (`--to-entity` for the second end) and `unjoin`; `entity list` and the confirmations show a repeated name with its id. MCP `hive_entity` gains an optional `entity`. Only an entity's creator, or an owner-signed write, rewrites it (a device's `identity_ref` write is weigh-only otherwise), a module may not create a second entity of a name it holds (`403 entity-name-taken`) or update one it did not create, and an update that names no entity, another name or another update is skipped. No wire, signing or manifest change: a 2.4 validator accepts the new fields (tested against a frozen copy of 2.4's) and a 2.4 node shows one entity per name. Operator rule: update every node before creating a second entity of a name. Residuals in `THREAT_MODEL.md`; the contract text is PR 10's.
- **3.0: the schema-3 migration drops, rebuilds and stamps `meta.schema_version` in one transaction (PR 7 follow-up).** A crash part-way through the migration can no longer leave a store with the tables dropped but the version unstamped, or stamped but not rebuilt; the next store command re-runs the whole migration.
- **3.0: entity surfaces and the store migration check (PR 9).** `hv doctor` gains `entity-identity` (`ok: N entities, M names shared by more than one`; it fails a store not at schema 3, an entity without an identity ref, or a legacy name group split across entities). The dashboard serves `/api/entities` (loopback-only) and shows an Entities panel, and the CLI and MCP `hive_entity` show a name's `h:` id only when more than one entity holds it. `hive-mind update` prints the `entity-identity` result after the rebuild and warns, never fails, when it is not ok. A 2.4 store is migrated once and a current one is left alone. No journal, wire, signing or manifest change.
- A module service unit is now ordered after `hive-sync.service` (`After=` only, no `Wants=` or `Requires=`), so a module that reads the hive at start finds sync up first; a node without hive-sync behaves as before. Existing units pick this up from the 15-minute `hv doctor --fix` timer, which re-renders them and restarts each module once, within about 15 minutes of a core update (#96 in the private tracker).
- `hv feed` now serves each node's chain only as the contiguous run of held seqs from `after[node] + 1`, so a sync that lands seq N+1 before N no longer lets a consumer's cursor skip N for good (#358). A missing seq withholds the higher seqs of that node only; `more` is true only when the limit stopped on an entry that was eligible to serve. Residual: if this node holds a higher seq and keeps refusing a lower one, the feed withholds the rest of that device's chain (fail closed). Only an admitted device can write such a seq. A cursor that already passed a hole stays past it. No contract, sync or signing change.
- `hive-mind group admit` now prints to stderr when it adds no sync target (no join-request URL, an unusable URL, or a write failure), with the reason and the `.peers.json` entry to add by hand; a duplicate stays quiet and the admit's exit code is unchanged.
- **3.0: contract 3.0.** `CONTRACT_VERSION` is `3.0`, a MAJOR for the adapter surface: the 2.0 exit-2 pointers and the 1.x aliases are gone, `forget_writers=legacy` and the pre-genesis honouring branch are removed (`hive-mind update` re-issues the forgets that depended on them, owner-signed, before the new code runs), and an entity is identified by its creating ref (`hv entity add --new`). No adapter calls a removed name; re-read, change nothing. **Operators: update the owner machine first;** `hive-mind update` may stop and say so. No signing, manifest or sync change: a mixed 2.x/3.0 fleet converges, `fleet-contract` lists 2.x peers as behind, and a module declaring `min_core: 2.x` still installs. A mixed fleet can disagree only on a repeated entity name, so update the fleet before creating a second same-named entity. `docs/CONTRACT_HISTORY.md` has the entry; THREAT_MODEL gains residual (e) (a revoked writer's pre-genesis forget can appear in the migration set).

## 2.4.1 — 2026-10-10 · `v2.4.1`

No contract change: `hv version` still reports 2.4, and nothing an adapter calls moves. **2.4.1 is the step every node takes before 3.0.** Run `hive-mind update` on each node; the updater's new pre-switch gate runs from the tree that is installed, so a node must be on 2.4.1 before it updates across a major.

- `hive-mind update` now refuses a switch to a higher contract major (2.x to 3.x) while `forget-authz` is open on an owned hive: it runs the installed tree's check before the merge or reset, prints the ACTION REQUIRED block and exits 1 with HEAD, the tree and the daemon untouched; run `hive-mind doctor --fix` first (#331, #332).
- Outbound `enforce`: a pull from a peer whose hello is not `verified` (`unsigned`, `unadmitted`, `addr-unproven`) is now sent with no `Hive-Auth-*` headers, and the dashboard's signed telemetry read and the daemon's per-node `/api/*?node=` proxy are not sent to an address that has not proved itself (redirects off) (#328, #330).
- `sign.yml`: the `test` job now checks out full history (`fetch-depth: 0`), so `gen_verify` can write the manifest `sequence` and main is re-signed again (#326, #327).

## 2.4 — 2026-10-09 · `v2.4.0`

**Upgrading from 2.3.** Run `hive-mind update` on each node. Nothing an adapter calls changes, so adapters keep
working, and a mixed 2.3 and 2.4 fleet converges. New for an adapter: `hv search --chain`, and the
`superseded_by_sid`, `superseded_by_ref`, `superseded_by_authority` and `supersede_evidence` fields on the search
surfaces (first bullet below). A node on 2.3 sends and reads neither. Several security bullets below change what the
projection honours (owner-signed acts, entry-type shapes, module writes, entity rewrites): after a rebuild, entries a
journal already holds in breach of those rules stop projecting, and `hv doctor` counts them; the journal is unchanged.

- **`hv search --chain`** (#157, #283). Follow one decision's supersede chain, one hop per line, to the decision that is still in effect. A superseded decision names the entry that replaced it by stable id (`superseded_by_sid`, `superseded_by_ref`) on `hv search`, `hv search --id`, the dashboard, and the MCP tools. It is an addition to the adapter surface, so the contract number is 2.4.
- **The sync client bounds what one peer can make a round spend.** A round with one peer now has a total deadline (`HIVE_SYNC_ROUND_DEADLINE`, default 240 s) instead of per-operation timeouts only, so a peer that drips a byte at a time (in the body, the headers or the status line) is cut off; a reply over a byte cap (`HIVE_SYNC_MAX_RESPONSE`, default 32 MiB) is refused; and a redirect is never followed, so the signed `Hive-Auth` headers are only ever sent to the address in `.peers.json`. A refused peer is reported on its own line and the round moves on to the next peer.
- **`hive-mind update` verifies the new code before it switches to it.** It fetches, checks out the commit it would move to in a scratch directory, and runs the installed `hv`'s signature check on it against the release key the installed tree pins (the fetched `hivemind.pub` is not trusted, and the fetched `hv` is never run). Only a tree whose manifest verifies under that key, and that ships that same key, replaces the branch; the new script is re-executed after that. A tree that is unsigned, modified, signed by another key, or ships a different key is refused with the reason, exit 1, and the branch and working tree are left exactly as they were. A commit still waiting for its release re-sign is waited for as before, then refused if it never arrives. `hive-mind update --allow-unsigned` installs it anyway, and says so. Nodes pick this up on the update after the one that installs it.
- **An owner-signed act counts only from a member device** (SECREV A3). The projection honours an owner-signed governance act, forget, hard link, capsule or cell only when the device carrying it is the genesis device or was admitted at or before that position and not since revoked or purged. A `claim-succession` does not admit its carrier: the successor's device must already be a member. Owner acts must now be made from an admitted device or the genesis device. `hv doctor` has a `succession` check that reports when succession acts arrived out of journal order; it changes nothing the projection honours.
- **`hive-mind update` refuses a fetched commit that is not a descendant of the installed one.** That covers a force-push back to an earlier, still validly signed commit, and a diverged rewrite; is refused with both shas, exit 1, and the branch and working tree are untouched. `hive-mind update --allow-rewind` installs it, for a history rewrite done on purpose; the signature check still applies. The fast-forward is unchanged. No manifest change. On its own this is not full rollback protection: an older signed tree committed as a descendant still installs. The signed `sequence` in the next bullet (#317) closes that case once a node has updated with it; see THREAT_MODEL, "Update rollback", for what remains.
- **A device's own revoke in the same ingest call is read before that device's later entries are judged** (#284, #285). Those facts are not stored. A revoke carried on another device's chain is read only if that chain is swept first; otherwise the facts are stored, and they do not project. Facts that were already stored stay in the journal and in `hv feed`, and they stay out of `hv search`.
- **Dashboard and loopback hardening.** The dashboard builds its page with the DOM API (text nodes, not markup) and runs no inline script, so its script and styles are now `app.js` and `app.css`, and the daemon sends `Content-Security-Policy: default-src 'self'` with the page. A request that arrives on loopback must carry a `Host` naming this listener (`localhost`, a loopback address or the bound address) or it is `421`. A POST to `/sync/ingest` is refused when the browser labels it cross-site (`Sec-Fetch-Site`, or an `Origin` that is not this listener), and one that arrives on loopback must also carry the `Hive-CSRF` token from the node's `.csrf-token` (or a valid signed envelope). `hv sync` sends the token itself; a script that POSTs to a loopback daemon reads it from `$HIVE_HOME/.csrf-token`, and a peer entry for a daemon under another `HIVE_HOME` on the same machine may name that file as `csrf_token_file`.
- **The sync daemon bounds what an unauthenticated or unadmitted peer can make it spend.** A request's headers and its body each have a wall-clock deadline (10 s and 60 s) that a slow trickle of bytes does not renew, and one source address may hold at most 16 connections (more are answered 503 and closed). A content entry from a device that is not admitted is refused before its signature is checked, so it costs no verification. A `Hive-Auth-Nonce` longer than 64 characters is refused before it is cached. A `join-request` or `announce` is capped at 2 KiB and must have the shape such an entry has (a `join-request`'s `device_id` is its signer; `label` is at most 80 printable characters; `url` is a short `http(s)` address), and `.peers.json` takes a join-request's `url` and `label` only when they pass the same bounds, so a bound-breaking entry already in a journal cannot reach it. `/sync/merkle-root` re-hashes the journal only when a journal file's mtime or size has changed. Nothing an adapter calls changes.
- **Ingest checks the envelope of an entry before its signature** (security). `node_id` is a non-empty string, `seq` an integer in `[1, 2**53)` and no further than 2^20 past the highest seq held for that device (plus what the batch carries of it), `type` a non-empty string, `payload` an object or null, `prev_hash`, `timestamp` and `sig` strings when present, and the governance and cell, comb and capsule payload fields that readers key on (`action`, `device_id`, `proposal_id`, `basis_ts`, `label`, `principal`, `module`, `name`, `version`) have their expected type. An entry that fails is refused whole. A local write that fails it is refused too, so the next seq is never minted over a skipped line. The journal reader applies the same check and skips a failing line, so a journal that already holds one reads again after the upgrade; `hv doctor` lists the files and `hv rebuild` prints the count. The type vocabulary stays open, so a newer node's entry types still land.
- docs: `THREAT_MODEL.md` gains a seat-steering section: what is gated (the `channel.<name>.authors` and `author_classes` gate, where an event is admitted by listed login or listed class and both unset admits nobody; fork heads are not followed, meaning no later head move and no checks read, while the first opened event from an admitted author is still yielded; untrusted bodies framed as data), the accepted 3.x residual (seats run as the operator's OS user and `gh` login), the operator rules, and the conditions that reopen it (hive-mind-private #44).
- sync_client: a per-request timeout clamped to the round deadline that fires just before the deadline watchdog now surfaces as the round-deadline error, not a raw `ReadTimeout` (#313).
- security: a revoked or purged device is no longer a listed peer (SECREV B6, hive-mind-private #54). The signed read envelope names no responder, so a device this node kept syncing with after its revoke held fresh signed reads it could replay to a third node. When a revoke or purge projects, `hv` now drops that device from `.peers.json` (an entry is matched by its device `id`; one labelled otherwise, as `group admit --principal` writes it, by the URL of the ended device's last join-request at or before its revoke or purge (a later one moves nothing, and neither does one this node received after the act's stamp, by `.arrivals.jsonl`) or the one device `.peer_candidates.json` saw at its address, unless an admitted device was seen at or advertised that host (a join-request from a device that is not admitted keeps nothing); an entry whose `id` names a live device is never dropped), and `hv sync now` and the doctor peer probes send it nothing. An entry set by hand that matches no ended device by id, join-request URL or sighting is kept; list peers by `k1:…` id, as also for a peer an admitted device later re-points with a different join-request URL or shares the host of (accepted for 3.x), as also for clock skew between this node's receipt clock and the act's stamp and for entries that arrived before arrival records existed. Local only: no signed byte or sync wire format changes. Re-admit the device and re-add the peer to restore it. THREAT_MODEL states what remains: an admitted peer you still list can replay your signed reads to a third node.
- **`hive-mind update` refuses a rollback to an older signed tree.** sign.yml now signs a `sequence` (`git rev-list --count HEAD` of the commit it signs) into `verify.json`, and the updater refuses a verified commit whose `sequence` is lower than the installed manifest's, naming both numbers, unless `--allow-rewind` is passed. This closes the case #307 left open, an older signed tree committed as a descendant of the installed one. An equal `sequence` (a re-sign) installs; an installed manifest without the field counts as 0, so a node starts enforcing after its first update with this script; old nodes ignore the field.
- **A capsule, cell or comb body only lands under its own type** (SECREV B1). The owner signature does not cover the entry type, so an owner-signed body could be re-appended under another one. Each type now has a shape only it carries (capsule: `alg` and `wraps`; cell: `kind` `tool` or `agent`; comb: a `cells` list), checked at ingest, on a local write and in the reader; a mismatch is refused, or skipped and counted in `skipped_lines`. The signed bytes are unchanged. A cell without a `kind` is no longer accepted by `hv wire --add`.
- security: the module write policy is now enforced by the projection, not only by `POST /v1/entries` (hive-mind-private #50). An entry carried by a device admitted with `admit --module` projects only if the module API gate would have accepted it: no `retract`, no `governance`, no `manual`- or `owner`-source fact, no foreign `x-` name, no legacy reference field, and the rest of the gate's payload rules. The API and the projection read the same rule table (`vocabulary.MODULE_ENTRY_TYPES`, `check_module_name`, `REF_FIELDS`) through the same functions (`hv _module_policy_problem`), so they cannot drift. **Upgrade effect:** facts, retracts and other entries a module key already landed in breach of the policy (for example by pushing through `/sync/ingest`) stop projecting after the upgrade; they stay in the journal. `hv doctor` counts them (`module-policy`).
- **Security: an entity is rewritten only by its creator or the owner.** The projection now applies to an `entity` write by name the rule it applies to a link: the device that created the name, or an owner-signed write, replaces the entity; any other admitted device's write is weigh-only and no longer replaces it (SECREV B3, closing the residual #208 left for non-module devices). A module device is refused as before. **Existing journals:** a rewrite by a non-creator already on disk stops winning after the upgrade; the entry stays in the journal, and `hv doctor` counts them (`entity-rewrite`). `hv entity add` on a name another device created journals the write and reports that it does not replace the entity. No signing, manifest, or sync wire-format change.
- security: the release workflow is split so the test suite never runs with a signing secret in scope (hive-mind-private #56). `sign.yml` now has a `test` job (the full suite, no `secrets.*`, read-only permissions) and a `sign` job (`needs: test`, `environment: signing`) that regenerates and signs the manifest and pushes with the App token. `tests/test_workflow_secrets.py` fails if any job that runs pytest references `secrets.`. No secret is renamed; `HIVE_SIGNING_KEY` stays a repository secret (residual in `docs/THREAT_MODEL.md`).
- tests: each guard from the SECREV B6 change (#314) now has a test that fails when it is removed: the `_sync_with_peer` skip, the `rebuild_db` ended-peer prune, the `_probe_peer_map` filter, and the `- admitted` subtraction in `_ended_devices` (#319). No behaviour change.

## 2.3 — 2026-10-07 · `v2.3.0`

**Upgrading from 2.2.** Run `hive-mind update` on each node. Nothing an adapter calls changes, so adapters keep
working, and a mixed 2.2 and 2.3 fleet converges. A node on 2.2 sends no `node_id` or `node_devices` from `GET /v1/`, and
a module reads an absent `node_devices` as unknown. The new non-owner install changes no governance entry: the owner
admits the device with the `group admit --module` line it prints, as before.

- **Added: `GET /v1/` reports `node_id` and `node_devices`** (hwatch C1, M3b, #267, #270). `node_id` is this node's own device id
  and `node_devices` the number of node devices in the hive (the admitted devices and the genesis device, not revoked, not purged, not a module device). Two read-only
  fields, a string and an integer: no device list, address or principal, and no new route. A module can tell a one-node
  hive from a fleet; it reads an absent `node_devices` as unknown on a node without this.
- **Added: install a module on a device without the owner key** (hwatch C6, M1b, #268, #272). `hive-mind module add <name> --from
  <repo>` there stages the verified tree, mints the module's key and prints the owner's `group admit <device> --module
  <name> --principal <p>` line with the publisher fingerprint and the verified commit, and installs nothing. A second
  `add` after the owner's admit has synced installs the staged tree; `add --abort <name>` drops it. `module update`
  no longer needs the owner key (same checks, no membership change; only the owner's `quota` raises a limit above the defaults), and `module remove` there deletes the
  tree and key and prints the owner's `group revoke` line (the device stays admitted until then). `quota` stays
  owner-only. No governance route or entry changes.
- **Added: `service.stop_grace` in a module manifest** (#273, #274). Seconds, 1 to 3600; it renders `TimeoutStopSec`
  and `KillMode=mixed` for a daemon or timer unit, so a long one-shot can drain on stop. Without it nothing changes.
- **Added: `hive-mind module config <name> set|unset|list`** (hwatch C3, #275, #277). Edits the module's per-node
  config file: local, never journaled, no owner key, written atomically with mode 0600. `update` keeps what you set.
- **Added: `hive-mind group retire` accepts a revoked former member** (#271, #278), with `--confirm`: the retire brings
  back the prefix the signed head names. An id that was only revoked or denied, never a member, is refused as before.
- **Fixed: a stop, disable or restart waits out a `stop_grace` drain** (#276, #279). The `systemctl` calls wait the
  unit's `TimeoutStopSec` plus 30 s; `module remove` deletes nothing while the unit is still draining, and a restart that
  timed out says so instead of reporting that the unit would not start.

## 2.2 — 2026-10-07 · `v2.2.0`

**Upgrading from 2.1.** Run `hive-mind update` on each node. Nothing an adapter calls changes, so adapters keep
working. A mixed 2.1 and 2.2 fleet converges. One effect to expect on the first rebuild (#246): a revoked or purged
device's past content leaves `hv search`, as the next bullet says (a retired device's signed prefix stays).

- **A revoked or purged device's past content leaves `hv search`** (#246, closing #230 and #250). The store now
  projects a device's facts, decisions and ideas only while the final projection lists it as admitted and not purged.
  On rebuild, the content of a revoked or purged device drops out of `hv search` and the dashboard. It stays in the
  journal and in `hv feed`. A later admit restores a revoked device's rows; a purge is final. A plain purge drops all of it; a retire
  (next bullet) keeps the prefix its signed head names. Exempt: an entry that verifies as the owner; the genesis
  device until its revoke or purge; and content positioned before the genesis owner stays only for a device with no honoured revoke and no purge.
- **Added: `hive-mind group retire <device>`** (#260). The owner chooses, per device, whether a retired device's past
  content still counts. `purge` stays the compromise tombstone and drops all of it; `retire` is the same signed `purge`
  carrying `keep_through` (a seq) and `keep_hash` (the hash of the entry at that seq), and the chain that entry names
  keeps counting, with its corroboration weight, while later seqs do not. A node that does not know the fields reads it
  as a plain purge. Ingest stores an entry up to `keep_through` from a purged device in any arrival order. The device
  still cannot be re-admitted; `revoke` is unchanged. Retiring an already-purged device needs `--confirm`.
- **Owner-signed governance beats a device-stamped entry, and ingest refuses nothing for a timestamp** (#246). The
  timestamp bounds apply when the store is built, not when an entry arrives, so no entry is lost from a journal for
  its stamp. `docs/CONTRACT.md` states both in its guarantees.
- **`hv search --id SID|REF`** (#158, #249): look one entry up by its `sid` or `ref`. It exits 1 with nothing on stdout
  when the id names nothing. MCP `hive_lookup` and the dashboard search box take an id too.
- **A failing journal lock stops the write with a clear error** (#253, #254). `hv doctor` gains a `journal-lock` check.
- **Concurrent local writers mint distinct seqs and project each entry once** (#215, #252).
- **Fixed: `hive-mind update --help` ran the update** (#224, #244). `install`, `update`, `status` and `invite` now print
  usage and exit 0 on `-h` / `--help` without changing anything, and refuse an unknown argument with exit 2.
- **Fixed: a peer sighting that names no `via` keeps the recorded one** (#146, #261).
- **Fixed: a non-object module record in `.modules.json` reads as absent** in `limits_for` (#227, #247).
- **Fixed: the dashboard no longer suggests a nonexistent `hive-mind verify`**; it says `hv verify` (#193, #245).
- **Tests only:** the suite clears an exported `HIVE_KEY_DIR` (#178, #256) and never reads the repo-root `.peers.json`
  (#142, #257), a member device's retract is pinned never to become an owner act at genesis (#148, #259), and off
  Linux the core hook output still passes through while the module hook does not run (#241, via #262), and a
  retire's cutoff is pinned in the raw evidence, at `keep_through + 1` on ingest, against a head naming a higher-seq
  body, and for a prefix arriving after a plain purge (#266, #269).

## 2.1 — 2026-10-06 · `v2.1.0`

**Upgrading from 2.0.** Run `hive-mind update` on each node. Nothing an adapter calls changes, so adapters keep
working. A mixed 2.0 and 2.1 fleet converges; the one skew is in `docs/CONTRACT.md`, under *The guarantees*.

- **The module API, `/v1`** (plan PRs 4 and 5). A loopback-only listener for modules, separate processes with their own device key. Every request is signed
  and an unsigned one is always `401`. Routes: `GET /v1/`, `/v1/feed`, `/v1/search`, `/v1/item`, `/v1/entity`,
  `/v1/tip`, and `POST /v1/entries` for an entry the module signed itself. Per-module quotas (60 an hour, 500 a day,
  16 KiB an entry, 50,000 for life; the owner raises them). No governance route. `docs/MODULE_API.md` is the
  reference and `docs/CONTRACT.md` the stability promise.
- **`hv feed`** (PR 1): journal entries past a per-node cursor, as JSON. A `fact` entry carries `forgotten` and an owner
  `retract` carries `affects`, both computed by the core, so a consumer never reimplements the forget rule.
- **`hive-mind module add|remove|update|list|quota`** (PR 6): a module is a git repository with a manifest signed
  by its publisher key, pinned on first use. It installs outside the checkout, and `remove` revokes its device and
  keeps its entries. Linux only; elsewhere `add` refuses before it touches anything.
- **Module units** (PR 7): a manifest `service` block becomes `hive-module-<name>.service` (and a timer), and
  `hive-mind update` runs `hive-mind module reapply` to re-render them, restarting only the units that changed.
- **`hv doctor` checks each module** (PR 9): `modules:<name>` and `modules-contract`. `hive-mind doctor --fix`
  re-renders a unit and starts one that failed, and leaves a unit the operator stopped alone (#232). It only enables
  a unit that is running but not enabled, and with no user systemd manager it touches no unit and says so (#234).
  Plain `hv doctor` now warns "active but not enabled" for such a unit (#237).
- **Module entities and `same-as`** (#208). A module writes only `x-<module>:` entities and links only its own. The
  core joins one to a shared entity with `hv entity join`, and `unjoin` withdraws only the joins this device wrote
  (`--owner` withdraws any). `hv entity show` lists the joined entities (`--no-joins` hides them).
- **Bounded entry timestamps** (#217). After the owner runs `hive-mind owner freeze-timestamps`, every node skips an
  entry stamped more than 5 minutes before its device's latest earlier entry, or before its first admit. `hv`
  clamps its own entries to the latest it holds. `hv doctor` and `hv audit` report `ts-bounds`, `future-dated` and `flood`.
- **Module devices do not vote.** The owner's `admit --module` marks a device, and the election walk skips it. A 2.0
  node still counts it, which matters only with `quorum_m > 0` and `quorum_by=device`.
- **A prefixed config key `x-<module>:<key>` is accepted** by `set-config` and projected as a string; a bare unknown
  key is still refused.
- **Module hooks, and the `Notification` and `Stop` events.** After the core behaviours for an event, the dispatcher runs
  each installed module's `hooks/<event>`: payload on stdin, output discarded, 3 seconds per hook and a 6-second event
  budget (clamped to the shim's timeout), the process group reaped after each hook. `hv wire claude`, the `agent-hooks`
  check and the doctor timer add the two new shims to a node that has the four older ones.
- **`hv doctor` checks a module's hook files** (PR 9d, #237). `modules:<name>` inspects every file under `hooks/`. An
  undeclared `hooks/*` file (one the manifest's `hooks` list omits) is refused at `module add` and failed by the doctor.
  The doctor warns, naming the reason, on a hook for an event the dispatcher does not know (it never runs) and on one
  the dispatcher would skip (not a regular file, not executable, not owned by this user, writable by group or other),
  and on a linked `hooks/`.

## 2.0.3 — 2026-10-05 · `v2.0.3`

No contract change.

- **`hv doctor` and `hv audit` no longer raise on a malformed ref or content in a payload** (#207). The pure functions
  behind them (`_links_unauthorized`, `_signer_reliability`, `_forgets_grandfathered`, `_compute_audit`) judged a ref
  by its length alone and used it as a key, so a ref with a list or dict inside it raised `TypeError` exactly when
  a bad entry was in the journal. Every read path now uses `_valid_ref`, and the audit counts only string content,
  as the projection does.

- **The ingest quarantine is bounded and admitted-only** (#205, #216). `.quarantine.jsonl` holds the entries ingest
  refused for a hostile payload. An entry from a signer this node does not admit (or has purged) is refused as before
  and not quarantined; a hive with no owner yet still quarantines. An entry up to 64 KB of canonical bytes is kept
  verbatim, a larger one as its hash, size and first 4 KB. The file keeps the newest 200 records within 16 MB.
  A refusal appends one line and reads only a small index, `.quarantine.idx`; the file is rewritten only when a
  cap is crossed.

- **The legacy `supersedes_ref`, `supersedes` and `resolves_ref` payload fields now go through the link authority**
  (#204, security fix). They projected for any admitted device, so one device could mark another's decision
  superseded on every node. They now command only when the owner key signed the entry or its signer wrote the
  target, as a `link` entry does; `resolves_ref` must name a fact. Signed self-authored and owner-signed history
  projects as before. An unsigned legacy field commands only while the journal has no owner; once an owner exists
  it is evidence, and a matching `node_id` is not a signer. `hv doctor` `link-authz` lists a legacy field that no
  longer commands. A `link` entry is the only way to supersede or resolve (`AGENT_INTEGRATION.md` §7).
  **Upgrade effect:** a device-signed legacy supersede or resolve of another author's entry stops commanding on
  upgrade, and the target stands again on every node until the owner re-ratifies it with an owner-signed `link`.
  On the live hive this is the four `decide --revoke` entries of 2026-08-19; `hv doctor` `link-authz` lists them.
  An unsigned self-authored legacy field likewise stops commanding once any owner exists. The live hive has none:
  its legacy fields are device-signed, and its unsigned entries carry no legacy field.
- **`rebuild_db` is atomic** (#206). It committed the deletes before replaying the journal and never closed its
  connection on error, so a failure left the node's projection empty, search returning nothing, and a write lock
  held. It now runs in one transaction (`BEGIN IMMEDIATE` to the final insert, no commit between), rolls back on any
  exception so the previous projection stays queryable, and closes the connection in a `finally`. `_init_fts` runs
  its statements one at a time, because `executescript` commits.
- **`ed25519.verify` enforces RFC 8032's canonical-encoding checks** (#213, security fix). It rejects a signature
  whose `S` is `l` or more (§5.1.7), and an `R` or public key whose `y` is `q` or more or whose `x` is 0 with the
  sign bit set (§5.1.3). It had skipped them on purpose, to match the reference it replaced, so `S + k*l`
  verified for every `k` that fits in 32 bytes. Anyone who had seen a signed entry could re-encode its `sig`
  without the key; ingest keeps the first copy of a `(node_id, seq)` and `sig` is inside the entry hash and the
  Merkle chunk hashes, so a node fed the malleated copy first held different bytes from the fleet for good. No
  forgery was possible. The cofactorless equation is unchanged, and `sign` is byte-identical. The live journals
  hold no such encoding, so tightening rejects nothing already held. A node still on v2.0.2 accepts the
  malleated copies, so update every node. No adapter-visible change: no verb, flag or output moves, so this is
  not a contract bump (`AGENT_INTEGRATION.md` §7).
- **`api_search` `kind` is exclusive** (#209). `kind=idea` also returned every live fact and decision (the
  fact and decision branches ran for any kind but their own opposite); the dashboard's `/api/search` and any caller of `api_search`
  inherited it. `fact`, `decision` and `idea` now return only that type, and `all` returns the three together.
  `kind` outside those four answers 400 on `/api/search`, as the CLI's `--kind` choices refuse it. `min_confidence`
  filters facts everywhere, and earned ideas under `kind=all` on both surfaces (raw ideas stay hidden under `all`).
  Under `kind=idea` raw ideas, which sit at 0.0 by design, come back whatever their confidence (decision by David,
  `h:0167a9c01a`). Decisions have no confidence filter. `hv search` already behaved this way.

## 2.0.2 — 2026-10-03 · `v2.0.2`

No contract change.

- **`rebuild_db` no longer raises on an `entity_fact`, `supersedes`, `resolves_ref` or `link` whose ref or local id is
  the wrong kind, absent or malformed** (#196, security fix). An `entity_fact` whose `fact_ref` named an entity,
  whose `entity_ref` named a fact, or whose legacy `entity_id` / `fact_id` named no row made the rebuild fail with
  `IntegrityError`. A ref that is not `[str, int]`, or an integer outside SQLite's 64-bit range (a ref's seq, a
  legacy `entity_id` / `fact_id` / `supersedes`), made it fail with `OverflowError` or `ProgrammingError`. Content of
  these types is accepted from any admitted device and the journal is permanent, so one such entry stopped every
  node's rebuild. The entry now lands and projects to nothing, as a dangling link does. A `supersedes` is held to
  the same rule: a `supersedes_ref` to a non-decision, or a `supersedes` that is not a decision row, marks nothing.
  The link-evidence passes skip a malformed ref instead of raising `TypeError`. Entries that resolve are projected
  as before.

## 2.0.1 — 2026-10-02 · `v2.0.1`

No contract change.

- **`hv verify` now exits non-zero when the install is not verified** (#190). `0` verified; `1` modified,
  signature invalid, fork key or no manifest; `3` could not fully check (anchor unreachable, unsigned build).
  Before, it exited 0 whatever it printed. `hv doctor` is unchanged and advisory. The printed lines are unchanged, and the MCP
  `hive_verify` tool still returns the verdict text for every exit code.

## 2.0 — 2026-10-02 · `v2.0.0`

**Upgrading from 1.x.** Run `hive-mind update` on each node. There is no journal or wire change, so a mixed
1.x and 2.0 fleet converges while you do.
- **Agents re-integrate** (the §0 check fires on the major): local ids are refused, `tags` is a JSON list,
  and every write passes `--source`. `docs/AGENT_INTEGRATION.md` §7 has the details.
- **Owner and operator commands run as `hive-mind`.** Run on `hv`, each names its `hive-mind` form and exits
  2, acting on nothing. So do the removed aliases, which name their `hv` replacements.
- **Keys leave the checkout.** `hv doctor --fix` moves the device key, and `hive-mind doctor --fix` the owner
  key. A plaintext owner key still works; `hive-mind owner seal` seals it, and `hv doctor` fails until then.
- **An owned hive whose `forget_writers` is still open fails `forget-authz`.** The 15-minute timer's
  `hv doctor` alerts, and `hive-mind update` ends with ACTION REQUIRED, until the owner runs
  `hive-mind doctor --fix` once. Nothing a hive forgot comes back.
- **`fleet-contract` lists every 1.x peer as behind** on a 2.0 node. That is intended: upgrade it.
- **A build without its bundled crypto refuses to run.**

- **PR 2b, the split: `hv` cannot owner-sign.** `hv` is the agent data plane and `hive-mind` the
  owner/operator control plane. Every code path that reads the owner seed, writes owner-key material or
  produces an owner signature now lives on the control plane (`hivemind_ctl.py`, `hivemind_owner.py`), and
  `hv` reaches none of it. Two static tests hold that true: `hv`'s import graph never reaches `ownerkey` or
  the control plane, and no `owner_sig` is produced anywhere `hv` can reach. The second one catches an
  inline signer, which imports nothing. Each check is shown failing on mutants in the suite.
- **Moved commands point, exit 2, and act on nothing.** These moved: `hv owner` (init, export, import,
  standby, escrow, restore, nominate, unnominate, claim, transfer, revoke-escrow, heartbeat, pin), `hv admit`,
  `hv group admit|revoke|deny|change|purge`, `hv config set` (with its `confidence set` and `quorum set` forms),
  `hv unforget` and `hv retract --owner`. Each now prints the exact `hive-mind` command to run, this
  invocation's arguments included, and exits 2 (contract §7's 2.0 amendment). `revoke-escrow` becomes
  `hive-mind owner revoke` (S5), and the three `config … set` forms collapse into `hive-mind config set`.
- **What stays on `hv`:**
  - the reads, and the device-signed dead-man recovery: `owner show`, `owner elections`,
    `owner propose-election --pub` and `owner vote`. A member node that has only `hv` can still elect a
    new owner.
  - `hv owner propose-election --mint` points at the new `hive-mind owner mint`, which no longer
    overwrites a key already on the device without `--force`.
- **Owner-signed links come from the control plane** (decision `h:34cc1dbcd3`). Through `hv`, every link is
  device-signed, including source `manual` on the owner device. The same verb through `hive-mind remember`,
  `decide` or `entity` owner-signs its links, when the source is `manual` (#114). Using owner authority is an
  explicit act: typing `hive-mind`.
- **Owner-policy content writes.** Under `capsule_putters=owner` or `cell_writers=owner`, `hv capsule
  put|rotate|rm` and `hv wire --add` point at `hive-mind`. Under `fertile` they run on `hv` as before,
  device-signed.
- **`doctor --fix` is split by what it touches** (5848736351).
  - `hv doctor --fix`, which the 15-minute timer runs, keeps every data-plane repair: the device key's
    permissions, orphan daemons, restarts, the key announce, the skill relink and the peer-address repoint.
  - The owner key's permissions and the genesis pin are operator state, so they move to
    `hive-mind doctor --fix`. `hv doctor --fix` says when either is needed.
  - `hive-mind update` and the installer now pin through the control plane.
- **Key presence without reading the seed.** `hv whoami`, `hv owner show`, `hv doctor` and the admission hint
  decide whether this device holds the owner key from the key file's metadata and a public sidecar,
  `owner-pub`, which the control plane writes. They never read the seed. They can say *unknown*: permission
  denied is not "absent".
- **No journal or wire change** (S7). A mixed 1.x and 2.0 fleet converges.
- **PR 3a: private keys leave the working tree** (private #27). `HIVE_HOME` is the git checkout, which
  every agent CLI runs in and some index, so a 0600 seed there was one `cat` away from any tool running
  as the user.
  - The seeds now live in a key directory (0700): `$HIVE_KEY_DIR`, else the path recorded in
    `$HIVE_HOME/.key-dir`, else `~/.hive/keys/<sha256 of the checkout's path, 16 hex>`. The files are
    `device-key`, `owner-key` (0600) and `owner-pub` (0644). The pointer keeps a renamed checkout on its
    keys.
  - Keys at the old root paths keep working, with a `keyperm` warning. Each plane's `doctor --fix` moves
    its own: `hv` the device key, `hive-mind` the owner key and its public half. A move never overwrites
    a key already in the key directory, and finishes one that was interrupted after the copy.
  - `keyperm` fails on a key directory that is not 0700.
  - The installer's identity stash saves from and restores into the key directory, and the uninstaller
    removes only the three key files there.
  - `hv whoami`, the doctor `owner` check and the dashboard label the device and owner ids as public ids
    and say where the private keys are, without printing them.
  - Presence (`_owner_key_state`) now answers *held* only for a regular file of a seed's size, so a
    directory or an empty file in the key's place reads as *present*, not held (#159 review).
  - The signed manifest names its one extensionless file, `hv`. A test fails if another runnable
    extensionless file would ship unsigned.
- **PR 3b: the owner key is sealed at rest** (private #27). A 0600 file outside the checkout is still
  readable by every process running as the owner's user, the agents included.
  - Every new owner key (`owner init`, `mint`, `import`, `restore`, `claim`) is written only as
    `owner-key.sealed`: the envelope `owner escrow` already uses, scrypt then ChaCha20-Poly1305, written at
    0600 atomically. The seal is opened once before any plaintext copy is removed.
  - `hive-mind` unlocks it **once per command** (h:af5ecf48c5), from the tty with three tries, or from
    `$HIVE_OWNER_KEY_PASSPHRASE` with one. A cancel or a wrong passphrase exits 1 having signed nothing.
    That variable is separate from `$HIVE_OWNER_PASSPHRASE`, which still encrypts an export or an escrow.
  - `hive-mind owner seal` converts a plaintext key in place: same owner id, no journal change. It
    refuses when two different keys are on the device. `hv owner seal` points at it.
  - Doctor's new `owner-seal` check **fails** while a plaintext owner key exists (the key directory's or
    the legacy root's), and names the fix.
  - `hv` never opens either form: presence is still a `stat`, of `owner-key.sealed` first. A test asserts
    `hv` calls neither the opener nor the sealed-key reader.
  - The identity stash, the keep-hive backup, restore and uninstall carry `.owner-key.sealed`. A stash
    holding the sealed form drops its plaintext copy.
  - The installer asks for the new passphrase once, at bootstrap, for `owner init` and the self-admit.
- **PR 4a: the agent surface.** The adapter-visible breaks contract §7 promised for the next MAJOR.
  - **Local ids are refused** (#59, #64). A bare or kind-prefixed rowid (`118`, `d17`, `i5`) on any flag that
    takes a reference (`remember --resolves/--outcome-of/--supports/--contradicts/--extends`,
    `decide --supersedes/--revoke/--informed`, `retract`, `entity link --fact-id`, `hive-mind unforget`,
    `hive-mind retract --owner`, and the MCP and Hermes inputs behind them) exits 1 with
    `'118' is a local id, which 2.0 no longer accepts: … Pass the sid (h:…) or ref (node_id:seq) that
    hv search shows.`, having written nothing. `--resolves` aborts too, where an unresolvable target
    is still only a warning. MCP `hive_entity`'s `fact_id` is a `str`. Journal reads are unchanged: the
    legacy resolvers still read every historical entry.
  - **`tags` is a JSON list** in `hv search --format json` (#77), as it already was on every `/api/*` row.
    `tag_list` stays, the same list. The Hermes prefetch joins it.
  - **No `$HERMES_AGENT` source fallback** (#119). A write's source is `--source`, else `manual`. The
    Hermes adapter now passes `--source` on `decide`, as it already did on `remember` and `propose`;
    without it every Hermes decision would have read as `manual`, which means a person.
- **The core vocabulary is registered** (#136, #150). `vocabulary.py` lists every bare name core writes or
  reads, in ten categories: entry types, link kinds, governance actions, `set-config` keys, channels,
  behaviour tags, announce kinds, source apps, source context classes and envelope fields. Each name has a
  status (`written`, `legacy`, `read`, or `reserved` for four envelope fields held for the module API), the
  contract version that introduced it, and one line of meaning.
  - [`docs/NAMESPACES.md`](docs/NAMESPACES.md) is generated from it by `scripts/common/gen_namespaces.py`, and
    states the rule: core reserves every bare name, and a module's names take a prefix, `x-<module>:<name>`
    (decision `h:af137f9421`), which the 2.1 module API enforces. A test fails when the page and the generator
    differ.
  - `tests/test_vocabulary.py` holds the registry to the code both ways, by AST at enumerated writer and
    reader sites. A name written or read there that is not registered fails, and so does a registered name
    that nothing writes or reads. Each category has a mutant in the suite.
  - No behaviour change. `hv`'s `_CHANNELS` and `_LINK_EVIDENCE_KINDS` now come from the registry, with the
    same values. No journal or wire change.
- **PR 4b: removals** (from this list's "2.0 removals and changes"). No journal read path changes.
  - **The `sync_daemon.py` shim is gone.** `hive-mind update` repoints an `@reboot` cron fallback that still
    names it, since nothing rewrote that line before.
  - **`hv doctor migrate-identity`** (the one-time 1.3 re-keying, #130) and its `hv migrate-device-identity`
    alias are gone. Both say to run it on a 1.x release first, and exit 2. **`utilities/migrate_journal.py`**
    goes too, with `scripts/common/deploy_node.sh`, its only caller, which had been broken since the scripts
    reorg.
  - **Internal shims** `_is_salient` and `_wire_claude_hooks` are gone. The `trust_score` column is no longer
    written; a new store no longer has it. The pre-1.12 direct-hook names are no longer patterns of their own.
  - **A build missing its bundled crypto refuses to run** (`ed25519`, `x25519` or `chacha20poly1305`), at
    import, so the CLI, the control plane and the sync daemon all stop; through 1.x only `hv doctor` failed.
  - **`fleet-contract`** warns below the current MAJOR, and never below 1.19 (where `link` entries became
    honoured).
  - `smoke.sh`'s entity check expects a `link` entry, as written since 1.19. `crontab` is stubbed in tests.
  - **The 1.x aliases point, exit 2, and act on nothing** (decision `h:af137f9421`). `hv rebuild`, `hv merkle`,
    `hv key` and `hv doctor wire-agent` each print the `hv` command that replaced them, this invocation's
    arguments included (`hv doctor rebuild`, `hv doctor merkle`, `hv config identity …`, `hv wire claude`), and
    exit 2, the same shape as a moved command. They are kept through 2.x and deleted at 3.0. Their table is
    `commandmap.RENAMED`, beside `MOVED`. `hive-mind` suggests the new name too. The installer, the smokes and CI
    call the new names; a test fails if shipped shell or a workflow calls an old one.
- **4c: the pre-genesis forget grandfather is closed by the owner, not by a default flip** (#135 part 2;
  decisions `h:af137f9421`, `h:696638b9b7`).
  - **Nothing reappears.** An unset `forget_writers` still projects as `legacy`. A default that meant `owner`
    only when nothing depends on the grandfather would project the same forgotten set in every case, because
    the two policies disagree exactly on the facts `_forgets_grandfathered` lists, and it would not close
    #122 either. So the projection does not change, and a mixed 1.x/2.0 fleet agrees by construction.
  - **`hv doctor` fails `forget-authz` on an owned hive whose policy is still open**, whether or not a fact
    depends on it. Each dependent fact is listed by `h:` id, the form both remedies accept. A closed hive
    reports `ok`, and a hive with no owner reports nothing.
  - **`hive-mind doctor --fix` closes it.** With nothing depending, it closes at once through the #122 guard.
    Otherwise it lists each dependent fact with its text and asks y/N at a terminal, default N, before the
    owner key is unlocked. `y` runs 1.28's `owner init` routine with its own reason: every dependent forget
    is re-issued owner-signed, then `forget_writers=owner` is set. `N`, a piped answer or no terminal writes
    nothing. `hv doctor --fix` (the 15-minute timer) cannot owner-sign, so it only points there.
  - **`hive-mind update` ends with ACTION REQUIRED** on an owned open hive, after the restart, the rebuild
    and the re-wire: the dependent facts and the one command. It exits non-zero, and prints the note on every
    update until the hive is closed. A closed or unowned hive ends as before.
- **4d (docs): the architecture page describes the two planes.** `docs/HV_ARCHITECTURE.md` is rewritten for
  the split. It covers what each file holds and on which plane, how `hive-mind` installs its owner steps
  into the library, the pointer tables, what stays on `hv` and why, where the keys live, and the tests that
  hold S2. `docs/P2P_DESIGN.md` moves to `docs/history/`, and `INTERNALS.md` no longer calls it the full
  design. `ownerkey.py`'s docstring no longer says `hv` imports it.
- **#150 finished: what a module may add, and the local files** (decision `h:a1e3e7cd73`). `docs/NAMESPACES.md`
  now says, for each category, whether a module may add names. A module may add a link kind or a config key,
  prefixed. It may never add an entry type, a governance action or a channel. A new *Local files* table lists
  the per-node names under `$HIVE_HOME` and in the key directory, and a `via` table lists the verification
  values of a peer sighting. Both are generated from `vocabulary.py` and kept apart from the journal tables,
  and `tests/test_vocabulary.py` holds them to the path literals in the code, both ways. The ref-bearing
  payload fields stay deferred to the 2.1 module API. No behaviour change.
- **The docs name each moved command on the plane it runs on** (decision `h:02010d37e3`). Every reference that told a
  reader to run a command that moved in 2b as `hv …` now says `hive-mind …`. The files are `CLI_REFERENCE.md`,
  `AGENT_INTEGRATION.md`'s command table, `INTERNALS.md`, `SYNC_API.md`, `THREAT_MODEL.md`, the continual-learning
  design and the MCP adapter's `retract` docstring. `CLI_REFERENCE.md`'s owner, group and config sections say which
  verbs stay on `hv` and which moved. `tests/test_docs_name_moved_commands.py` fails when a document names a
  `commandmap.MOVED` command, or `retract --owner` or `owner propose-election --mint`, on `hv`. It excludes §7's
  per-version history, the CHANGELOG, `docs/history/`, and `README.md` and `SECURITY.md`, which #141 reconciles
  (6 and 2 references).
- **The docs state what 2.0 does.** Pages written during 1.x described 4a's changes as future ones: bare local ids
  "still accepted" and "removed at the next MAJOR", `tags` that "becomes the list", and a `$HERMES_AGENT` source
  fallback. `CLI_REFERENCE.md`, `INTERNALS.md` (whose `_BARE_ID_WARNING` no longer exists), the `hive-memory`
  skill and the MCP `hive_search` docstring now say a local id is refused, `tags` is a JSON list, and an omitted
  source is `manual`. `tests/test_docs_state_2_0_behaviour.py` fails if one of those phrases comes back outside
  the history, using the moved-command sweep's exclusions.

## 1.28 — 2026-09-26 · `v1.28.0`

- **Contract 1.28: `hv owner init` leaves a new hive closed (#135 part 1).** Before a hive has an owner it
  has no key to sign a forget with, so an owner-source forget dated before the genesis owner has always been
  honoured unsigned — the grandfather, kept since 1.4 so that adopting governance never resurrected a
  deliberately forgotten fact. 1.25 let an owner close it (`hv config set forget_writers owner`), but
  `legacy` remained the default, so every hive depended on its owner remembering to run that. Now genesis
  does it: at the end of `hv owner init`, every forget that is in effect **only** because it precedes genesis
  is re-issued as one ordinary owner-signed `retract` — the same act `hv retract <fact> --owner` writes — and
  only **then** is `forget_writers=owner` set. Each fact stays forgotten on an owner signature of its own, so
  a hive born here never depends on the grandfather. `owner init` prints which facts it re-issued. The old
  unsigned entries stay in the append-only journal and count for nothing.
- **The order is the design, not an implementation detail.** `hv config set forget_writers owner` refuses
  while closing would bring a fact back, naming each one with its two remedies (#122). Re-issuing first
  empties that list, so the flip has nothing left to decide — and the flip still goes through the same guard.
  That is what makes "closed **and** a fact silently back" unreachable rather than merely unlikely.
- **Failing does not close the hive.** Every retract is prepared and signed before any of them is appended.
  If preparation fails, nothing is appended and the config is not set: the journal is as it was. If an append
  fails after some retracts have landed, the config is still not set and what landed is **not** removed — an
  append-only journal cannot be rolled back, and those entries are ordinary post-genesis owner forgets, so
  nothing is resurrected by their presence. Either way `owner init` prints which facts were re-issued, which
  were not, and the two remedies for each one still open.
- **What is deliberately left alone.** A grandfathered forget whose target is not a fact in this journal
  (`dangling`) is not re-issued: it hides nothing, and minting owner authority over a target that does not
  exist would be a new claim rather than a restatement. A member device's negative-evidence retract is never
  promoted into an owner act — the list re-issued is already limited to owner-source forgets and is used
  unfiltered. `owner init --force`, a deliberate re-genesis, gets the same treatment, because skipping it
  would let a forced re-genesis silently reopen facts. There is no `--no-close` flag: a hive born here starts
  closed, and an operator who wants `legacy` sets it afterwards.
- **`hv doctor` says `closed` even with nothing left to ignore.** `forget-authz` used to report the closed
  state only when there were unsigned pre-genesis forgets to count, so a hive born closed — which has none —
  reported it by silence. It now states it. Advisory output only: no projection, journal or wire change.
- **Compatibility.** No new command and no new flag; nothing an adapter calls moves. Everything written is
  an owner-signed `retract` plus the `set-config` act 1.25 already defined, so the forgotten set converges
  with any peer that honours an owner-signed retract. A **pre-1.25** peer does not know the `forget_writers`
  key at all: it lands the act and keeps its own default. That is harmless here precisely because the
  re-issued retracts are owner-signed post-genesis acts that do not depend on the key — which is the point of
  doing them first. Part (2) of #135, changing the **default** for hives that already exist, stays a 2.0 item.

## 1.27 — 2026-09-26 · `v1.27.0`

- **Contract 1.27: the genesis declaration is pinned (security).** Which `owner` declaration established
  this hive is now recorded on the node, at `$HIVE_HOME/.genesis-pin` (0600, never synced, never journaled,
  never in the signed manifest), and the pin decides the genesis instead of the entry timestamp. Genesis used
  to be "the earliest valid self-signed `owner` act wins", and a journal timestamp is written by whoever wrote
  the entry — so a declaration that arrived later with an earlier timestamp replaced the owner, and the real
  owner's later acts stopped counting. `hv owner init` pins what it writes; `hv owner pin --set` pins an
  existing hive's single declaration and refuses to guess between two; `hv owner pin --fingerprint` pins from
  an invite before the first pull. Ingest refuses any other `owner` act and the projection resolves genesis
  through the pin, so a rival already in the journal loses — nothing is ever removed from it. A node with no
  pin keeps the old rule, and `hv doctor genesis` says so. **A rival a peer already stored is never
  removed**, so a node that refused it and a node that holds it keep different Merkle roots from then on;
  what converges is the projection, once every node pins the same genesis. An unpinned node can project a
  different owner than a pinned peer — visibly, not silently.
- **Unsigned entries can no longer fork a device's chain.** An entry with no signature could take an admitted
  device's future `(node_id, seq)` and become that device's chain tip, after which the device's own entry was
  dropped as a duplicate — two bodies under one key. Now, on a chain this node holds, an unsigned entry above
  the tip or a different body at a held sequence is refused; on a chain it does not hold, only a verified first
  pull is accepted (one batch reproducing the peer's whole advertised chain, window hash for window hash), so a
  fresh node still receives the fleet's historical unsigned entries while a single crafted high sequence cannot
  land. A push never qualifies.
- **A node that has not pinned serves nothing of its journal remotely.** `/sync/hello`, `/sync/chunk` and
  `/sync/ingest` answer 403 until the genesis is pinned; `/hive/info` and `/sync/merkle-root` stay open, and
  loopback is never gated, so the operator can always pin. The node still reaches the hive through its own
  outbound pull — that is how it gets the declaration it then pins. `hive-mind update` pins on upgrade, and the
  periodic `hv doctor --fix` pins when there is exactly one declaration to pin. A hive that has **no
  owner at all** cannot pin, because there is no declaration to pin — so its nodes stop syncing with each
  other until one of them runs `hv owner init`. That is the bootstrap window closing, and it is the point.
- **The invite carries a genesis fingerprint.** `hive-mind invite` prints `<address>/<hive_id>/<owner_id>/<hash8>`,
  and the joining device pins that before it trusts any journal, so a squatter advertising this hive's id cannot
  capture it. The short hash prefix is safe **because the pin binds the declared owner**: a genesis candidate
  must be self-signed by the owner it declares, so a rival would need the victim's owner key, not a ground
  hash prefix. The fingerprint is also served in `/hive/info` and `/sync/hello` **inside** the 1.26 responder
  signature, so it cannot be swapped in transit. Older installers strip the path and still read just the address.
- **`hv doctor` gains `genesis` and `unsigned`.** `genesis` fails on more than one self-signed declaration
  (naming each) or on a pin whose declaration has not synced, and warns when the node is unpinned. `unsigned`
  counts unsigned entries positioned after genesis. `--fix` pins when there is exactly one candidate.
- **Test isolation (#142 class).** The governance projection now reads the pin as well as the journal, so tests
  that project a temp hive in-process point `HIVE_HOME` at it, and the #109 session guard snapshots
  `.genesis-pin` so a test that writes one into the developer's real hive is caught.

## 1.26 — 2026-09-26 · `v1.26.0`

- **Contract 1.26: a peer proves who answered (#107), sync protocol 3.** A `/sync/hello` or `/hive/info`
  asked for with a signed request now carries `hello_sig`: the responder's device signature over the
  caller's nonce, the path, its node id, hive id, advertised address, protocol and a digest of the whole
  answer. The caller checks it (verified, addr-unproven, unadmitted, purged, unsigned or invalid). A new
  setting, `hv sync auth --outbound off|permissive|enforce` (default `permissive`, which only flags), makes
  a node push only to a verified peer: under `enforce` an unsigned, addr-unproven or unadmitted peer is
  only pulled from, and a purged or invalid one is skipped. It is separate from the inbound `sync_auth`,
  because inbound enforce needs peers at protocol 2 and outbound enforce needs protocol 3. `hv doctor`
  gains `peer-identity`, which shows each peer's outcome and protocol and when the fleet is ready for
  either enforce, and `peer-address` can now find a peer that never contacts this node: it asks the
  peer's candidate addresses for a signed `/hive/info` and repoints only to one that proves the right
  device at that address. An address that answers is never rewritten. One new flag; no journal change;
  a mixed fleet keeps syncing.
- **CI and the pre-sign gate run the test suite in parallel.** `pytest-xdist` (pinned 3.8.0) runs the same full
  suite on every core: the CI test jobs use `-n auto`, and `sign_release.py`'s gate does too whenever xdist is
  installed (a local run without it still runs the whole suite, serially). The re-sign after a merge drops
  from about 4.5 minutes to under 180 seconds, inside the `hive-mind update` wait window. What gets signed
  is unchanged: only a tree whose full suite passed. No contract change.


## 1.25.1 — 2026-09-25 · `v1.25.1`

No contract change.

- **Ingest validates entry timestamps before writing (security fix).** An entry's timestamp names its journal
  file, so ingest now rejects an entry whose timestamp is not an ISO-8601 time, and every writer refuses a
  date prefix that is not `YYYY-MM-DD` or a path outside `journal/`. Both shapes already in journals stay
  valid, and lines on disk are read unchanged. A security advisory accompanies this release.
- **`actions/create-github-app-token` bumped to v3.2.0** (#137), still pinned to a commit SHA.

## 1.25 — 2026-09-25 · `v1.25.0`

Contract 1.25, tagged 2026-09-25 at df0d671.

- **Contract 1.25: owner forgets can require a signature (#122, step 2).** A governed config key closes the
  hole `forget-authz` reports: `hv config set forget_writers owner` makes only forgets signed by the owner as
  of their position count, so a backdated unsigned owner forget from an admitted device erases nothing.
  `legacy` stays the default. The key stores no journal refs (orphan-proof, #130), and a legitimate legacy
  forget is kept by re-issuing it signed. Closing refuses while it would bring a fact back, and lists each
  one with its two remedies. No new command or flag; no wire change (a pre-1.25 node ignores the key).

## 1.24.1 — 2026-09-25 · `v1.24.1`

CI and signing only; no contract change.

- **`sign.yml` pushes the re-signed manifest as a dedicated GitHub App (#131, #132).** A short-lived
  installation token for `hivemind-release-signer` replaces the default token, which is now read-only. The App
  is the only bypass of a ruleset that requires the Ubuntu checks on `main`, so the re-sign lands without
  GH006.
- **Every GitHub Action is pinned to a full commit SHA (#133).**

## 1.24 — 2026-09-25 · `v1.24.0`

Contract 1.24, tagged 2026-09-25 at b2fe903.

- **Contract 1.24: revoke a decision (#45).** `hv decide --revoke <sid> --rationale "<why>"` withdraws a
  decision that was wrong, with no replacement. It writes one decision tagged `revocation` (content
  `Revoke <sid>: <the target's first line>` unless given) and one `supersedes` link to the target. The
  target is resolved and kind-checked, and a missing rationale or a combination with `--supersedes` is
  refused, before anything is written. There is no new projection: the target is superseded only when
  the link is hard (a person on the owner device, or the device that wrote the decision). The
  confirmation is derived from that authority, so an agent's revoke elsewhere prints `NOT in effect`
  until the owner re-runs it, and `hv doctor` lists it under `link-authz`. MCP and Hermes `hive_decide`
  gain `revoke` and `supersedes` (the latter had no path since 1.19), and a parity test now covers
  `hv decide`'s flags. No wire change; a pre-1.24 node sees an ordinary superseding decision.
- **Contract 1.24: `hv unforget` reverses an owner forget (#46), and owner forgets are honoured
  point-in-time.** `hv unforget <fact> --reason "<why>"` is owner-only and off MCP. It journals an
  owner-signed `retract` carrying `unretracts_ref`. Per fact text, owner forgets and unforgets are sorted
  on `(timestamp, node_id, seq)` and the latest honoured act wins. An act counts only when signed by the
  owner as of its own position, which fixes a resurrection bug: a previous owner's forget was dropped
  after a transfer, succession or election. An unforget is never grandfathered; a forget before the
  genesis owner still is (#122). Owner acts no longer move a fact's `last_evidence_at`, so an ignored
  forged forget can't refresh a fact's decay clock and an unforgotten fact re-derives from its evidence.
  A pre-1.24 node skips an unforget and keeps the fact forgotten until it upgrades (projection skew).

- **CI: the macOS legs run only where they can matter (#125).** The macOS test and installer smoke
  moved to `ci-macos.yml`. It runs on every push to `main`, and on a pull request only when the diff
  touches `hv`, the daemon, the installer or launchd scripts, or the tests that stub them. The merge
  rule is "CI green, and macOS green when it ran"; the macOS jobs are not required checks
  (CONTRIBUTING.md). No contract change.
- **`hv doctor` shows forgets that need no signature (#122, step 1).** An owner forget dated before
  the genesis owner is honoured unsigned, and ingest does not check timestamps, so an admitted device
  can erase a fact with a backdated forget. The advisory `forget-authz` check names every fact such a
  forget keeps forgotten (undo it with `hv unforget`) and counts the ones whose target is not in the
  journal. No projection or contract change; step 2 closes the hole.

- **The contract history moved out of `hv` (#106).** The per-version notes were one trailing comment on
  `hv`'s `CONTRACT_VERSION` line (18,544 characters), printed whole by every `grep` that matched it, at a
  real token cost for every agent reading the code. They now live in `docs/CONTRACT_HISTORY.md`, one
  section per version, text unchanged. No code change.

## 1.23 — 2026-09-25 · `v1.23.0`

Contract 1.23, tagged 2026-09-25 at 3f6d569.

- **Contract 1.23: links carry owner authority only when a person writes them (#114).** On a machine
  that holds the owner key, a link is owner-signed only when its source is `manual`; every agent
  source is device-signed, as on a member device, so an agent there can no longer `supersedes` or
  `resolves` another device's entries with owner authority. All eight link kinds go through one
  builder (`outcome-of` and `informed` were built inline). `hv decide` and `hv entity link` gain
  `--source` (the MCP server passes `claude-ai`), so an agent's decision is no longer attributed to a
  person. Write confirmations say `(owner-signed: source manual)` or `(device-signed: source …)`. An
  omitted `--source` still means `manual` (#119). No wire change.
- **`hv doctor` catches a sync daemon left on old code (#112).** A bare `git pull` moves the files but
  not the running daemon. The daemon now records the source digest it loaded and serves it on a
  loopback-only `/api/daemon`; the new `daemon-code` check compares it with the same digest of the
  daemon's own checkout (never the checkout doctor runs from) and `--fix` restarts the managed daemon,
  at most once per run. A hive daemon from before this change also warns; another program on the port
  gets no verdict. The 15-minute doctor timer therefore heals a bare pull.

## 1.22 — 2026-09-24 · `v1.22.0`

Contract 1.22, tagged 2026-09-24 at 5c30c20. It also carries the fixes that landed before the tag.

- **Contract 1.22: an `extends` link kind.** `hv remember "…" --extends <sid>` (and MCP
  `hive_remember(extends=…)`, Hermes `hive_remember`) writes the fact plus one `extends` link to a
  fact, idea or decision: "builds on" without evidence semantics. The projection keeps it as an edge
  row in `links` and never weighs it toward confidence on any channel. One relationship per write, so
  it is mutually exclusive with `--resolves`, `--outcome-of`, `--supports` and `--contradicts`.
  `hv search` text shows `extends h:…` on the row; JSON rows are unchanged. No wire change and no
  skew: a pre-1.22 node lands the link and projects it to nothing (#115).
- **The test suite no longer touches the developer's real account (#109).** Every test runs with a
  throwaway `HOME`, `CLAUDE_CONFIG_DIR` and `HIVE_IDENTITY_STASH`, and with service-manager stubs
  first on `PATH`, so `hv doctor --fix` can no longer relink the live `~/.claude/skills/hive-memory`
  into a worktree or restart the live daemon, and `hv owner init` can no longer overwrite the
  owner-key stash. A session guard checks those real paths are unchanged at the end of every run.

## 1.21 — 2026-09-23 · `v1.21.0`

Contract 1.21, tagged 2026-09-24 at b723b12. It also carries the fixes and documentation that landed before the tag.

- **Contract 1.21: the grounding rule covers fact assertions.** A fact written with
  `--channel introspect` no longer counts as corroboration (it weighs `introspect_support_weight`,
  default 0, like an `introspect` link); it is still recorded and can earn confidence from
  observations (#73).
- **Unrecognised channel labels fail closed:** a `channel` outside `sense`/`act`/`introspect` counts
  as `introspect` everywhere; an unrecognised source class keeps full weight, like an absent one,
  since a class can only claim a discount (#72).
- **MCP:** `hive_remember` gains `resolves`, for parity with `hv remember --resolves` (#75).
- **A peer that moves to a new tailnet IP heals itself (#7).** The daemon records a peer's address
  only from requests signed by that peer's admitted device key (`$HIVE_HOME/.peer_candidates.json`,
  local and never journaled). A new `hv doctor` check, `peer-address`, repoints the `.peers.json`
  entry with `--fix` when the stored address fails and the peer has verified itself elsewhere. A
  working address is never rewritten, and `tailscale status` names are only unverified hints. The
  responder-signed hello that would also cover a peer that never contacts this node is #107.
- **`.gitignore`** ignores the local bus log (`.bus/`) and any `*.log` in the checkout. Like the
  store's side files (#74), they hold hive content and could otherwise be committed to the public repo
  by accident (#103).
- **Search JSON:** rows gain `tag_list` (the tags as a list); `tags` stays a JSON-encoded string
  until 2.0, when it becomes the list (#77).
- **Ideas can earn confidence:** `hv remember "<observation>" --supports <sid>` / `--contradicts <sid>`
  (and MCP `hive_remember(supports=…, contradicts=…)`) write the evidence links ideas and facts
  need. An idea's author can't support their own idea but can contradict it. One relationship per
  write: `--resolves`, `--outcome-of`, `--supports` and `--contradicts` are mutually exclusive, so
  `--resolves` with `--outcome-of`, previously accepted, is refused (#71).
- **Hermes adapter at parity with MCP (#76):** the Hermes plugin gains `hive_remember` (outcomes,
  corrections, `supports`/`contradicts`), `hive_decide` (with `informed_by`) and `hive_propose`, and
  `hive_search` gains `kind`. All writes, including the `memory()` mirror, run on one bounded
  background writer, so a turn never waits on the hive. The unused root `hermes_integration.py` is
  removed.
- **`hive-mind update` no longer aborts on a busy store (#93).** It now refreshes the units, restarts
  the daemon and waits for it, *then* rebuilds (the old daemon could hold the store's lock through a
  minutes-long rebuild, past the 10 s busy timeout, which aborted the update and skipped the restart
  and hooks). A rebuild that still finds the store busy warns and continues; the daemon catches up on
  its next cycle. A pull that lands before the release re-sign waits for it (up to 3 minutes) and
  pulls it, or says it is pending, and `hv doctor`'s `authenticity` check marks a clean checkout on a
  commit under 30 minutes old advisory instead of failed while the re-sign is pending.
- **Agent write guidance teaches the grounding rule (#99):** the Claude Code skill, the MCP server
  instructions and the Hermes context block now tell agents to write their own conclusions, analysis
  and plans with `--channel introspect` (only if worth finding later), and that tags help readers but
  never change how much a fact counts as evidence. A new test (`tests/test_agent_guidance.py`) keeps
  all three from dropping it.

## 1.20.1 — 2026-09-23 · `v1.20.1`

A patch release: no contract change.

- **Performance fix (#70):** `ed25519.py` is rewritten for speed with an identical accept set and
  byte-identical signatures (roughly 60–180× faster), and each signature is verified once per
  process. On a hive of about 860 entries `hv search` drops from about 15 s to 0.3 s and `hv remember`
  from about a minute to 0.7 s, back inside the agent adapters' timeouts (#87). SQLite waits up to 10 s
  for a busy store. A write that can't reach it after its journal append (`remember`, `decide`,
  `propose`, `retract`, `entity`) reports success (journaled) instead of failing, so callers don't
  retry into duplicates, and the next command catches the store up; a busy store never stops a read
  (#95).
- **The sync daemon's bind heals itself (#47):** a daemon that starts before `tailscaled` waits up to
  30 s for the tailnet. If it still lands on loopback, it rebinds within 15 s of the tailnet appearing,
  and on a tailnet IP change within one sync round, by exiting 75 for its service manager to restart
  it. It never moves toward loopback. A new `sync-bind` doctor check, fixed by `--fix`, catches a
  daemon still on the wrong address (#90).
- **`.gitignore`** ignores the store's SQLite side files (`store.db-wal`, `-shm`, `-journal`), which
  hold hive content, so they can't be committed by accident (#74, #80).
- Documentation brought up to date with contract 1.20: a new `SECURITY.md`, `docs/SYNC_API.md`
  rewritten (read authentication, current fields, the `/api/*` surface), `docs/P2P_DESIGN.md` marked
  historical, and README, CLI reference, agent-integration spec, internals, threat model and skills
  updated (#78). This changelog and the version tags were added. The continual-learning design
  record is in `docs/design/` (#68).
- `hv dash` prints only the local URL; the dashboard is refused to other devices (see 1.17).
- Security advisory [GHSA-242f-7fxg-f7wm](https://github.com/projectmentor/hive-mind/security/advisories/GHSA-242f-7fxg-f7wm)
  published (fixed in 1.17).
- CI also runs on Ubuntu 26.04, ahead of the `ubuntu-latest` migration (#89).

## 1.20 — 2026-09-20 · `v1.20.0`

The second half of the continual-learning work.

- **Ideas:** a new `idea` entry type for hypotheses, whose confidence is earned from others' evidence
  and never asserted; `hv propose` and MCP `hive_propose`; `hv search --kind all|fact|decision|idea`;
  open ideas in the session-start digest (#62). *Ideas could not earn confidence in 1.20: nothing
  wrote the links they need (fixed in 1.21, #71).*
- **Trust velocity:** per-device reliability drift, the `trust-drift` doctor advisory and a `DRIFT`
  column in `hv peers`; advisory only (#63).
- **Stable short ids:** every fact, decision and idea has an `h:…` id that is the same on every node,
  shown everywhere and accepted wherever an id is; bare local ids are deprecated (#64).
- **Learned importance and utility:** importance (salience L3) starts at a capped self-hint and rises
  only through other agents' links; utility credits the facts that informed decisions, weighted by
  outcomes; per-class half-lives; `hv search --sort importance|utility|recency` (#65).
- **Write-path switch:** `hv decide --supersedes`, `hv remember --resolves` and `hv entity link` now
  write one `link` entry; the `fleet-contract` doctor advisory lists peers older than 1.19. Upgrade
  always-on nodes first (#66).

## 1.19 — 2026-09-20 · `v1.19.0`

The first half of the continual-learning work.

- **Links:** one generic `link` entry type with an open vocabulary (`supports`, `contradicts`,
  `supersedes`, `resolves`, `entity`, `informed`, `outcome-of`). Links are evidence, not commands:
  only the owner (by signature) or the target's author can supersede or resolve; `link-authz` doctor
  advisory (#57).
- **Informed decisions:** `hv decide --informed` records what a decision relied on (#60).
- **Outcomes:** `hv remember --outcome-of --polarity [--channel]`; decisions gain an outcome score, a
  measure of whether they worked out, never confidence (#61).

## 1.18 — 2026-07-09 · `v1.18.0`

- **`announce`:** a device the owner admitted directly, which never wrote anything, can publish its
  key and so receive capsules (`hv key announce`; `hv doctor --fix` emits it automatically) (#43).
  Upgrade always-on nodes first; older peers show a temporary divergence until they upgrade.
- `_is_salient` renamed `_is_admissible` (the salience L2 admission gate) (#49).

## 1.17 — 2026-06-30 · `v1.17.0`

- **Cell and comb write authorization** under a separate `cell_writers` policy (default: owner only);
  `cell-authz` doctor advisory (#40). *Behaviour change:* `hv wire --add` is owner-only by default.
- **Security fix, 2026-07-08:** sync reads are signed by an admitted device
  (`hv sync auth off|permissive|enforce`, default `permissive`), the dashboard and its data answer only
  local or signed requests, and the daemon binds the Tailscale address instead of all interfaces.
  Fixes [GHSA-242f-7fxg-f7wm](https://github.com/projectmentor/hive-mind/security/advisories/GHSA-242f-7fxg-f7wm)
  (#42).

## 1.16 — 2026-06-30 · `v1.16.0`

- **Capsule write authorization** enforced where capsules are read, not only in the CLI, under
  `capsule_putters`; a compromised admitted device can no longer overwrite or delete a capsule;
  `capsule-authz` doctor advisory (#39).

## 1.15 — 2026-06-28 · `v1.15.0`

- **Decisions become taggable and searchable:** `hv decide --tags`; `hv search` returns matching
  decisions (#33).
- **Web dashboard:** `hv dash`, served by the sync daemon (#34–#38).

## 1.14 — 2026-06-25 · `v1.14.0`

- **Standards-anchored crypto:** ChaCha20-Poly1305 (RFC 8439) for capsules and owner-key sealing,
  with a pinned known-answer test; `keyperm` doctor check. *Breaking* for escrows and passphrase
  exports made before 1.14: re-run `hv owner escrow` from a device that holds the owner key.
- Also: `hive-mind reset`, the `hv peers` roster, the invite and seed-peer join flow (Android), sync
  over sub-1280-MTU tailnet paths, and MCP parity with the CLI.

## 1.13 — 2026-06-25 · `v1.13.0`

- **Cells, combs and capsules** as entry types: `hv wire` for self-wiring tools and agents (replacing
  `hv doctor wire-agent`, now a deprecated alias), `hv capsule` for secrets sealed to your devices, a
  crypto self-test and the bundled advisories feed; release signing requires a green test suite.

## 1.12 — 2026-06-22 · `v1.12.0`

- **Self-healing Claude Code integration:** one stable dispatch shim per lifecycle event in
  `~/.claude`, reconciled by `hv doctor --fix`; `agent-hooks` doctor check.

## 1.11 — 2026-06-22 · `v1.11.0`

- **Reconciliation:** `hv remember --resolves` corrects and soft-retracts a fact; the audit's
  CONTRAVENED check flags corrections that were never reconciled.

## 1.10 — 2026-06-21 · `v1.10.0`

- **Sync fix:** the Merkle index de-duplicates the journal by `(node_id, seq)`, so a repeated line can
  no longer cause a permanent false divergence.

## 1.9 — 2026-06-14 · `v1.9.0`

- **Owner resilience, part 3:** quorum election with a dead-man switch (`hv owner propose-election`,
  `vote`, `heartbeat`; `hv config quorum`). A live owner can never be unseated.

## 1.8 — 2026-06-14 · `v1.8.0`

- `hv rebuild` folded into `hv doctor rebuild` (the old name still works).

## 1.7 — 2026-06-14 · `v1.7.0`

- **Owner resilience, part 2:** nominated succession (`hv owner nominate` / `claim`), immediate
  `transfer`, `revoke-escrow`; `owner` doctor check.

## 1.6 — 2026-06-14 · `v1.6.0`

- **Owner resilience, part 1:** `hv owner export` / `import`, in-hive escrow (`escrow` / `restore`),
  `standby`.

## 1.5 — 2026-06-13 · `v1.5.0`

- **Membership lifecycle:** `hv group` (admit, revoke, deny, change, purge, list); `hv config
  identity` and `hv config confidence`; `hv merkle` and `migrate-device-identity` folded under
  `hv doctor`.

## 1.4 — 2026-06-08 · `v1.4.0`

- **Governed confidence:** journaled, owner-signed governance; the same-device discount; the
  admission gate; `cap_self`. An owner forget requires the owner key.
- Also: read-only membership until admitted, `hv whoami`, installer self-healing and the `hv doctor`
  timer, MCP nudge, audit and telemetry tools.

## 1.3 — 2026-06-08 · `v1.3.0`

- **Cryptographic device identity:** Ed25519 device keys; entries are signed and verified on ingest;
  migration tooling.

## 1.2 — 2026-06-07 · `v1.2.0`

- `hv remember` auto-tags transient status claims `volatile`; `hv doctor`.

## 1.1 — 2026-06-07 · `v1.1.0`

- A local-only telemetry lane (`hv telemetry`) that is never journaled or synced.

## 1.0 — 2026-06-07 · `v1.0.0`

- The first versioned contract: the `hv` CLI over an append-only journal, peer-to-peer Merkle sync,
  confidence from independent corroboration, the nudge-and-audit capture loop, `hv verify`, and the
  installer.
