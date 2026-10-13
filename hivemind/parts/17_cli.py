# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _add_plan_flags(parser):
    """`--plan --json` on an owner verb a ticket can carry: print the canonical bodies it would sign, sign nothing."""
    parser.add_argument("--plan", action="store_true",
                        help="print the exact canonical governance bodies this would sign, and sign nothing (needs --json)")
    parser.add_argument("--json", action="store_true", help="with --plan: print the plan as JSON on stdout")


def _plan_or_run(args, verb, fn):
    """Run `fn`, or with `--plan` print its plan (owner approval slice A0). `--plan` without `--json` is a usage error."""
    if not getattr(args, "plan", False):
        return fn()
    if not getattr(args, "json", False):
        print(f"{verb}: --plan prints JSON: add --json", file=sys.stderr)
        sys.exit(2)
    return plan_verb(verb, fn)


def build_parser(plane="data"):
    """The command line. `plane="data"` is `hv`: it has no owner-signed verb and no owner flag, so a command
    that lives on the control plane is argparse's own unknown command (exit 2, nothing written). `plane="control"`
    is the full parser `hive-mind` routes through, so every flag is still defined once."""
    control = plane == "control"
    if plane not in ("data", "control"):
        raise ValueError(f"unknown plane {plane!r}")
    parser = argparse.ArgumentParser(
        description="Hive Mind CLI — shared, confidence-weighted institutional memory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            '  hv remember "X happened" --tags a,b --source claude-code   # store a fact\n'
            '  hv remember "..." --gate                                  # admission gate: skip non-statements\n'
            '  hv search "X" [--min-confidence -1] [--format json]        # ranked by effective confidence\n'
            '  hv decide "chose Y" --rationale "because"                  # record a decision\n'
            "  hv retract <fact-id> [--reason ...]                        # peer negative evidence (rejected)\n"
                        "  hv stats | sync now|daemon\n"
            "  hv doctor [--format json] [--fix | --boot]                 # health check (+ self-heal / boot pass)\n"
            "  hv doctor merkle | rebuild                                 # sync diag / rebuild db\n"
            "  hv wire claude                                             # (re)wire the Claude Code hooks + skill\n"
            "\nconfidence: derived in [-CAP,+CAP] from distinct corroborators minus retractors;\n"
            "decays with age ($HIVE_NOW injectable); owner-forget = -1.0."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    remember_parser = subparsers.add_parser("remember", help="Store a fact")
    remember_parser.add_argument("content", help="Fact content")
    remember_parser.add_argument("--tags", help="Comma-separated tags")
    remember_parser.add_argument("--importance", type=float, default=0.5)
    remember_parser.add_argument("--source", help="Source agent")
    remember_parser.add_argument("--gate", action="store_true",
                                 help="Apply the content-neutral admission gate (salience L2): skip writes that are "
                                      "not knowledge-shaped (trivially short, bare question, greeting)")
    remember_parser.add_argument("--no-volatile", action="store_true",
                                 help="Do not auto-tag transient operational-status claims as volatile")
    # One relationship per write (#71): argparse refuses any two of these before anything is read or written.
    rel = remember_parser.add_mutually_exclusive_group()
    rel.add_argument("--resolves", metavar="FACT",
                                 help="A prior fact this write resolves/closes (soft-retracts it): its short id "
                                      "`h:…` (preferred) or `node_id:seq` (2.0 refuses local ids)")
    rel.add_argument("--outcome-of", metavar="DECISION",
                                 help="This fact is an OUTCOME of a decision: its short id `h:…` (preferred) or stable "
                                      "ref `node_id:seq`, both shown by `hv search` (2.0 refuses local ids); "
                                      "resolved and kind-checked before anything is written. Emits an `outcome-of` link "
                                      "that feeds the decision's outcome_score (vindication, not confidence)")
    rel.add_argument("--supports", metavar="REF",
                     help="This observation SUPPORTS a fact or an idea: its short id `h:…` (preferred) or `node_id:seq` "
                          "(2.0 refuses local ids). Writes the fact plus one `supports` link, "
                          "resolved and kind-checked before anything is written. It counts as this identity's positive "
                          "evidence on the write's --channel (introspect weighs introspect_support_weight, default 0); "
                          "an idea's author cannot support their own idea")
    rel.add_argument("--contradicts", metavar="REF",
                     help="This observation CONTRADICTS a fact or an idea (same forms as --supports). Writes the fact "
                          "plus one `contradicts` link: this identity's negative evidence. An idea's author may "
                          "contradict their own idea (the way to withdraw it)")
    rel.add_argument("--extends", metavar="REF",
                     help="This entry BUILDS ON (extends, comments on) a fact, an idea or a decision (same forms as "
                          "--supports). Writes the fact plus one `extends` link: a relationship, "
                          "not evidence — it never moves the target's confidence on any channel")
    remember_parser.add_argument("--polarity", type=int, choices=[-1, 0, 1], default=1,
                                 help="With --outcome-of: +1 worked out (default), -1 did not, 0 observed and neutral. "
                                      "Ternary on purpose — magnitude comes from how many independent identities report, "
                                      "not from one agent's claimed intensity")
    remember_parser.add_argument("--channel", choices=["sense", "act", "introspect"],
                                 help="Which experience signal this write is: sense (an observation of the world — the "
                                      "default when absent), act (an action taken), introspect (the agent's own reasoning "
                                      "or plan: recorded, but never counted as corroboration of the fact or toward a "
                                      "decision's outcome_score)")

    search_parser = subparsers.add_parser("search", help="Search facts")
    search_parser.add_argument("query", nargs="?", help="Search query (omit with --id)")
    search_parser.add_argument("--id", dest="lookup_id", metavar="SID|REF",
                               help="Look up ONE entry by its short id (h:…) or ref (node_id:seq) instead of searching: "
                                    "prints it (kind, sid, ref, source, content, tags, confidence or outcome, superseded "
                                    "state) and exits 1 when nothing matches, so a script or agent can verify an id "
                                    "before citing it. Reads the local store; needs no daemon")
    search_parser.add_argument("--chain", dest="chain_id", metavar="SID|REF",
                               help="Follow ONE decision's supersede chain instead of searching: one hop per line, "
                                    "each naming the superseding entry by sid and the link's authority (hard = in "
                                    "effect; an evidence-only supersedes link is shown as not in effect), to the live "
                                    "entry. With --format json: {chain: [...], live: sid}. Exits 1 when the id names "
                                    "no decision. Reads the local store; needs no daemon")
    search_parser.add_argument("--format", choices=["text", "json"], default="text")
    search_parser.add_argument("--min-confidence", type=float, default=0.0,
                               help="Hide facts below this confidence (default 0.0 = show all)")
    search_parser.add_argument("--kind", choices=["all", "fact", "decision", "idea"], default="all",
                               help="What to search (default all). Under `all` an idea appears only once it has "
                                    "earned confidence > 0; `--kind idea` lists every idea")
    search_parser.add_argument("--sort", choices=["confidence", "importance", "utility", "recency"], default="confidence",
                               help="Rank facts/ideas by effective confidence (default), learned importance, learned "
                                    "utility, or recency (1.19 PR6). Decisions always list newest-first")

    propose_parser = subparsers.add_parser("propose", help="Record an idea — a hypothesis the hive can support or contradict (1.20)")
    propose_parser.add_argument("content", help="The hypothesis, stated so it can be supported or contradicted")
    propose_parser.add_argument("--tags", help="Comma-separated tags, like `remember`")
    propose_parser.add_argument("--source", help="Source agent (default: manual)")
    propose_parser.add_argument("--channel", choices=["sense", "act", "introspect"],
                                help="Experience signal of the proposal itself (default introspect: a hypothesis is "
                                     "internal state). Does not affect how the idea earns confidence")

    decide_parser = subparsers.add_parser("decide", help="Record a decision")
    decide_parser.add_argument("content", nargs="?",
                               help="Decision content (optional only with --revoke, which writes `Revoke <sid>: "
                                    "<the target's first line>`)")
    decide_parser.add_argument("--rationale", help="Why this decision")
    decide_parser.add_argument("--source", help="Source agent (e.g. claude-code), as on `remember`. Omitted: "
                                               "`manual`, the only source whose links are "
                                               "owner-signed on the owner device (#114)")
    decide_parser.add_argument("--tags", help="Comma-separated tags (e.g. project scope), like `remember`")
    dec_rel = decide_parser.add_mutually_exclusive_group()   # one relationship to a prior decision per write
    dec_rel.add_argument("--supersedes", metavar="DECISION",
                         help="The decision this replaces: its `h:` short id or `ref` (2.0 refuses local ids)")
    dec_rel.add_argument("--revoke", metavar="DECISION",
                         help="Withdraw a decision that was wrong, with no replacement (#45): writes a decision "
                              "tagged `revocation` that supersedes it. Needs --rationale")
    decide_parser.add_argument("--informed", nargs="+", metavar="REF",
                               help="What this decision relied on: short ids `h:…` (preferred) or stable refs "
                                    "`node_id:seq`, both shown by `hv search` (2.0 refuses local ids), resolved "
                                    "before anything is written")

    if control:
        unforget_parser = subparsers.add_parser("unforget", help="Owner only: reverse an owner-forget (`retract --owner`)")
        unforget_parser.add_argument("fact_id", help="The forgotten fact: its `h:` short id or `ref` (2.0 refuses local ids)")
        unforget_parser.add_argument("--reason", required=True, help="Why the forget is reversed (journaled)")

    retract_parser = subparsers.add_parser("retract", help="Record negative evidence against a fact (soft-forget)")
    retract_parser.add_argument("fact_id", metavar="FACT",
                                help="The fact to retract: its `h:` short id or `ref` (2.0 refuses local ids)")
    retract_parser.add_argument("--reason", help="Why")
    retract_parser.add_argument("--source", help="Retractor identity (default: env/manual)")
    if control:
        retract_parser.add_argument("--owner", action="store_true",
                                    help="Owner forget — governance, decisive (drives to the forget floor)")

    entity_parser = subparsers.add_parser("entity", help="Manage entities")
    entity_parser.add_argument("action", choices=["add", "list", "show", "link", "join", "unjoin"], help="Sub-command")
    entity_parser.add_argument("--name", help="Entity name")
    entity_parser.add_argument("--type", help="Entity type (person, project, concept)")
    entity_parser.add_argument("--attr", help="JSON attributes")
    entity_parser.add_argument("--fact-id", metavar="FACT", help="Fact to link: its `h:` short id or `ref` (2.0 refuses local ids)")
    entity_parser.add_argument("--confidence", type=float, help="Link confidence")
    entity_parser.add_argument("--to", help="`join`/`unjoin`: the unprefixed entity a module's `x-<module>:` "
                                           "entity (`--name`) is the same as (2.1, #208)")
    entity_parser.add_argument("--new", action="store_true",
                               help="`add`: create a new entity even when one has this name (two people called "
                                    "David); without it `add` updates the one entity of that name (3.0)")
    entity_parser.add_argument("--entity", metavar="ID",
                               help="The entity itself, by its `h:` id or `node_id:seq` ref (`entity list` shows "
                                    "the id of a repeated name): `add` updates it, `show`, `link`, `join` and "
                                    "`unjoin` act on it. A name that more than one entity holds needs this (3.0)")
    entity_parser.add_argument("--to-entity", metavar="ID",
                               help="`join`/`unjoin`: the unprefixed entity by `h:` id or ref, instead of `--to`")
    entity_parser.add_argument("--no-joins", action="store_true",
                               help="`show`: the core entity only, without the module entities joined to it")
    entity_parser.add_argument("--owner", action="store_true",
                               help="`unjoin`: an owner withdrawal (control plane, owner key)")
    entity_parser.add_argument("--source", help="Source agent for `link` (e.g. claude-code). Omitted: "
                                               "`manual`, the only source that is owner-signed on the owner "
                                               "device (#114)")

    subparsers.add_parser("version", help="Print the hv contract version (SemVer), not the release; `hive-mind version` prints the release")
    subparsers.add_parser("verify", help="Verify this is the official, untampered HiveMind")
    subparsers.add_parser("stats", help="Show memory usage stats")
    feed_parser = subparsers.add_parser("feed", help="Read-only: journal entries past a per-node cursor, as JSON")
    feed_parser.add_argument("--after", default="", help="cursor: node_id:seq,node_id:seq (default: from the start)")
    feed_parser.add_argument("--limit", type=int, default=200, help="entries per page (default 200)")
    feed_parser.add_argument("--format", choices=["json"], default="json")
    subparsers.add_parser("whoami", help="Show this device's identity + membership status (sterile/fertile/owner)")
    subparsers.add_parser("peers", help="List hive members by device + principal + address + reachability")

    dash_parser = subparsers.add_parser("dash", help="Removed in 4.0: the dashboard is the hdash module (`hdash dash`)")
    dash_parser.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    doctor_parser = subparsers.add_parser("doctor", help="Health checks + device maintenance (rebuild, merkle)")
    doctor_parser.add_argument("--format", choices=["text", "json"], default="text")
    doctor_parser.add_argument("--fix", action="store_true",
                               help="Take safe remedial action: kill orphan sync daemons + restart the managed unit, and re-assert the Claude Code hooks/skill")
    doctor_parser.add_argument("--dry-run", action="store_true",
                               help="With --fix: PREVIEW the remedial actions (kill/restart/rewire) without making any change")
    doctor_parser.add_argument("--boot", action="store_true",
                               help="The boot pass: wait (bounded) for the sync daemon, check the platform, run --fix, recheck, "
                                    "and record one `boot` fact for this boot")
    doctor_sub = doctor_parser.add_subparsers(dest="doctor_action")
    doctor_sub.add_parser("merkle", help="Show the Merkle index over the journal (sync diagnostic)")
    doctor_sub.add_parser("rebuild", help="Rebuild store.db from the journal")

    wire_parser = subparsers.add_parser("wire",
                                        help="Wire an agent/tool from its cell (auto-dispatch by kind), or a comb of cells")
    wire_parser.add_argument("name", nargs="?", help="Cell name to wire")
    wire_parser.add_argument("--comb", metavar="NAME", help="Wire every cell in this comb")
    wire_parser.add_argument("--list", action="store_true", help="List cells (and combs)")
    wire_parser.add_argument("--kind", help="(with --list) filter by kind: tool|agent")
    wire_parser.add_argument("--show", metavar="NAME", help="Show a cell/comb definition")
    wire_parser.add_argument("--add", metavar="FILE", help="Publish a cell/comb from a JSON file")
    wire_parser.add_argument("--env-file", dest="env_file", metavar="PATH",
                             help="Dotenv file to read tool credentials from (default ~/.claude/.env)")

    capsule_parser = subparsers.add_parser("capsule",
                                           help="Encrypt-to-device secrets (sealed to the authorized device set)")
    capsule_sub = capsule_parser.add_subparsers(dest="capsule_action")
    cap_put = capsule_sub.add_parser("put", help="Seal a secret into a capsule (value via --env-file/--file/--stdin/prompt — never argv)")
    cap_put.add_argument("name")
    cap_put.add_argument("--env-file", dest="env_file", metavar="PATH", help="Dotenv file to read the value from (default ~/.claude/.env)")
    cap_put.add_argument("--name", dest="var", metavar="VAR", help="Variable name within the env file (default the capsule name)")
    cap_put.add_argument("--file", metavar="PATH", help="Read the raw value from this file")
    cap_put.add_argument("--stdin", action="store_true", help="Read the value from stdin")
    cap_get = capsule_sub.add_parser("get", help="Open a capsule on this device (prints the value)")
    cap_get.add_argument("name")
    cap_get.add_argument("--raw", action="store_true", help="No trailing newline")
    capsule_sub.add_parser("ls", help="List capsules + whether this device can open each")
    cap_rm = capsule_sub.add_parser("rm", help="Tombstone a capsule (logical delete; ciphertext stays in the append-only journal)")
    cap_rm.add_argument("name")
    cap_rot = capsule_sub.add_parser("rotate", help="Re-seal to the current device set (run after admit/revoke/purge)")
    cap_rot.add_argument("name", nargs="?", help="Capsule to rotate (omit = all openable capsules)")



    owner_parser = subparsers.add_parser("owner", help="Show or create the governance owner identity")
    owner_sub = owner_parser.add_subparsers(dest="owner_action")
    owner_sub.add_parser("show", help="Show the established owner + governance state")
    if control:
        owner_init = owner_sub.add_parser("init", help="Mint the owner key and claim ownership")
        owner_init.add_argument("--force", action="store_true", help="Replace an existing owner key / override an established owner")
        owner_pin = owner_sub.add_parser("pin", help="Show or set the pinned genesis declaration (no arg shows)")
        owner_pin.add_argument("--set", action="store_true",
                               help="Pin the journal's single self-signed owner declaration (refuses if there are 0 or 2+)")
        owner_pin.add_argument("--fingerprint", metavar="FP",
                               help="Pin from an invite's genesis fingerprint (<hive_id>/<owner_id>/<hash8>), before the first sync")
        owner_pin.add_argument("--force", action="store_true", help="With --set/--fingerprint: replace an existing pin (a deliberate fork)")
        owner_export = owner_sub.add_parser("export", help="Back up this device's owner key to a passphrase-encrypted file (for recovery)")
        owner_export.add_argument("--out", help="Output file (default ./hive-owner-<owner_id>.key)")
        owner_export.add_argument("--passphrase", action="store_true", help=argparse.SUPPRESS)  # the default now; kept so old scripts run
        owner_export.add_argument("--plaintext", action="store_true",
                                  help="Write the seed UNENCRYPTED (default: encrypted with a prompted passphrase)")
        owner_import = owner_sub.add_parser("import", help="Install an owner key from a backup file (resume governance here)")
        owner_import.add_argument("file", help="The exported owner-key file")
        owner_import.add_argument("--force", action="store_true", help="Install even if it doesn't match the journal's established owner")
        owner_standby = owner_sub.add_parser("standby", help="Declare/remove a standby device that may hold the owner key (advisory)")
        owner_standby.add_argument("device_id", help="The standby device's device_id (k1:…)")
        owner_standby.add_argument("--off", action="store_true", help="Remove the standby declaration")
        owner_sub.add_parser("escrow", help="Store the owner key, passphrase-encrypted, IN the hive (syncs to all nodes)")
        owner_sub.add_parser("restore", help="Recover the owner key from the hive's escrow (needs the passphrase)")
        owner_nominate = owner_sub.add_parser("nominate", help="Nominate a successor owner key (the successor then `claim`s)")
        owner_nominate.add_argument("successor_pub", help="The successor's owner pubkey (base64; from `hive-mind owner claim --mint`)")
        owner_unnominate = owner_sub.add_parser("unnominate", help="Withdraw a pending successor nomination")
        owner_unnominate.add_argument("successor_pub", help="The nominated successor's owner pubkey (base64)")
        owner_claim = owner_sub.add_parser("claim", help="Claim ownership on this device against an open nomination (successor side)")
        owner_claim.add_argument("--mint", action="store_true", help="Mint a fresh owner key for this device first")
        owner_claim.add_argument("--force", action="store_true", help="With --mint, replace an existing owner key on this device")
        owner_transfer = owner_sub.add_parser("transfer", help="Immediately hand ownership to a key (the target must already hold it)")
        owner_transfer.add_argument("new_owner_pub", help="The new owner's pubkey (base64)")
        owner_revoke_escrow = owner_sub.add_parser("revoke-escrow", help="Tombstone an escrowed key so `restore` skips it")
        owner_revoke_escrow.add_argument("ref", help="Escrow ref `node_id:seq`, or `all`")
        owner_sub.add_parser("heartbeat", help="Refresh owner liveness (resets the dead-man timer; owner key holder)")
        owner_sub.add_parser("freeze-timestamps", help="Arm the bounded entry timestamps (#217): freeze every device's "
                                                       "chain at its tip, so only later entries are checked (owner key holder)")
        owner_mint = owner_sub.add_parser("mint", help="[hive-mind] Mint a prospective owner key on this device, "
                                                      "to propose with `hv owner propose-election --pub`")
        owner_mint.add_argument("--force", action="store_true", help="Replace an owner key already on this device")
        owner_sub.add_parser("seal", help="[hive-mind] Seal a plaintext owner key at rest under a passphrase (2.0)")
    owner_propose = owner_sub.add_parser("propose-election", help="Propose electing a new owner (admitted devices; needs quorum + a dark owner)")
    owner_propose.add_argument("--pub", help="Propose this base64 owner pubkey (mint one with `hive-mind owner mint`)")
    owner_vote = owner_sub.add_parser("vote", help="Vote for an open election proposal (admitted devices)")
    owner_vote.add_argument("proposal_id", help="The election's proposal_id (from `hv owner elections`)")
    owner_sub.add_parser("elections", help="List open owner-election proposals and their tallies")

    if control:
        admit_parser = subparsers.add_parser("admit", help="[alias of `hive-mind group admit`] Admit a device; no arg lists pending")
        admit_parser.add_argument("device_id", nargs="?", help="The peer's device_id (k1:…). Omit to list devices awaiting admission")
        admit_parser.add_argument("--principal", help="Tag the person or agent who owns this device")
        admit_parser.add_argument("--module", help="Mark the device as module NAME's (2.1): it never votes in an election")
        _add_plan_flags(admit_parser)

        migrate_parser = subparsers.add_parser("migrate", help="Owner only: one-time migrations (3.0): `migrate forget`")
        migrate_sub = migrate_parser.add_subparsers(dest="migrate_action", required=True)
        m_forget = migrate_sub.add_parser("forget", help="Re-issue, owner-signed, every forget that only the pre-genesis "
                                                         "grandfather keeps in effect (idempotent)")
        m_forget.add_argument("--check", action="store_true",
                              help="Write nothing: list the facts that depend on such a forget; exit 0 only if none")
    group_parser = subparsers.add_parser("group", help="Membership lifecycle (owner-only): admit/revoke/deny/change/purge/retire/list")
    group_sub = group_parser.add_subparsers(dest="group_action")
    if control:
        g_admit = group_sub.add_parser("admit", help="Admit a device; no arg lists pending requests")
        g_admit.add_argument("device_id", nargs="?", help="The peer's device_id (k1:…). Omit to list pending")
        g_admit.add_argument("--principal", help="Tag the person or agent who owns this device")
        g_admit.add_argument("--module", help="Mark the device as module NAME's (2.1): it never votes in an election")
        _add_plan_flags(g_admit)
        g_revoke = group_sub.add_parser("revoke", help="Un-admit a device (reversible) → returns to STERILE")
        g_revoke.add_argument("device_id")
        _add_plan_flags(g_revoke)
        g_deny = group_sub.add_parser("deny", help="Reject a pending join-request (a later admit overrides)")
        g_deny.add_argument("device_id")
        g_change = group_sub.add_parser("change", help="Re-tag a device's principal (admission unchanged)")
        g_change.add_argument("device_id")
        g_change.add_argument("--principal", required=True, help="The new owner tag (person or agent)")
        g_purge = group_sub.add_parser("purge", help="Tombstone a compromised device (permanent; none of its content counts)")
        g_purge.add_argument("device_id")
        g_retire = group_sub.add_parser("retire", help="Tombstone an honest device but keep its past content (purge with keep_through)")
        g_retire.add_argument("device_id")
        g_retire.add_argument("--through", type=int, metavar="SEQ",
                              help="Keep the device's chain up to this seq (default: the highest seq this node holds)")
        g_retire.add_argument("--confirm", action="store_true",
                              help="Needed to retire a device that is already purged: its kept prefix counts again")
    group_sub.add_parser("list", help="Show the membership roster")

    join_parser = subparsers.add_parser("join", help="Request admission to this device's hive (after syncing it)")
    join_parser.add_argument("--principal", help="The person or agent this device should be tagged with (you)")

    config_parser = subparsers.add_parser("config", help="Settings: device identity + owner-signed confidence/quorum params")
    config_sub = config_parser.add_subparsers(dest="config_action")
    if control:
        # back-compat alias: `hv config set <key> <value>` == `hv config confidence set …`
        config_set = config_sub.add_parser("set", help="[alias] Set an owner-signed governed parameter")
        config_set.add_argument("key", help="a governed key, e.g. cap_self, importance_self_cap, capsule_putters "
                                            "(an unknown key lists them all)")
        config_set.add_argument("value", help="numeric value")
        config_set.add_argument("--non-interactive", action="store_true",
                                help="never ask for the owner passphrase or read stdin: exit 5 when the agent is "
                                     "absent, locked or refuses")
        _add_plan_flags(config_set)
    # canonical: identity (this device's key) + confidence (owner-signed hive params)
    config_id = config_sub.add_parser("identity", help="Show or mint this device's identity key")
    config_id_sub = config_id.add_subparsers(dest="config_identity_action")
    config_id_sub.add_parser("announce", help="Publish this device's signing key as a signed journal entry (makes it capsule-addressable)")
    config_id_sub.add_parser("show", help="Show this device's device_id and pubkey")
    config_id_init = config_id_sub.add_parser("init", help="Mint a device key (fresh install)")
    config_id_init.add_argument("--force", action="store_true", help="Replace an existing key / skip the populated-journal guard")
    for _name, _help in (("schema", "Print the governed and node-local key tables (types, defaults, ranges)"),
                         ("show", "Print every governed key's value, source and who set it last")):
        config_sub.add_parser(_name, help=_help).add_argument("--json", action="store_true", help="machine-readable output")
    config_node = config_sub.add_parser("node", help="Node-local keys of .peers.json (port, bind, sync_auth, ...): no owner key")
    config_node_sub = config_node.add_subparsers(dest="config_node_action")
    for _name, _help in (("list", "every node key with its value and source"), ("get", "one node key"),
                         ("set", "set one node key (the daemon re-reads at restart)")):
        _p = config_node_sub.add_parser(_name, help=_help)
        if _name != "list":
            _p.add_argument("key", help="port | bind | sync_auth | sync_auth_outbound | dashboard_share | dashboard_viewers | dashboard_viewer_port")
        if _name == "set":
            _p.add_argument("value")
        _p.add_argument("--json", action="store_true", help="machine-readable output")
    if control:
        config_conf = config_sub.add_parser("confidence", help="Set an owner-signed confidence parameter")
        config_conf_sub = config_conf.add_subparsers(dest="config_confidence_action")
        config_conf_set = config_conf_sub.add_parser("set", help="Set an owner-signed confidence, salience or trust parameter")
        config_conf_set.add_argument("key", help="e.g. same_device_lambda, cap_self, introspect_support_weight, "
                                                 "importance_self_cap, halflife_fact (an unknown key lists them all)")
        config_conf_set.add_argument("value", help="numeric value")
        _add_plan_flags(config_conf_set)
        config_quorum = config_sub.add_parser("quorum", help="Set an owner-signed quorum-election parameter")
        config_quorum_sub = config_quorum.add_subparsers(dest="config_quorum_action")
        config_quorum_set = config_quorum_sub.add_parser("set", help="Set quorum_m, quorum_by or dead_man_days")
        config_quorum_set.add_argument("key", help="quorum_m | quorum_by | dead_man_days")
        config_quorum_set.add_argument("value", help="value (quorum_m=int, quorum_by=device|principal, dead_man_days=float)")
        _add_plan_flags(config_quorum_set)

    discover_parser = subparsers.add_parser("discover", help="Scan the tailnet for hives (Tailscale + /hive/info probe)")
    discover_parser.add_argument("--format", choices=["text", "json"], default="text")

    nudge_parser = subparsers.add_parser("nudge", help="Emit a best-effort save/audit nudge (for hooks)")
    nudge_parser.add_argument("--event", required=True,
                              choices=["user-prompt", "precompact", "sessionend", "session-start"])
    nudge_parser.add_argument("--session", default="", help="Session id (debounce state)")
    nudge_parser.add_argument("--cwd", default="", help="cwd for the session-start project digest")
    nudge_parser.add_argument("--agent", default="agent", help="stable agent label for the spec-update marker")

    audit_parser = subparsers.add_parser("audit", help="Surface redundant/obsolete/missing facts")
    audit_parser.add_argument("--depth", choices=["light", "normal", "deep"], default=None)
    audit_parser.add_argument("--session", default="", help="Session id (enables the MISSING proxy)")
    audit_parser.add_argument("--format", choices=["text", "json"], default="text")

    sync_parser = subparsers.add_parser("sync", help="Sync with peers (P2P)")
    sync_subparsers = sync_parser.add_subparsers(dest="sync_action")
    sync_subparsers.add_parser("now", help="One-shot bidirectional sync with all peers")
    sync_subparsers.add_parser("daemon", help="Run the sync daemon (serve + periodic sync)")
    sync_auth_p = sync_subparsers.add_parser(
        "auth", help="Show or set this node's sync read-auth mode (off|permissive|enforce), and with "
                     "--outbound what it requires of a peer's signed hello before pushing to it")
    sync_auth_p.add_argument("mode", nargs="?", choices=["off", "permissive", "enforce"],
                             help="omit to show the current modes; set to change it (restart the daemon to apply)")
    sync_auth_p.add_argument("--outbound", choices=["off", "permissive", "enforce"], default=None,
                             help="set the outbound mode (#107): enforce pushes only to a peer whose hello "
                                  "verified; applies from the next sync round")

    tel_parser = subparsers.add_parser("telemetry", help="Removed in 4.0: session telemetry is the hwatch module (`hwatch telemetry`)")
    tel_parser.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    return parser


# Commands that read or incrementally write store.db, so they need it current first (#70).
_STORE_COMMANDS = {"remember", "search", "decide", "propose", "retract", "entity", "stats", "audit", "nudge"}


def main():
    if sys.argv[1:2] and sys.argv[1] in _REMOVED_VERBS:
        # Whatever follows the removed verb (argparse would reject a bare `--print`) gets the pointer, not a usage error.
        return removed_verb_cmd(argparse.Namespace(command=sys.argv[1]))
    args = build_parser(plane="data").parse_args(sys.argv[1:])
    return dispatch(args)


def _refuse_policy(key):
    """A current verb refused by hive policy (`capsule_putters=owner`, `cell_writers=owner`): say what the
    policy needs and where to run it. Exit 2, acting on nothing, so no script mistakes it for success."""
    print(commandmap.policy_text(key), file=sys.stderr)
    return commandmap.POLICY_EXIT


def dispatch(args):
    """Run the parsed command. Split out of `main` so the control plane (`hivemind_ctl.py`) can reach the
    library's command table without re-implementing it — the flags are defined once, in `build_parser`,
    and the routing once, here. 2.0 (#136): the owner-signed handlers move to the control plane in the
    split; this function is what both planes call in the meantime.

    The store prologue lives HERE rather than in `main`, so a caller that is not the `hv` CLI cannot skip
    it. It was in `main` when `main` was the only entry point; the control plane calling `dispatch`
    directly then minted an owner key against an uninitialised store."""
    try:
        return _dispatch(args)
    except NotOnDataPlane as e:            # an owner-signed step reached on the data plane (S2)
        return _refuse_policy(e.key)
    except JournalLockError as e:          # #253: one line naming cause and remedy, not a traceback
        print(str(e), file=sys.stderr)
        return 1


def _dispatch(args):
    # Idempotent; also auto-migrates older DBs missing tables/indexes.
    # `hv doctor rebuild` builds a new store from the journal and reads nothing of the old one, so it skips this.
    from_scratch = args.command == "doctor" and getattr(args, "doctor_action", None) == "rebuild"
    try:
        if not from_scratch:
            init_db()
    except NewerStoreSchema as e:
        if args.command != "doctor":          # `hv doctor` reports it
            print(f"hv: {e}", file=sys.stderr)
            return 1
    if args.command in _STORE_COMMANDS:
        try:
            _ensure_store_current()   # #70: catch up after a deferred write or an out-of-band append
        except sqlite3.OperationalError as e:
            # Another writer holds the store past the busy timeout. Never let the catch-up kill a command:
            # a read proceeds on the store as it is, and a write has its own post-append guard.
            print(f"hv: the local store is busy and could not catch up ({e}); continuing on the store as it is",
                  file=sys.stderr)
    if args.command == "remember":
        remember(args)
    elif args.command == "search":
        _forget_migration_stderr_notice()
        search(args)
    elif args.command == "decide":
        decide(args)
    elif args.command == "propose":
        propose(args)
    elif args.command == "retract":
        retract(args)
    elif args.command == "unforget":
        unforget(args)
    elif args.command == "entity":
        entity(args)
    elif args.command == "stats":
        stats(args)
    elif args.command == "feed":
        _forget_migration_stderr_notice()
        feed(args)
    elif args.command == "version":
        version_cmd(args)
    elif args.command == "verify":
        return verify_cmd(args)
    elif args.command == "doctor":
        doctor_cmd(args)
    elif args.command == "wire":
        wire_cmd(args)
    elif args.command == "capsule":
        capsule_cmd(args)
    elif args.command == "owner":
        owner_cmd(args)
    elif args.command == "admit":
        _plan_or_run(args, "group admit", lambda: admit_cmd(args))
    elif args.command == "migrate":
        return migrate_cmd(args)
    elif args.command == "group" and args.group_action == "retire":
        group_retire_cmd(args)
    elif args.command == "group":
        _plan_or_run(args, f"group {args.group_action}", lambda: group_cmd(args))
    elif args.command == "join":
        join_cmd(args)
    elif args.command == "config":
        _plan_or_run(args, "config set" if args.config_action == "set"
                     else f"config {args.config_action} set", lambda: config_cmd(args))
    elif args.command == "discover":
        discover_cmd(args)
    elif args.command == "nudge":
        nudge(args)
    elif args.command == "audit":
        audit(args)
    elif args.command == "sync":
        sync_cmd(args)
    elif args.command in ("dash", "telemetry"):
        return removed_verb_cmd(args)
    elif args.command == "whoami":
        whoami_cmd(args)
    elif args.command == "peers":
        peers_cmd(args)
    else:
        # Unreachable through the CLI: argparse rejects an unknown subcommand before this. Explicit
        # rather than silent, because the control plane routes through here too and a typo in its own
        # translation table would otherwise look like a command that did nothing.
        print(f"hv: unknown command {getattr(args, 'command', None)!r}", file=sys.stderr)
        return 2


