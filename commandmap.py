"""Which commands belong to the control plane, in one table (2.0, public #136; a routing table since 3.0).

The split gives `hv` (the agent data plane) and `hive-mind` (the owner/operator control plane) a shared
problem: `hive-mind` must route exactly the commands `hv` does not have. If that list lived in two places
they would drift, so this is the single source of truth, read by `hivemind_ctl` and by the tests.

Since 3.0 `hv` no longer names these commands. Its parser (`build_parser(plane="data")`) does not define
them, so a control-plane command typed on `hv` is argparse's unknown command: exit 2, nothing written. A test
asserts every entry is reachable in the control plane and refused by the data-plane parser.

Deliberately importable by `hv`: it holds no secret, reads no configuration, and imports nothing. It is
a table. The module `hv` must NOT import is `ownerkey`, and nothing here reaches it.

Each entry maps the `hv`-shaped argv prefix to the `hive-mind` argv prefix that implements it.
"""

# (argv prefix as typed on the control plane) -> (the library argv prefix, one-line why)
#
# Every target here must resolve to a real command on the control plane, and a test walks the library's
# actual subparsers to prove it. `owner mint` joined in 2b, with the subcommand that implements it:
# advertising a command that does not exist is the failure this table exists to prevent, and it is worse
# than the command being missing, because the operator is told to type something that cannot work.
CONTROL_PLANE = {
    # Owner identity and governance — every one of these produces an owner signature.
    ("owner", "init"):              ("owner init",              "mints and claims the owner key"),
    ("owner", "export"):            ("owner export",            "reads the owner key"),
    ("owner", "import"):            ("owner import",            "installs an owner key"),
    ("owner", "standby"):           ("owner standby",           "owner-signed"),
    ("owner", "escrow"):            ("owner escrow",            "reads and seals the owner key"),
    ("owner", "restore"):           ("owner restore",           "installs an owner key"),
    ("owner", "nominate"):          ("owner nominate",          "owner-signed"),
    ("owner", "unnominate"):        ("owner unnominate",        "owner-signed"),
    ("owner", "claim"):             ("owner claim",             "installs an owner key"),
    ("owner", "transfer"):          ("owner transfer",          "owner-signed"),
    ("owner", "revoke-escrow"):     ("owner revoke",            "owner-signed; S5 renames it here"),
    ("owner", "heartbeat"):         ("owner heartbeat",         "owner-signed"),
    ("owner", "freeze-timestamps"): ("owner freeze-timestamps", "owner-signed"),
    ("owner", "pin"):               ("owner pin",               "operator state: the genesis pin"),
    ("owner", "mint"):              ("owner mint",              "mints owner-key material; propose it "
                                                                "with `hv owner propose-election --pub`"),
    ("owner", "seal"):              ("owner seal",              "reads the owner key and writes it sealed"),

    # Membership. `hv admit` was already an alias; it resolves to the group form on the control plane.
    ("admit",):                     ("group admit",             "owner-signed"),
    ("group", "admit"):             ("group admit",             "owner-signed"),
    ("group", "revoke"):            ("group revoke",            "owner-signed"),
    ("group", "deny"):              ("group deny",              "owner-signed"),
    ("group", "change"):            ("group change",            "owner-signed"),
    ("group", "purge"):             ("group purge",             "owner-signed"),
    ("group", "retire"):            ("group retire",            "owner-signed"),

    # Governed configuration. The three ways to set a value collapse to one here.
    ("config", "set"):              ("config set",              "owner-signed"),
    ("config", "confidence", "set"): ("config set",             "owner-signed; collapsed into `config set`"),
    ("config", "quorum", "set"):    ("config set",              "owner-signed; collapsed into `config set`"),

    # One-time migrations (release 3.0): the re-issues are owner-signed.
    ("migrate", "forget"):          ("migrate forget",          "owner-signed; re-issues the grandfathered forgets"),

    # Owner acts on content. `hv retract` without --owner stays: that is peer evidence, not governance.
    ("unforget",):                  ("unforget",                "owner-signed"),
}

# Reads and device-signed acts that deliberately STAY on `hv`, with the reason. Not a pointer table —
# a statement of intent, so a later refactor does not "tidy" one of these into the control plane and
# take a capability with it.
STAYS = {
    ("owner", "show"):              "a read",
    ("owner", "elections"):         "a read",
    ("owner", "propose-election"):  "DEVICE-signed: an admitted member must be able to propose when the "
                                    "owner has gone dark, on a node that has only hv",
    ("owner", "vote"):              "DEVICE-signed: same reason. NOTE the CLI verb is `vote`; "
                                    "`vote-election` is the JOURNAL ACTION name, and using it here made "
                                    "the dead-man guard vacuous",
    ("group", "list"):              "a read",
    ("config", "schema"):           "a read",
    ("config", "show"):             "a read",
    ("retract",):                   "peer negative evidence; only --owner is governance",
    ("doctor",):                    "read-only checks, and the peer-address repoint is data-plane self-heal",
}

# Verbs that stay on `hv` but are refused by a hive POLICY (`capsule_putters=owner`, `cell_writers=owner`):
# the handler reads the hive's config, so the refusal cannot be a parser fact. `policy_text` explains it.
FLAG_CONDITIONAL = {
    "capsule put (capsule_putters=owner)": ("capsule put", "owner-signed under that policy; reads and "
                                                          "fertile puts stay on hv"),
    "capsule rotate (capsule_putters=owner)": ("capsule rotate", "owner-signed under that policy"),
    "capsule rm (capsule_putters=owner)": ("capsule rm", "owner-signed under that policy"),
    "wire --add (cell_writers=owner)": ("wire --add", "owner-signed under that policy"),
    "doctor --fix (key perms, genesis pin)": ("doctor --fix", "operator state: the owner key's permissions "
                                                             "and the genesis pin. `hv doctor --fix` keeps "
                                                             "every data-plane repair, the device key's "
                                                             "permissions included, and points at this"),
}

# Data-plane verbs the control plane ALSO accepts, for the owner-signed form of the links they write
# (decision h:34cc1dbcd3). Through `hv` their links are device-signed; through `hive-mind`, with source
# `manual`, they are owner-signed (#114). Not pointers: `hv` keeps running them.
OWNER_LINK_VERBS = ("remember", "decide", "entity")

POLICY_EXIT = 2


def policy_text(key):
    """What `hv` prints when an owner-signed step is refused on the data plane: for a policy key, the policy
    and where to run it; for any other step, that `hv` cannot sign it. Names what the operator needs next."""
    if key in FLAG_CONDITIONAL and "(" in key:
        verb, policy = key.split(" (", 1)
        policy = policy.rstrip(")")
        return (f"`hv {verb}` needs an owner-signed write on this hive (`{policy}`).\n"
                f"  Run it on the owner machine with `hive-mind {FLAG_CONDITIONAL[key][0]}`.")
    return "`hv` is the agent data plane and cannot owner-sign this step; see docs/HV_ARCHITECTURE.md."


def lookup(argv):
    """The longest matching CONTROL_PLANE prefix for an argv, or None. Longest-first so `config confidence set`
    is not shadowed by `config set`."""
    for n in (3, 2, 1):
        key = tuple(argv[:n])
        if key in CONTROL_PLANE:
            return key, CONTROL_PLANE[key]
    return None
