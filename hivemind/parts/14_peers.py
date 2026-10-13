def _prune_ended_peers_after_rebuild():
    """The projection just replayed the journal: a revoke or purge in it now ends that device as a listed peer.
    Best-effort and cheap when there is nothing to do (no .peers.json, or no peer in it)."""
    try:
        if (HIVE_HOME / ".peers.json").exists():
            _prune_ended_peers(_governance_state(merkle.read_all_entries(JOURNAL_DIR)))
    except Exception:
        pass


def _ended_devices(gov):
    """Devices an honoured revoke or purge has ended: revoked and not re-admitted, or purged (a purge is final).
    Empty before an owner exists, since without one nothing is honoured."""
    if not gov.get("owner_id"):
        return set()
    return set(gov.get("purged") or ()) | (set(gov.get("revoked") or ()) - set(gov.get("admitted") or ()))


def _peer_bound_device(peer):
    """The device id a .peers.json entry is bound to, else None: the node-local `device` field
    `group admit --principal` records beside the principal, else an `id` that is itself a device id (k1:…)."""
    for key in ("device", "id"):
        v = str(peer.get(key) or "")
        if _is_device_id(v):
            return v
    return None


def _peer_ended_device(peer, ended, cands=None, joins=None, admitted=()):
    """The ended device this .peers.json entry stands for, else None. An entry naming a device id is decided on
    that id alone, and so is an entry whose `device` field `group admit` recorded. An entry with neither (a hand-set
    one, or one written before that field existed) with a label other than a device id is matched to an ended device
    by that device's join-request URL, else by the host a signed request or hello once proved it at
    (.peer_candidates.json) when it is the only device verified there. Either match is dropped when an ADMITTED
    device (not ended) was verified at, or advertised, the same host: a reinstall at the old address keeps its
    entry. A join-request from a device outside `admitted` is only a claim and keeps nothing. A node-local judgement: no wire format involved (SECREV B6)."""
    if not ended or not isinstance(peer, dict):
        return None
    bound = _peer_bound_device(peer)
    if bound:
        return bound if bound in ended else None
    url = str(peer.get("url") or "")
    host = _url_host(url)
    if not host:
        return None
    cands = _load_peer_candidates() if cands is None else cands
    joins = _join_request_urls() if joins is None else joins
    live = ({d for d, hist in cands.items() if host in hist} | {d for d, u in joins.items() if _url_host(u) == host}) & set(admitted) - ended
    if live:
        return None
    by_url = sorted(d for d in ended if joins.get(d, "").rstrip("/") == url.rstrip("/"))
    if by_url:
        return by_url[0]
    here = [d for d, hist in cands.items() if host in hist]
    return here[0] if len(here) == 1 and here[0] in ended else None


def _live_peers(peers, gov):
    """`peers` without the entries of an ended device: this node sends such a device nothing, signed or not."""
    ended = _ended_devices(gov)
    if not ended:
        return list(peers)
    cands, joins, adm = _load_peer_candidates(), _join_request_urls(gov.get("ended_at")), gov.get("admitted") or ()
    return [p for p in peers if _peer_ended_device(p, ended, cands, joins, adm) is None]


def _prune_ended_peers(gov):
    """Drop the entries of a revoked or purged device from this node's .peers.json (SECREV B6). The signed request
    envelope names no audience, so every signed read this node sends a listed peer is one that peer can replay to
    a third node inside the freshness window; a device the owner ended must therefore stop being a listed peer.
    Returns the dropped device ids. A re-admitted device is re-added by the admission flow, not here."""
    path = HIVE_HOME / ".peers.json"
    ended = _ended_devices(gov)
    if not ended or not path.exists():
        return []
    try:
        cfg = json.loads(path.read_text())
        peers = cfg.get("peers") or []
        cands, joins, adm = _load_peer_candidates(), _join_request_urls(gov.get("ended_at")), gov.get("admitted") or ()
        gone = [(p, _peer_ended_device(p, ended, cands, joins, adm)) for p in peers]
        if not any(d for _p, d in gone):
            return []
        cfg["peers"] = [p for p, d in gone if d is None]
        _atomic_write_text(path, json.dumps(cfg, indent=2) + "\n")
    except (OSError, ValueError, AttributeError):
        return []
    dropped = sorted({d for _p, d in gone if d})
    print(f"hv: dropped {', '.join(dropped)} from .peers.json: the owner revoked or purged it", file=sys.stderr)
    return dropped


def _load_peer_candidates():
    """{device_id: {ip: {"first_seen": s, "last_seen": s}}} (epoch seconds) from PEER_CANDIDATES_PATH.
    {} when the file is absent or unreadable: it is advisory, so a bad one only means nothing learned."""
    try:
        devs = json.loads(PEER_CANDIDATES_PATH.read_text()).get("devices")
    except Exception:
        return {}
    out = {}
    for d, hist in (devs.items() if isinstance(devs, dict) else ()):
        recs = {ip: r for ip, r in (hist.items() if isinstance(hist, dict) else ())
                if isinstance(r, dict) and isinstance(r.get("last_seen"), int)}
        if recs:
            out[d] = recs
    return out


def _record_peer_candidate(device_id, ip, now=None, via=None):
    """Note that `device_id` verified itself from `ip`. The daemon calls this only after
    _verify_sync_request passed, the sync client only after a `verified` hello (#107, `via="outbound"`,
    kept on the record of that sighting); loopback is refused here too, since that is this device. Keeps
    the _PEER_CANDIDATES_PER_DEVICE most recent addresses per device, and writes nothing when nothing
    changed. Returns True when `ip` is new for that device."""
    import sync_common
    ip = str(ip or "")
    ip = ip[7:] if ip.startswith("::ffff:") else ip      # an IPv4 peer seen on a dual-stack socket
    if not device_id or not ip or sync_common.is_loopback(ip):
        return False
    now = int(time.time()) if now is None else int(now)
    cands = _load_peer_candidates()
    hist = cands.setdefault(device_id, {})
    rec = hist.get(ip)
    if rec is not None and rec["last_seen"] >= now and (not via or rec.get("via") == via):
        return False                                     # nothing new; a same-second sighting naming a new `via` still lands
    hist[ip] = {"first_seen": rec.get("first_seen", now) if rec else now,
                "last_seen": max(rec["last_seen"], now) if rec else now}
    via = via or (rec.get("via") if rec else None)       # a sighting that names no `via` keeps the earlier one
    if via:
        hist[ip]["via"] = via
    if len(hist) > _PEER_CANDIDATES_PER_DEVICE:
        keep = sorted(hist, key=lambda k: hist[k]["last_seen"], reverse=True)[:_PEER_CANDIDATES_PER_DEVICE]
        cands[device_id] = {k: hist[k] for k in keep}
    if len(cands) > _PEER_CANDIDATES_MAX_DEVICES:
        order = sorted(cands, key=lambda d: max(r["last_seen"] for r in cands[d].values()), reverse=True)
        cands = {d: cands[d] for d in order[:_PEER_CANDIDATES_MAX_DEVICES]}
    _atomic_write_text(PEER_CANDIDATES_PATH, json.dumps({"devices": cands}, indent=2, sort_keys=True) + "\n")
    return rec is None


def _is_device_id(s):
    return bool(re.fullmatch(r"k1:[0-9a-f]{16}", str(s or "")))


def _url_host(url):
    from urllib.parse import urlsplit
    try:
        return urlsplit(str(url or "")).hostname or ""
    except ValueError:
        return ""


def _url_with_host(url, ip):
    """`url` with only its host replaced by `ip`: scheme, port, path and any userinfo are kept."""
    from urllib.parse import urlsplit, urlunsplit
    u = urlsplit(url)
    netloc = (f"[{ip}]" if ":" in ip else ip) + (f":{u.port}" if u.port else "")
    if "@" in u.netloc:
        netloc = u.netloc.rsplit("@", 1)[0] + "@" + netloc
    return urlunsplit(u._replace(netloc=netloc))


def _peer_entry_device(entry, candidates):
    """The device a .peers.json entry points at, or None: its `id` when that is a device id (k1:…),
    else the ONE device verified at the entry's current host. Never a hostname or label: names are
    self-reported and collide (two devices named HP-cn2063cl on one hive)."""
    bound = _peer_bound_device(entry)
    if bound:
        return bound
    host = _url_host(entry.get("url"))
    here = [d for d, hist in candidates.items() if host and host in hist]
    return here[0] if len(here) == 1 else None


def _peer_address_verdict(host, answered, device, seen, since):
    """#7, pure: what the `peer-address` check says about ONE .peers.json entry. `host` is the entry's URL
    host, `answered` whether that URL answered doctor's probe, `device` the device the entry maps to
    (None when unknown), `seen` that device's verified sightings {ip: last_seen} and `since` the
    .peers.json mtime, since the stored binding is at least that recent. Returns (verdict, ip):
      ("ok", None)       the stored address answers; it is never rewritten, whatever `seen` holds
      ("move", ip)       it fails, and the device verified itself at `ip` after the stored binding
      ("report", None)   it fails, and no newer verified address is known for the device
      ("unknown", None)  it fails, and no device is known for the entry: report only, never rewrite"""
    if answered:
        return "ok", None
    if not device:
        return "unknown", None
    if not seen:
        return "report", None
    ip, last = max(seen.items(), key=lambda kv: (kv[1], kv[0]))
    if ip != host and last > max(seen.get(host, 0), since):
        return "move", ip
    return "report", None


def _tailscale_hosts():
    """[(name, [ipv4, …])] for the other devices on the tailnet, from `tailscale status --json` (its
    HostName and the first label of its DNSName). [] when the CLI is absent (Android/Termux has none),
    logged out or failing: the hints this feeds are optional, so that is never an error."""
    try:
        r = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5)
        out = []
        for p in ((json.loads(r.stdout) if r.returncode == 0 else {}).get("Peer") or {}).values():
            ips = [ip for ip in (p.get("TailscaleIPs") or []) if ":" not in str(ip)]
            for name in {str(p.get("HostName") or "").lower(), str(p.get("DNSName") or "").split(".")[0].lower()}:
                if name and ips:
                    out.append((name, ips))
        return out
    except Exception:
        return []


def _peer_hint_names(entry):
    """Lower-cased names a stale entry may go by on the tailnet, for the unverified hints only: its
    `label`, its `id` when that is not a device id, and its URL host when that is a name, not an IP."""
    import ipaddress
    names = {str(v).lower() for v in (entry.get("label"), entry.get("id")) if v and not _is_device_id(v)}
    host = _url_host(entry.get("url"))
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host:
            names.add(host.split(".")[0].lower())
    return names


_PEER_PROBE_MAX = 8          # candidate hosts the peer-address probe asks per failing entry (#107)
_PEER_PROBE_TIMEOUT = 3      # seconds per probe; an entry's probes run concurrently


def _hive_info_fetch(url, headers, timeout):
    """GET a /hive/info URL as JSON: the peer-address probe's one network call (tests replace it)."""
    import requests
    return requests.get(url, headers=headers or None, timeout=timeout).json()


def _peer_address_prover(gov):
    """#107: the peer-address probe, for an entry whose stored address FAILS and whose device is known
    with no newer verified sighting (verdict `report`), so a peer that never contacts this node can be
    found too. Returns prove(url, device, hosts): it asks up to _PEER_PROBE_MAX candidate hosts (`hosts`,
    then the device's join-request host), each with the entry's port, for a /hive/info signed over our
    nonce, and returns the first host whose answer is `verified` for exactly `device`: admitted and not
    purged once an owner exists, advertising the host:port asked. None otherwise: another device, an
    unsigned or invalid answer, a relay (its answer carries the real peer's address) or a purged device
    never qualifies. Records nothing; `--fix` applies the resulting move."""
    import concurrent.futures
    import sync_common

    def proves(base, device):
        hdrs = _probe_headers("/hive/info")
        if not hdrs:
            return False                     # no device key: nothing for a responder to sign over
        try:
            info = _hive_info_fetch(base + "/hive/info", hdrs, _PEER_PROBE_TIMEOUT)
        except Exception:
            return False
        v = sync_common.verify_hello(info, hdrs.get("Hive-Auth-Nonce"), "/hive/info", base, gov, device)
        return v["outcome"] == "verified" and v["device"] == device and not v["other_device"]

    def prove(url, device, hosts):
        stored, order = _url_host(url), []
        for h in list(hosts) + [_url_host(_join_request_url(device))]:
            if h and h != stored and h not in order:
                order.append(h)
        order = order[:_PEER_PROBE_MAX]
        if not order:
            return None
        base = str(url).rstrip("/")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(order)) as ex:
            ok = list(ex.map(lambda h: proves(_url_with_host(base, h), device), order))
        return next((h for h, good in zip(order, ok) if good), None)
    return prove


def _peer_identity_check(peers, identity, mode):
    """#107, pure: the advisory `peer-identity` check. `identity` maps each ANSWERING .peers.json entry's
    base URL to what its signed /hive/info proved (_probe_peer_map), `mode` is the outbound auth mode.
    Names each peer still below protocol 3 and each whose answer is not `verified` for its entry
    (invalid, another device than its `id`, addr-unproven, unadmitted, purged, unsigned at protocol 3),
    and says whether every configured peer is ready for inbound enforce (answers at protocol >= 2) and
    for outbound enforce (answers verified): the all-upgraded green light. Warns on a peer that is not
    merely pre-upgrade, or on a pre-upgrade one while outbound enforce holds its push. Never acted on."""
    old, odd, n_ok, silent = [], [], 0, 0
    in_ready = out_ready = True
    for p in peers:
        url = str(p.get("url", "")).rstrip("/")
        if not url:
            continue
        where, r = url.split("://", 1)[-1], identity.get(url)
        if not r:
            silent += 1
            in_ready = out_ready = False
            continue
        pv = r.get("protocol_version") if isinstance(r.get("protocol_version"), int) else 0
        good = r["outcome"] == "verified" and not r["other_device"]
        in_ready, out_ready = in_ready and pv >= 2, out_ready and good
        if good:
            n_ok += 1
        elif r["outcome"] == "unsigned" and pv < 3:
            old.append(f"{where} (protocol {pv or '?'})")
        elif r["other_device"]:
            odd.append(f"{where} answered as {r['device'][:11]}…, not the device its entry names")
        else:
            odd.append(f"{where} {r['outcome']} ({r['reason']})")
    bits = [f"outbound {mode}", f"{n_ok} peer(s) verified"]
    if old:
        bits.append(f"{len(old)} before protocol 3, unsigned: {', '.join(old)}")
    if odd:
        bits.append("not verified: " + ", ".join(odd))
    if silent:
        bits.append(f"{silent} not answering (no verdict)")
    bits.append(f"ready for `hv sync auth enforce`: {'yes' if in_ready else 'no'}, "
                f"for `hv sync auth --outbound enforce`: {'yes' if out_ready else 'no'}")
    warn = bool(odd) or (mode == "enforce" and bool(old))
    return {"name": "peer-identity", "status": "warn" if warn else "ok", "detail": "; ".join(bits)}


def _peer_address_check(peers, answered, candidates, since, tailscale_hosts=None, prove=None):
    """#7: the `peer-address` doctor check over the .peers.json `peers` list. `answered` maps each entry's
    base URL to whether it answered the `peers` probe (so there is no second round of network calls; an
    entry missing from it counts as answering and is left alone), `candidates` is _load_peer_candidates()
    and `since` the .peers.json mtime. `tailscale_hosts` supplies the unverified hints and is called
    only when an unreachable entry has no verified address. `prove` (_peer_address_prover, #107) is asked
    only for a `report` entry: its tailscale hints and its other sightings, newest first, are the hosts it
    tries. The check's `moves` are what `--fix` applies."""
    moves, lines, quiet, n_ok, hosts = [], [], 0, 0, None
    for i, p in enumerate(peers):
        url = str(p.get("url", "")).rstrip("/")
        if not url:
            continue
        host, where = _url_host(url), url.split("://", 1)[-1]
        device = _peer_entry_device(p, candidates)
        seen = {ip: r["last_seen"] for ip, r in (candidates.get(device) or {}).items()}
        verdict, ip = _peer_address_verdict(host, answered.get(url, True), device, seen, since)
        if verdict == "ok":
            n_ok += 1
            continue
        if verdict == "move":
            moves.append({"index": i, "device": device, "url": p.get("url"), "to": _url_with_host(p.get("url"), ip)})
            lines.append(f"peer {device[:11]}… unreachable at {where}, verified at {ip} — `hv doctor --fix` repoints it")
            continue
        if hosts is None:
            hosts = (tailscale_hosts() if tailscale_hosts else None) or []
        names = _peer_hint_names(p)
        if verdict == "report" and prove:
            ip = prove(p.get("url"), device, [h for name, ips in hosts if name in names for h in ips]
                       + sorted(seen, key=lambda h: seen[h], reverse=True))
            if ip:
                moves.append({"index": i, "device": device, "url": p.get("url"), "to": _url_with_host(p.get("url"), ip)})
                lines.append(f"peer {device[:11]}… unreachable at {where}, proved itself at {ip} (signed "
                             f"/hive/info) — `hv doctor --fix` repoints it")
                continue
        hints = sorted({f"{h} ({name})" for name, ips in hosts if name in names for h in ips if h != host})
        if not hints:
            quiet += 1
            continue
        who = f"peer {device[:11]}… unreachable at {where}, no newer verified address" if device \
            else f"{where} unreachable, no known device for this entry"
        lines.append(f"{who}; unverified tailscale hint(s) by name, not acted on: {', '.join(hints)}")
    if not lines:
        detail = f"{n_ok} stored peer address(es) answer"
        if quiet:
            detail += f"; {quiet} unreachable with no newer verified address (nothing to repoint)"
        return {"name": "peer-address", "status": "ok", "detail": detail, "moves": []}
    return {"name": "peer-address", "status": "warn", "detail": "; ".join(lines), "moves": moves}


def _repoint_peers(path, moves):
    """Apply peer-address `moves` to the .peers.json at `path`. Each changes ONE entry's `url` (host only)
    and nothing else: every other key of that entry and of the file, known or not, keeps its value and
    its order. The file is re-read first, and a move whose entry no longer holds the URL the check saw
    (edited meanwhile) is skipped. Atomic. Returns the moves applied."""
    cfg = json.loads(Path(path).read_text())
    peers = cfg.get("peers") if isinstance(cfg, dict) else None
    done = []
    for m in moves:
        i = m["index"]
        if isinstance(peers, list) and 0 <= i < len(peers) and isinstance(peers[i], dict) \
                and peers[i].get("url") == m["url"]:
            peers[i]["url"] = m["to"]
            done.append(m)
    if done:
        _atomic_write_text(path, json.dumps(cfg, indent=2) + "\n")
    return done


