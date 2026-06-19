"""Per-check parsers. Each binds to a catalog id and returns a CheckResult.

A parser receives `out`: {command: raw_text} for that check's commands, plus the
DeviceInfo. Register new ones with @parser("<id>"). Unregistered checks fall
back to a generic capture (raw shown, INFO verdict).
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Callable, Dict

from .connectors.base import DeviceInfo
from .verdict import CheckResult, Status

_REGISTRY: Dict[str, Callable] = {}
CERT_WARN_DAYS = 30


def _age_days(date_str: str, dev=None):
    d = _parse_date(date_str)
    return (_now(dev) - d).days if d else None


def _now(dev=None) -> _dt.datetime:
    """Verdict reference clock: the device's own clock when known (correct for
    its cert/license validation), else this host's time."""
    n = getattr(dev, "now", None) if dev is not None else None
    return n or _dt.datetime.now()


def parser(check_id: str):
    def deco(fn: Callable) -> Callable:
        _REGISTRY[check_id] = fn
        return fn
    return deco


def get_parser(check_id: str) -> Callable:
    return _REGISTRY.get(check_id, _generic)


def _first(out: Dict[str, str]) -> str:
    return next(iter(out.values()), "")


def _generic(meta, out, dev):
    raw = "\n".join(out.values())
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    r.status = Status.INFO
    r.headline = "Captured" if raw.strip() else "No output"
    return r


# --------------------------------------------------------------------------
@parser("version_model")
def _version_model(meta, out, dev: DeviceInfo):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    r.m("Model", dev.model); r.m("Version", dev.full_version or dev.version)
    r.m("Serial", dev.serial); r.m("Hostname", dev.hostname)
    supported = dev.version in ("7.4", "7.6", "8.0")
    r.status = Status.PASS if supported else Status.WARN
    r.headline = (f"{dev.model} {dev.version}" if supported
                  else f"{dev.version} outside supported set (7.4/7.6/8.0)")
    return r


@parser("resources")
def _resources(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    if not re.search(r"Memory:", raw):
        r.status, r.headline = Status.INFO, "Could not read performance status"
        return r
    mem = re.search(r"used\s*\(([\d.]+)%\)", raw)
    conserve = re.search(r"conserve mode:\s*(\w+)", raw)
    cpu_idle = re.search(r"(\d+)%\s*idle", raw)
    mem_pct = float(mem.group(1)) if mem else 0.0
    r.m("Memory used", f"{mem_pct:.0f}%")
    if cpu_idle:
        r.m("CPU", f"{100 - int(cpu_idle.group(1))}% busy")
    if conserve:
        r.m("Conserve mode", conserve.group(1))
    if conserve and conserve.group(1).lower() != "off":
        r.status, r.headline = Status.FAIL, "Conserve mode ACTIVE - memory pressure"
    elif mem_pct >= 88:
        r.status, r.headline = Status.WARN, f"Memory high ({mem_pct:.0f}%)"
    else:
        r.status, r.headline = Status.PASS, f"Memory {mem_pct:.0f}%, conserve off"
    return r


@parser("fortiguard")
def _fortiguard(meta, out, dev):
    raw = "\n".join(out.values())
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    now = _now(dev)
    fds = re.search(r"FDS Connection:\s*(\w+)", raw)
    if not fds and "Contract Expiry" not in raw:
        r.status, r.headline = Status.INFO, "Could not parse FortiGuard status"
        return r
    worst = Status.PASS
    soon = []
    for mod, exp in re.findall(r"^([A-Za-z][\w /]+?)\s*\n-+\n(?:.*\n)*?.*Contract Expiry Date:\s*(.+)$",
                               raw, re.MULTILINE):
        mod = mod.strip()
        exp = exp.strip()
        if exp.lower() == "expired":
            r.m(mod, "EXPIRED"); worst = Status.FAIL; soon.append(mod)
            continue
        d = _parse_date(exp)
        if d:
            days = (d - now).days
            r.m(mod, f"{days}d")
            if days < 0:
                worst = Status.FAIL; soon.append(mod)
            elif days <= CERT_WARN_DAYS and worst != Status.FAIL:
                worst = Status.WARN; soon.append(mod)
    if fds:
        r.m("FDS", fds.group(1))
        if fds.group(1).lower() != "available":
            worst = Status.FAIL
    r.status = worst
    r.headline = ("All licenses healthy, FDS available" if worst == Status.PASS
                  else f"Attention: {', '.join(soon) or 'FDS'}")
    return r


@parser("certificates")
def _certificates(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    now = _now(dev)
    worst, flagged = Status.PASS, []
    blocks = re.split(r"^Name:\s*", raw, flags=re.MULTILINE)[1:]
    if not blocks:
        r.status, r.headline = Status.INFO, "No certificates parsed"
        return r
    for b in blocks:
        name = b.splitlines()[0].strip()
        role = _cert_role(name, b)
        to = re.search(r"Valid to:\s*([\d-]+)", b)
        if not to:
            continue
        d = _parse_date(to.group(1))
        if not d:
            continue
        days = (d - now).days
        r.m(f"{name} ({role})", f"{days}d")
        if days < 0:
            worst, _ = Status.FAIL, flagged.append(f"{name} EXPIRED")
        elif days <= CERT_WARN_DAYS:
            if worst != Status.FAIL:
                worst = Status.WARN
            flagged.append(f"{name} in {days}d")
    r.status = worst
    r.headline = ("All certificates >30d valid" if worst == Status.PASS
                  else "; ".join(flagged))
    return r


def _cert_role(name: str, block: str) -> str:
    n = name.lower()
    if "ssl" in n or "inspect" in n or "deep" in n:
        return "SSL-inspection"
    if "vpn" in n or "portal" in n or "gw" in n or "gateway" in n:
        return "remote-gateway"
    return "device"


@parser("hw_certificate")
def _hw_certificate(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    if not raw.strip():
        r.status, r.headline = Status.INFO, "No output"
        return r
    low = raw.lower()
    valid_to = re.search(r"valid to\s*:\s*([\d-]+)", raw, re.I)
    if valid_to:
        r.m("Valid to", valid_to.group(1))
        d = _parse_date(valid_to.group(1))
        if d:
            r.m("Days left", str((d - _now(dev)).days))
    failed = re.search(r"\b(failed|fail|invalid|expired|not valid|revoked|error)\b", low)
    passed = re.search(r"\b(passed|pass|valid|verified|ok)\b", low)
    if failed:
        r.status, r.headline = Status.FAIL, "Hardware/factory certificate problem"
    elif passed:
        r.status, r.headline = Status.PASS, "Hardware/factory certificate OK (all checks passed)"
    else:
        r.status, r.headline = Status.INFO, "Captured (define verdict from real output)"
    return r

@parser("interfaces")
def _interfaces(meta, out, dev):
    raw = "\n".join(out.values())
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    phys = out.get("get system interface physical", "")
    port_ip = {}
    for m in re.finditer(r"name:\s*(\S+).*?ip:\s*(\d+\.\d+\.\d+\.\d+)", phys):
        port_ip[m.group(1)] = m.group(2)
    addressed = {p for p, ip in port_ip.items() if ip != "0.0.0.0"}
    nic = {k.split()[-1]: v for k, v in out.items()
           if k.startswith("diagnose hardware deviceinfo nic ")}

    def _f(blk, pat):
        m = re.search(pat, blk)
        return m.group(1) if m else ""

    def _err(blk):
        rx = re.search(r"Rx_Errors\s*:\s*(\d+)", blk)
        tx = re.search(r"Tx_Errors\s*:\s*(\d+)", blk)
        return (int(rx.group(1)) if rx else 0) + (int(tx.group(1)) if tx else 0)

    if not nic:
        down = [p for p in addressed
                if re.search(r"name:\s*" + re.escape(p) + r"\b.*?link:\s*down", phys, re.DOTALL)]
        r.m("Addressed ports", len(addressed))
        r.headline = ("Hardware NIC detail unavailable (needs diagnose); "
                      + ("addressed link down: " + ", ".join(down) if down
                         else "no link faults via admin view"))
        r.status = Status.WARN if down else Status.INFO
        return r

    bad = []
    for port in sorted(addressed):
        blk = nic.get(port, "")
        link = _f(blk, r"link_status\s*:\s*(\w+)").lower()
        duplex = _f(blk, r"Duplex\s*:\s*(\w+)").lower()
        speed = _f(blk, r"Speed\s*:\s*(\d+)")
        speed_i = int(speed) if speed.isdigit() else 0
        reasons = []
        if link != "up":
            reasons.append("link down")
        if duplex and duplex != "full":
            reasons.append(duplex + "-duplex")
        if speed_i < 1000:
            reasons.append((str(speed_i) if speed_i else "?") + "Mbps")
        if reasons:
            bad.append(port + " (" + ", ".join(reasons) + ")")
    r.m("Physical ports", len(nic))
    r.m("Addressed ports", len(addressed))
    err_ports = [p + "(" + str(_err(b)) + ")" for p, b in nic.items() if _err(b) > 0]
    if err_ports:
        r.m("Ports with rx/tx errors", ", ".join(err_ports))
    if bad:
        r.status, r.headline = Status.WARN, "Addressed ports not up/1000full: " + "; ".join(bad)
    else:
        r.status, r.headline = Status.PASS, str(len(addressed)) + " addressed port(s) up at 1000/full"
    return r

@parser("routing")
def _routing(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    has_default = bool(re.search(r"^\S*\s*0\.0\.0\.0/0", raw, re.MULTILINE))
    blackhole = re.findall(r"^\S.*(?:Null0|blackhole)", raw, re.MULTILINE)
    routes = len([l for l in raw.splitlines() if re.match(r"^[KCSBOR]\*?\s", l)])
    r.m("Routes", routes); r.m("Default route", "yes" if has_default else "NO")
    r.m("Blackhole routes", len(blackhole))
    if not has_default:
        r.status, r.headline = Status.WARN, "No default route present"
    elif blackhole:
        r.status, r.headline = Status.INFO, f"{len(blackhole)} blackhole route(s) (intentional?)"
    else:
        r.status, r.headline = Status.PASS, f"{routes} routes, default present"
    return r


@parser("dynamic_routing")
def _dynamic_routing(meta, out, dev):
    raw = "\n".join(out.values())
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    if not re.search(r"Neighbor|OSPF|BGP router", raw, re.I):
        r.status, r.headline = Status.INFO, "No BGP/OSPF output (not configured or unreadable)"
        return r
    bad = []
    for nb, state in re.findall(r"^(\d+\.\d+\.\d+\.\d+)\s+4\s+\d+.*?\s(\S+)\s*$", raw, re.MULTILINE):
        if state.isdigit():
            continue  # established (prefix count)
        bad.append(f"BGP {nb} {state}")
    for m in re.finditer(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)", raw, re.MULTILINE):
        st = m.group(2)
        if "/" in st and not st.startswith("Full"):
            bad.append(f"OSPF {m.group(1)} {st}")
    r.m("Adjacency issues", len(bad))
    if bad:
        r.status, r.headline = Status.WARN, "; ".join(bad[:4])
    else:
        r.status, r.headline = Status.PASS, "All adjacencies up"
    return r


@parser("ntp")
def _ntp(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    m = re.search(r"synchronized:\s*(\w+)", raw)
    sync = (m.group(1).lower() == "yes") if m else False
    r.m("Synchronized", "yes" if sync else "no")
    r.status = Status.PASS if sync else Status.WARN
    r.headline = ("Clock synchronized" if sync
                  else "NTP NOT synchronized - breaks certs/SAML/HA/log correlation")
    return r


@parser("ha")
def _ha(meta, out, dev):
    raw = "\n".join(out.values())
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    if re.search(r"mode:\s*standalone", raw, re.I):
        r.status, r.headline = Status.INFO, "Standalone (no HA)"
        return r
    if not re.search(r"HA Health|Configuration Status|is_manage_master|checksum", raw, re.I):
        r.status, r.headline = Status.INFO, "Could not read HA status"
        return r
    out_of_sync = re.findall(r"(\S+?)\(updated[^)]*\):\s*out-of-sync", raw)
    r.m("Members out-of-sync", len(out_of_sync))
    # HA event history (diagnose sys ha history read): count recent transitions
    hist = out.get("diagnose sys ha history read", "")
    events = re.findall(r"<(\d{4}-\d{2}-\d{2})[^>]*>\s*(.+)", hist)
    primary_changes = [d for d, txt in events if "selected as the primary" in txt.lower()]
    recent = [d for d in primary_changes if _age_days(d, dev) is not None and _age_days(d, dev) <= 7]
    if events:
        r.m("HA events logged", len(events))
        if primary_changes:
            r.m("Last role change", primary_changes[0])
    if out_of_sync:
        r.status = Status.FAIL
        r.headline = f"HA OUT-OF-SYNC: {', '.join(out_of_sync)} (checksum mismatch)"
    elif recent:
        r.status = Status.WARN
        r.headline = f"HA in-sync but {len(recent)} primary change(s) in last 7d (last {primary_changes[0]})"
    else:
        r.status, r.headline = Status.PASS, "HA in-sync"
    return r


@parser("policy_hitcount")
def _policy_hitcount(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    total = re.findall(r"idx=(\d+)", raw)
    if not total:
        r.status, r.headline = Status.INFO, "No policy rows parsed"
        return r
    dead = re.findall(r"idx=(\d+)\s+pkts/bytes=0/0\s+hit count:0", raw)
    r.m("Policies seen", len(total)); r.m("Dead (hit-count 0)", len(dead))
    if dead:
        r.status = Status.WARN
        r.headline = f"{len(dead)} dead policies (idx {', '.join(dead)}) - candidates to remove/reorder"
    else:
        r.status, r.headline = Status.PASS, "No dead policies"
    return r


@parser("dns")
def _dns(meta, out, dev):
    cfg = out.get("get system dns", "")
    proxy = out.get("diagnose test application dnsproxy 3", "")
    ping = next((v for k, v in out.items() if k.startswith("execute ping")), "")
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw="\n".join(out.values()))
    prim = re.search(r"primary\s*:\s*(\S+)", cfg)
    sec = re.search(r"secondary\s*:\s*(\S+)", cfg)
    dot = re.search(r"dns-over-tls\s*:\s*(\S+)", cfg)
    if prim:
        r.m("Primary", prim.group(1))
    if sec and sec.group(1) not in ("0.0.0.0", ""):
        r.m("Secondary", sec.group(1))
    if dot:
        r.m("DNS-over-TLS", dot.group(1))
    # Server readiness from dnsproxy 3 (GLOBAL command; output is per-VDOM).
    ready = total_srv = None
    if proxy.strip() and "ready=" in proxy:
        rts, fails, total_srv, ready = [], 0, 0, 0
        for line in proxy.splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+vrf=", line)
            if not m:
                continue
            total_srv += 1
            rd = re.search(r"ready=(\d+)", line)
            if rd and rd.group(1) == "1":
                ready += 1
            rt = re.search(r"\brt=(\d+)", line)
            if rt:
                rts.append(int(rt.group(1)))
            lf = re.search(r"last_failed=(\d+)", line)
            if lf and int(lf.group(1)) > 0:
                fails += 1
        r.m("DNS servers ready", str(ready) + "/" + str(total_srv))
        if rts:
            r.m("Best RTT", str(min(rts)) + "ms")
        if fails:
            r.m("Servers with recent failures", str(fails))
    loss = re.search(r"(\d+)%\s*packet loss", ping)
    if loss:
        r.m("Resolution loss", f"{loss.group(1)}%")
    # Verdict
    if loss and int(loss.group(1)) >= 100:
        r.status, r.headline = Status.FAIL, "Critical-name resolution FAILED (100% loss)"
    elif total_srv is not None and ready == 0:
        r.status, r.headline = Status.FAIL, "No DNS server ready (dnsproxy)"
    elif loss and int(loss.group(1)) > 0:
        r.status, r.headline = Status.WARN, f"Resolution {loss.group(1)}% loss"
    elif total_srv is not None and ready < total_srv:
        r.status, r.headline = Status.WARN, f"{total_srv - ready} DNS server(s) not ready"
    elif loss and int(loss.group(1)) == 0:
        r.status, r.headline = Status.PASS, (
            "DNS resolves" + (f", {ready}/{total_srv} servers ready" if total_srv else ""))
    else:
        r.status, r.headline = Status.WARN, "Could not confirm resolution"
    return r


@parser("sdwan_health")
def _sdwan(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    dead = re.findall(r"state\((dead)\)", raw)
    total = re.findall(r"state\(\w+\)", raw)
    r.m("SLA members", len(total)); r.m("Dead", len(dead))
    if dead:
        r.status, r.headline = Status.WARN, f"{len(dead)}/{len(total)} SD-WAN members dead"
    else:
        r.status, r.headline = Status.PASS, "All SD-WAN members alive"
    return r


# --------------------------------------------------------------------------
# Fine parsers added v0.1.1 (were _generic). Calibrated against mock fixtures;
# VALIDATE regexes against real-device output before production.
@parser("crashlog")
def _crashlog(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    entries = [l for l in raw.splitlines() if re.match(r"\s*\d+:\s", l)]
    stamps = re.findall(r"(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}", raw)
    dates = sorted({d for d in (_parse_date(x) for x in stamps) if d}, reverse=True)
    if not entries and not dates:
        r.status, r.headline = Status.PASS, "Crash log empty"
        return r
    if not dates:
        r.m("Crash entries", len(entries))
        r.status, r.headline = Status.WARN, f"{len(entries)} crash entries (no parseable date)"
        return r
    newest = dates[0]
    age = (_now(dev) - newest).days
    r.m("Crash entries", len(entries))
    r.m("Most recent", newest.strftime("%Y-%m-%d"))
    r.m("Age", f"{age}d")
    if age <= 7:
        r.status, r.headline = Status.FAIL, f"Recent crash(es) - newest {age}d ago"
    else:
        r.status, r.headline = Status.WARN, f"{len(entries)} crash entries, newest {age}d ago"
    return r


@parser("config_error_log")
def _config_error_log(meta, out, dev):
    cmd = next(iter(out), "")
    raw = out.get(cmd, "")
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    lines = []
    for l in raw.splitlines():
        t = l.strip()
        if not t:
            continue
        if "config-error-log" in t or t == cmd.strip():          # command echo
            continue
        if re.match(r"^\S+\s*(\([^)]*\))?\s*[#$]$", t):           # bare prompt
            continue
        lines.append(t)
    if lines:
        r.m("Error lines", len(lines))
        r.status, r.headline = Status.FAIL, (
            str(len(lines)) + " config error line(s) - configuration may not be fully applied")
    else:
        r.status, r.headline = Status.PASS, "No config errors logged"
    return r

@parser("sessions")
def _sessions(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    sc = re.search(r"session[_ ]count=(\d+)", raw) or re.search(r"total_session=(\d+)", raw)
    sr = re.search(r"setup[_ ]rate=(\d+)", raw)
    clash = re.search(r"clash=(\d+)", raw)
    mtd = re.search(r"memory_tension_drop=(\d+)", raw)
    if sc:
        r.m("Sessions", sc.group(1))
    if sr:
        r.m("Setup rate", f"{sr.group(1)}/s")
    issues = []
    if clash and int(clash.group(1)) > 0:
        issues.append(f"clash={clash.group(1)}")
    if mtd and int(mtd.group(1)) > 0:
        issues.append(f"mem-tension-drop={mtd.group(1)}")
    if issues:
        r.status, r.headline = Status.WARN, "; ".join(issues) + " - memory pressure on session table"
    elif sc:
        r.status = Status.PASS
        r.headline = f"{sc.group(1)} sessions" + (f", {sr.group(1)}/s setup" if sr else "")
    else:
        r.status, r.headline = Status.INFO, "Session stats captured"
    return r


@parser("webfilter_rating")
def _webfilter_rating(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    status = re.search(r"Status\s*:\s*(\w+)", raw)
    servers, rtts, total_lost = 0, [], 0
    for line in raw.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+(.*)", line)
        if not m:
            continue
        nums = re.findall(r"-?\d+", m.group(2))
        # columns after IP: weight rtt [flags(non-numeric, skipped)] tz packets curr_lost total_lost
        if len(nums) < 2:
            continue
        servers += 1
        rtts.append(int(nums[1]))
        total_lost += int(nums[-1])
    if status:
        r.m("Service", status.group(1))
    r.m("Rating servers", servers)
    if rtts:
        r.m("Best RTT", f"{min(rtts)}ms")
    r.m("Total lost", total_lost)
    if servers == 0:
        r.status, r.headline = Status.WARN, "No rating servers listed - FortiGuard web filter may be down"
    elif total_lost > 0:
        r.status, r.headline = Status.WARN, f"{servers} servers reachable, {total_lost} packet(s) lost"
    else:
        r.status, r.headline = Status.PASS, f"{servers} rating servers reachable, no loss"
    return r



# --------------------------------------------------------------------------
# SD-WAN + VPN parsers (v0.1.4). Commands cited from docs.fortinet.com 818746
# (SD-WAN) and VPN troubleshooting KB; output regexes calibrated to documented
# samples -- VALIDATE against real device output.
@parser("sdwan_service")
def _sdwan_service(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    blocks = re.split(r"(?=^Service\(\d+\):)", raw, flags=re.MULTILINE)
    no_path = []
    total = 0
    for b in blocks:
        m = re.match(r"Service\((\d+)\)", b)
        if not m:
            continue
        total += 1
        if "selected" not in b:                 # no member currently selected
            no_path.append(m.group(1))
    r.m("SD-WAN rules", total)
    r.m("Rules with no path", len(no_path))
    if total == 0:
        r.status, r.headline = Status.INFO, "No SD-WAN services configured"
    elif no_path:
        r.status, r.headline = Status.WARN, (
            f"Service(s) {', '.join(no_path)} have no selected member - traffic blackholed")
    else:
        r.status, r.headline = Status.PASS, f"{total} SD-WAN rule(s), all with a viable path"
    return r


@parser("sdwan_members")
def _sdwan_members(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    members = re.findall(r"Member\((\d+)\)", raw) or re.findall(r"Seq_num\((\d+)", raw)
    dead = re.findall(r"status\(dead\)|\bdead\b", raw)
    r.m("Members", len(members))
    if dead:
        r.m("Dead", len(dead))
        r.status, r.headline = Status.WARN, f"{len(dead)} SD-WAN member(s) dead"
    elif members:
        r.status, r.headline = Status.PASS, f"{len(members)} SD-WAN member(s), all alive"
    else:
        r.status, r.headline = Status.INFO, "No SD-WAN members parsed"
    return r


@parser("sdwan_sla_log")
def _sdwan_sla_log(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    to_dead = re.findall(r"->\s*dead", raw)
    to_alive = re.findall(r"->\s*alive", raw)
    transitions = len(to_dead) + len(to_alive)
    r.m("Transitions logged", transitions)
    r.m("-> dead", len(to_dead))
    if to_dead:
        r.status, r.headline = Status.WARN, f"{len(to_dead)} SLA member went down recently (flapping?)"
    elif transitions:
        r.status, r.headline = Status.PASS, f"{transitions} SLA transition(s), none to dead"
    else:
        r.status, r.headline = Status.INFO, "No recent SLA transitions"
    return r


@parser("vpn_ipsec_summary")
def _vpn_ipsec_summary(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    down = []
    total = 0
    for m in re.finditer(r"^'?([^'\n]+?)'?\s+\S+:\d+\s+selectors\(total,up\):\s*(\d+)/(\d+)",
                         raw, re.MULTILINE):
        name, tot, up = m.group(1).strip(), int(m.group(2)), int(m.group(3))
        total += 1
        if up < tot or up == 0:
            down.append(name)
    r.m("IPsec tunnels", total)
    r.m("Selectors down", len(down))
    if total == 0:
        r.status, r.headline = Status.INFO, "No IPsec tunnels"
    elif down:
        r.status, r.headline = Status.WARN, f"Down/incomplete: {', '.join(down[:4])}"
    else:
        r.status, r.headline = Status.PASS, f"{total} IPsec tunnel(s), all selectors up"
    return r


@parser("vpn_ike_gw")
def _vpn_ike_gw(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    names = re.findall(r"^name:\s*(\S+)", raw, re.MULTILINE)
    states = re.findall(r"^\s*state:\s*(\w+)", raw, re.MULTILINE)
    established = [st for st in states if st.lower() == "established"]
    bad = len(states) - len(established)
    r.m("IKE gateways", len(names) or len(states))
    r.m("Established", len(established))
    if not states:
        r.status, r.headline = Status.INFO, "No IKE gateways"
    elif bad:
        r.status, r.headline = Status.WARN, f"{bad} phase-1 gateway(s) not established"
    else:
        r.status, r.headline = Status.PASS, f"All {len(established)} phase-1 gateway(s) established"
    return r


@parser("vpn_ssl")
def _vpn_ssl(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    users = re.findall(r"^\s*\d+\s+\S+\s+\S+\s+\d+\(\d+\)", raw, re.MULTILINE)
    sec = re.search(r"SSL-VPN sessions:", raw)
    r.m("Login users", len(users))
    r.status = Status.INFO
    r.headline = (f"{len(users)} SSL-VPN user(s) connected" if users
                  else "No active SSL-VPN sessions")
    return r



# --------------------------------------------------------------------------
# v0.1.9 root-cause checks. Commands per Fable roadmap + docs.fortinet.com;
# output regexes calibrated to documented/representative samples -- VALIDATE.
@parser("conserve")
def _conserve(meta, out, dev):
    cons = out.get("diagnose hardware sysinfo conserve", "")
    shm = out.get("diagnose hardware sysinfo shm", "")
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw="\n".join(out.values()))
    if not cons.strip() and not shm.strip():
        r.status, r.headline = Status.INFO, "Could not read conserve status"
        return r
    km = re.search(r"conserve mode:\s*(\w+)", cons)
    used = re.search(r"memory used:.*?(\d+)\s*%", cons)
    shm_m = re.search(r"conserve mode:\s*(\d+)", shm)
    if used:
        r.m("Memory used", used.group(1) + "%")
    kernel_on = bool(km) and km.group(1).lower() not in ("off", "0")
    shm_on = bool(shm_m) and shm_m.group(1) != "0"
    r.m("Kernel conserve", "on" if kernel_on else "off")
    r.m("SHM conserve", "on" if shm_on else "off")
    if kernel_on:
        r.status, r.headline = Status.FAIL, "Kernel conserve mode ACTIVE - memory pressure"
    elif shm_on:
        r.status, r.headline = Status.WARN, "Shared-memory (proxy/WAD) conserve ACTIVE"
    else:
        r.status, r.headline = Status.PASS, "Conserve off (kernel + shared-memory)"
    return r


@parser("sensors")
def _sensors(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    low = raw.lower()
    if not raw.strip() or "not support" in low or "no sensor" in low or "fail to" in low:
        r.status, r.headline = Status.INFO, "No hardware sensors (VM or unsupported)"
        return r
    alarms, rows = [], 0
    for line in raw.splitlines():
        t = line.strip()
        if not t or re.match(r"(?i)(device|sensor|name)\b.*\bstatus\b", t):  # header
            continue
        rows += 1
        ll = t.lower()
        # explicit problem STATUS words (not the "(alarm:NN)" threshold annotation)
        if re.search(r"\b(failed|fail|critical|abnormal|shutdown|over-?temp|out of range)\b", ll):
            alarms.append(t.split()[0])
        elif re.search(r"(?<![(:])\balarm\b(?!\s*[:=])", ll):
            alarms.append(t.split()[0])
    r.m("Sensors", str(rows))
    if alarms:
        r.status, r.headline = Status.FAIL, "Sensor alarm: " + ", ".join(sorted(set(alarms))[:4])
    elif rows:
        r.status, r.headline = Status.PASS, str(rows) + " sensors, all within range"
    else:
        r.status, r.headline = Status.INFO, "No sensor rows parsed"
    return r

@parser("faz_logging")
def _faz_logging(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    low = raw.lower()
    if not raw.strip() or "not configured" in low or "no fortianalyzer" in low:
        r.status, r.headline = Status.INFO, "No FortiAnalyzer configured"
        return r
    st = re.search(r"Connection status:\s*(\w+)", raw) or re.search(r"Connection:\s*(\w+)", raw)
    reg = re.search(r"Registration:\s*(\w+)", raw)
    if st:
        r.m("Connection", st.group(1))
    if reg:
        r.m("Registration", reg.group(1))
    up = (st and st.group(1).lower() in ("up", "allow")) or "status: up" in low
    if up and (not reg or reg.group(1).lower() == "registered"):
        r.status, r.headline = Status.PASS, "FortiAnalyzer logging UP"
    elif st and st.group(1).lower() in ("down", "deny"):
        r.status, r.headline = Status.FAIL, "FortiAnalyzer connection " + st.group(1)
    else:
        r.status, r.headline = Status.WARN, "FortiAnalyzer logging not fully healthy"
    return r


@parser("interface_errors")
def _interface_errors(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    bad, total = [], 0
    blocks = re.split(r"(?=^if=)", raw, flags=re.MULTILINE)
    for b in blocks:
        nm = re.match(r"if=(\S+)", b)
        if not nm:
            continue
        total += 1
        rxe = int((re.search(r"rxe=(\d+)", b) or ["", "0"])[1] if re.search(r"rxe=(\d+)", b) else 0)
        txe = int((re.search(r"txe=(\d+)", b) or ["", "0"])[1] if re.search(r"txe=(\d+)", b) else 0)
        rxd = int((re.search(r"rxd=(\d+)", b) or ["", "0"])[1] if re.search(r"rxd=(\d+)", b) else 0)
        txd = int((re.search(r"txd=(\d+)", b) or ["", "0"])[1] if re.search(r"txd=(\d+)", b) else 0)
        e, d = rxe + txe, rxd + txd
        if e or d:
            bad.append(nm.group(1) + " (" + str(e) + " err, " + str(d) + " drop)")
    r.m("Interfaces", str(total))
    if bad:
        r.status, r.headline = Status.WARN, "Errors/drops: " + "; ".join(bad[:4])
    elif total:
        r.status, r.headline = Status.PASS, str(total) + " interfaces, no errors/drops"
    else:
        r.status, r.headline = Status.INFO, "No interface counters parsed"
    return r


@parser("arp")
def _arp(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    rows = re.findall(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})\s+(\S+)", raw, re.MULTILINE)
    if not rows:
        r.status, r.headline = Status.INFO, "No ARP entries parsed"
        return r
    per_if = {}
    for _, _, iface in rows:
        per_if[iface] = per_if.get(iface, 0) + 1
    incomplete = [ip for ip, mac, _ in rows if mac == "00:00:00:00:00:00"]
    r.m("ARP entries", str(len(rows)))
    r.m("Per interface", ", ".join(k + ":" + str(v) for k, v in sorted(per_if.items())))
    if incomplete:
        r.m("Incomplete", ", ".join(incomplete[:4]))
        r.status, r.headline = Status.WARN, "Unresolved ARP (L2 next-hop down?): " + ", ".join(incomplete[:4])
    else:
        r.status, r.headline = Status.PASS, str(len(rows)) + " ARP entries across " + str(len(per_if)) + " interface(s), all resolved"
    return r

@parser("policy_routes")
def _policy_routes(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    ids = re.findall(r"^id=\d+", raw, re.MULTILINE)
    r.m("Policy routes", str(len(ids)))
    if ids:
        r.status, r.headline = Status.INFO, str(len(ids)) + " policy route(s)/SD-WAN rule(s) in kernel (override routing table)"
    else:
        r.status, r.headline = Status.PASS, "No policy routes (routing table is authoritative)"
    return r


@parser("vpn_ipsec_traffic")
def _vpn_ipsec_traffic(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    asym, errs, total = [], [], 0
    blocks = re.split(r"(?=^name=)", raw, flags=re.MULTILINE)
    for b in blocks:
        nm = re.match(r"name=(\S+)", b)
        if not nm:
            continue
        total += 1
        bt = re.search(r"bytes\(tx/rx\)=(\d+)/(\d+)", b)
        if bt and int(bt.group(1)) > 0 and int(bt.group(2)) == 0:
            asym.append(nm.group(1))
        de = re.search(r"errors=(\d+)", b)
        rp = re.search(r"replay=(\d+)", b)
        if (de and int(de.group(1)) > 0) or (rp and int(rp.group(1)) > 0):
            errs.append(nm.group(1))
    r.m("Tunnels (SA)", str(total))
    if total == 0:
        r.status, r.headline = Status.INFO, "No IPsec SAs"
    elif asym:
        r.status, r.headline = Status.WARN, "tx>0 but rx=0 (asymmetry): " + ", ".join(asym[:4])
    elif errs:
        r.status, r.headline = Status.WARN, "decryption/replay errors: " + ", ".join(errs[:4])
    else:
        r.status, r.headline = Status.PASS, str(total) + " SA(s) passing traffic, no dec errors"
    return r



# --------------------------------------------------------------------------
# FortiSwitch (FortiLink-managed) + FortiAP (wireless-controller managed).
# All queried from the FortiGate; targets FortiSwitch 7.6.x and FortiAP 7.x.x.
# Output regexes calibrated to docs.fortinet.com + community KB samples --
# VALIDATE against real device output before production.
@parser("fsw_managed")
def _fsw_managed(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    rows = re.findall(r"^(S\d{3}\w{6,})\s+(v[\d.]+)\s+(\S+)", raw, re.MULTILINE)
    if not rows:
        r.status, r.headline = Status.INFO, "No managed FortiSwitches (FortiLink not in use)"
        return r
    down, off_ver = [], []
    for sid, ver, status in rows:
        st = status.lower()
        if not ("up" in st and "auth" in st):
            down.append(sid + " (" + status + ")")
        elif not ver.startswith("v7.6"):            # target is 7.6.x
            off_ver.append(sid + " " + ver)
    r.m("Managed switches", len(rows))
    r.m("Up", len(rows) - len(down))
    if down:
        r.m("Down/unauthorized", len(down))
        r.status, r.headline = Status.FAIL, "FortiSwitch down/unauthorized: " + "; ".join(down[:4])
    elif off_ver:
        r.m("Off-target firmware", ", ".join(off_ver[:4]))
        r.status, r.headline = Status.WARN, (
            str(len(off_ver)) + " FortiSwitch(es) not on 7.6.x: " + "; ".join(off_ver[:3]))
    else:
        r.status, r.headline = Status.PASS, (
            str(len(rows)) + " FortiSwitch(es) authorized & up on 7.6.x")
    return r


@parser("fsw_sync")
def _fsw_sync(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    rows = re.findall(r"^(S\d{3}\w{6,})\s+(.+)$", raw, re.MULTILINE)
    if not rows:
        r.status, r.headline = Status.INFO, "No managed FortiSwitches to sync"
        return r
    bad = [s for s, st in rows if "in-sync" not in st.lower()]
    r.m("Switches", len(rows))
    r.m("In-sync", len(rows) - len(bad))
    if bad:
        r.status, r.headline = Status.FAIL, (
            str(len(bad)) + " FortiSwitch config(s) out-of-sync: " + ", ".join(bad[:4]))
    else:
        r.status, r.headline = Status.PASS, "All " + str(len(rows)) + " FortiSwitch config(s) in-sync"
    return r


@parser("fsw_poe")
def _fsw_poe(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    hot, total = [], 0
    for b in re.split(r"(?=^FortiSwitch\s+S\d{3})", raw, flags=re.MULTILINE):
        m = re.match(r"FortiSwitch\s+(S\d{3}\w+)", b)
        if not m:
            continue
        total += 1
        pct = re.search(r"consumption:.*?\((\d+)%\)", b)
        if pct and int(pct.group(1)) >= 90:
            hot.append(m.group(1) + " " + pct.group(1) + "%")
    if total == 0:
        r.status, r.headline = Status.INFO, "No PoE-capable managed FortiSwitches"
        return r
    r.m("PoE switches", total)
    if hot:
        r.m("Near budget", ", ".join(hot))
        r.status, r.headline = Status.WARN, "PoE budget near limit: " + ", ".join(hot[:4])
    else:
        r.status, r.headline = Status.PASS, str(total) + " FortiSwitch PoE budget(s) healthy"
    return r


@parser("fap_managed")
def _fap_managed(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    blocks = [b for b in re.split(r"(?=^WTP ID:)", raw, flags=re.MULTILINE) if "serial-id" in b]
    if not blocks:
        r.status, r.headline = Status.INFO, "No managed FortiAPs (wireless controller not in use)"
        return r
    down, off_ver = [], []
    for b in blocks:
        sid = re.search(r"serial-id\s*:\s*(\S+)", b)
        name = re.search(r"name\s*:\s*(\S+)", b)
        state = re.search(r"state\s*:\s*([^\n]+)", b)
        ver = re.search(r"os-version\s*:\s*\S*?v(\d+\.\d+)", b)
        label = (name.group(1) if name else (sid.group(1) if sid else "?"))
        st = (state.group(1) if state else "").lower()
        if not ("run" in st or "connected" in st):
            down.append(label + " (" + (state.group(1).strip() if state else "?") + ")")
        elif ver and not ver.group(1).startswith("7."):   # target is 7.x.x
            off_ver.append(label + " v" + ver.group(1))
    r.m("Managed APs", len(blocks))
    r.m("Connected", len(blocks) - len(down))
    if down:
        r.m("Not connected", len(down))
        r.status, r.headline = Status.WARN, "FortiAP not fully connected: " + "; ".join(down[:4])
    elif off_ver:
        r.m("Off-target firmware", ", ".join(off_ver[:4]))
        r.status, r.headline = Status.WARN, (
            str(len(off_ver)) + " FortiAP(s) not on 7.x: " + "; ".join(off_ver[:3]))
    else:
        r.status, r.headline = Status.PASS, str(len(blocks)) + " FortiAP(s) connected (CWAS_RUN) on 7.x"
    return r


@parser("fap_clients")
def _fap_clients(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    rows = re.findall(
        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(\S+)\s+\S+\s+(-?\d+)",
        raw, re.MULTILINE)
    total = re.search(r"Total STA:\s*(\d+)", raw)
    if not rows and not total:
        r.status, r.headline = Status.INFO, "No wireless clients / no managed APs"
        return r
    weak = [m for m in rows if int(m[3]) <= -75]
    per_ap = {}
    for _, _, ap, _rssi in rows:
        per_ap[ap] = per_ap.get(ap, 0) + 1
    count = int(total.group(1)) if total else len(rows)
    r.m("Clients", count)
    r.m("APs serving", len(per_ap))
    if weak:
        r.m("Weak signal (<=-75dBm)", len(weak))
        r.status, r.headline = Status.WARN, str(len(weak)) + " client(s) at weak signal (<=-75 dBm)"
    else:
        r.status, r.headline = Status.PASS, str(count) + " wireless client(s), all healthy signal"
    return r


@parser("fap_health")
def _fap_health(meta, out, dev):
    raw = _first(out)
    r = CheckResult(meta["id"], meta["module"], meta["title"], raw=raw)
    utils, issues = [], []
    for m in re.finditer(
            r"channel\s+(\d+).*?noise\s+(-?\d+)dBm\s+chan-util\s+(\d+)%", raw):
        ch, noise, util = m.group(1), int(m.group(2)), int(m.group(3))
        utils.append(util)
        if util >= 80:
            issues.append("ch" + ch + " " + str(util) + "% util")
        elif noise > -80:
            issues.append("ch" + ch + " noise " + str(noise) + "dBm")
    if not utils:
        r.status, r.headline = Status.INFO, "No FortiAP radio data"
        return r
    r.m("Radios", len(utils))
    r.m("Busiest channel util", str(max(utils)) + "%")
    if issues:
        r.status, r.headline = Status.WARN, "Radio contention: " + "; ".join(issues[:4])
    else:
        r.status, r.headline = Status.PASS, str(len(utils)) + " radio(s), all uncongested"
    return r


def _parse_date(s: str):
    s = s.strip()
    for fmt in ("%Y-%m-%d", "%a %Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return _dt.datetime.strptime(s.split(" GMT")[0].strip(), fmt)
        except ValueError:
            continue
    return None
