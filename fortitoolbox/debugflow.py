"""Debug flow: smart filter parsing, bounded run with guaranteed cleanup, output
parsing into ONLY-what-happened, and plain-language conclusions.

Commands/format per docs.fortinet.com "Debugging the packet flow" (54688) and the
community debug-flow reference examples. Output regexes are calibrated to the
documented format -- VALIDATE against a real device.

Debug flow is ALWAYS per-VDOM. The runner enters the selected VDOM, sets a bounded
`trace start <N>`, captures the stream, and ALWAYS tears the debug down in finally.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_PROTO = {"icmp": 1, "tcp": 6, "udp": 17, "icmp6": 58, "icmpv6": 58}


# --------------------------------------------------------------------------
# 1) Smart filter parsing -- the operator types values, not object types.
def parse_filter(text: str) -> Tuple[List[str], dict]:
    """`192.168.1.11,53` or `8888` or `10.0.0.1 udp 53` -> filter commands.

    Each token is classified: IPv4 -> addr, 1..65535 -> port, tcp/udp/icmp ->
    proto. Returns (filter_commands, summary)."""
    tokens = [t for t in re.split(r"[\s,;]+", text.strip()) if t]
    f = {"addr": [], "port": None, "proto": None}
    for t in tokens:
        low = t.lower()
        if _IPV4.match(t):
            f["addr"].append(t)
        elif low in _PROTO:
            f["proto"] = _PROTO[low]
        elif t.isdigit() and 1 <= int(t) <= 65535:
            f["port"] = int(t)
        elif low.startswith("proto") and low[5:].isdigit():
            f["proto"] = int(low[5:])
        # silently ignore unrecognised tokens
    cmds = ["diagnose debug flow filter clear"]
    # up to two addresses: addr (single) covers src OR dst; two -> saddr/daddr
    if len(f["addr"]) == 1:
        cmds.append("diagnose debug flow filter addr " + f["addr"][0])
    elif len(f["addr"]) >= 2:
        cmds.append("diagnose debug flow filter saddr " + f["addr"][0])
        cmds.append("diagnose debug flow filter daddr " + f["addr"][1])
    if f["port"] is not None:
        cmds.append("diagnose debug flow filter port " + str(f["port"]))
    if f["proto"] is not None:
        cmds.append("diagnose debug flow filter proto " + str(f["proto"]))
    return cmds, f


# --------------------------------------------------------------------------
# 2) Flow output parsing -- one record per trace_id, only fields that occurred.
@dataclass
class FlowTrace:
    trace_id: str
    proto: Optional[int] = None
    src: str = ""
    dst: str = ""
    iface_in: str = ""
    iface_out: str = ""
    session_new: bool = False
    session: str = ""
    helper: str = ""
    route_gw: str = ""
    policy_id: str = ""
    policy_action: str = ""        # allowed | denied
    snat: str = ""
    dnat: str = ""
    modules: List[str] = field(default_factory=list)
    offload: str = ""
    shaping: str = ""
    verdict: str = ""              # allowed | dropped
    drop_reason: str = ""
    msgs: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Only the fields that actually happened (no empty/false noise)."""
        d = {"trace_id": self.trace_id}
        proto_name = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}.get(self.proto)
        if self.src:
            d["packet"] = ((proto_name or ("proto" + str(self.proto) if self.proto else "")) +
                           " " + self.src + " -> " + self.dst).strip()
        if self.iface_in:
            d["ingress"] = self.iface_in
        if self.session:
            d["session"] = self.session
        elif self.session_new:
            d["session"] = "new"
        if self.route_gw:
            d["route"] = "gw " + self.route_gw + (" via " + self.iface_out if self.iface_out else "")
        if self.policy_id:
            d["policy"] = ("Policy-" + self.policy_id +
                           ((" (" + self.policy_action + ")") if self.policy_action else ""))
        if self.snat:
            d["SNAT"] = self.snat
        if self.dnat:
            d["DNAT"] = self.dnat
        if self.modules:
            d["inspected_by"] = ", ".join(dict.fromkeys(self.modules))
        if self.helper:
            d["helper"] = self.helper
        if self.offload:
            d["offload"] = self.offload
        if self.shaping:
            d["shaping"] = self.shaping
        d["verdict"] = self.verdict or "?"
        if self.drop_reason:
            d["drop_reason"] = self.drop_reason
        return d


_TERMINAL_DROP = re.compile(
    r"reverse path check fail|iprope_in_check\(\) check failed|denied by [^,]*polic|"
    r"no matching policy|ttl=0|ttl exceeded|no route to|cannot find a route|"
    r"reverse path.*drop|blocked by|local-in policy.*deny", re.I)


def _apply(t: "FlowTrace", msg: str) -> None:
    t.msgs.append(msg)
    low = msg.lower()
    m = re.search(r"received a packet\(proto=(\d+),\s*([\d.]+:\d+|[\d.]+)\s*->\s*([\d.]+:\d+|[\d.]+)\)", msg)
    if m:
        t.proto = int(m.group(1)); t.src = m.group(2); t.dst = m.group(3)
        fi = re.search(r"from (\w[\w.\-]*)", msg)
        if fi:
            t.iface_in = fi.group(1).rstrip(".")
    if "allocate a new session" in low:
        t.session_new = True; t.session = "new"
    if "find an existing session" in low or "found an existing session" in low:
        t.session = "existing" + (" (reply)" if "reply" in low else "")
    r = re.search(r"find a route:.*?gw-([\d.]+)\s*via\s*(\S+)", msg)
    if r:
        t.route_gw = r.group(1); t.iface_out = r.group(2).rstrip(".")
    p = re.search(r"(allowed|matched|denied) by .*?policy[- ]?(\d+)", low)
    if p:
        t.policy_id = p.group(2)
        t.policy_action = "denied" if p.group(1) == "denied" else "allowed"
    sn = re.search(r"snat\s+([\d.]+)\s*->\s*([\d.]+(?::\d+)?)", low)
    if sn:
        t.snat = sn.group(1) + " -> " + sn.group(2)
    dn = re.search(r"dnat\s+([\d.]+(?::\d+)?)\s*->\s*([\d.]+(?::\d+)?)", low)
    if dn:
        t.dnat = dn.group(1) + " -> " + dn.group(2)
    if "send to ips" in low or "ips_receive" in low:
        t.modules.append("ips")
    if "send to av" in low or "scan " in low:
        t.modules.append("av")
    if "webfilter" in low:
        t.modules.append("webfilter")
    if "app" in low and "ctrl" in low:
        t.modules.append("app-ctrl")
    hp = re.search(r"run helper-([\w\-]+)", low)
    if hp:
        t.helper = hp.group(1)
    if "offload" in low and "cannot" not in low and "not " not in low:
        t.offload = "yes (NPU)" if "npu" in low else "yes"
        to = re.search(r"\bto\s+(\S+?),", msg)
        if to and not t.iface_out:
            t.iface_out = to.group(1)
    elif ("cannot offload" in low or "no offload" in low or "not offload" in low):
        t.offload = "no"
    if "shaping" in low or "shaper" in low:
        sh = re.search(r"(shared|per-ip)?\s*shaper\s+(\S+)", low)
        t.shaping = (sh.group(0).strip() if sh else "yes")
    # --- verdict: terminal drops only; "after check act-drop" is a per-check result ---
    is_check = ("after check" in low or "act-drop" in low or "ret-no-match" in low
                or "__iprope_check" in low or "checking" in low)
    if not is_check and _TERMINAL_DROP.search(msg):
        t.verdict = "dropped"
        if not t.drop_reason:
            t.drop_reason = re.sub(r",?\s*drop\.?$", "", msg).strip() or msg
    elif t.verdict != "dropped" and any(k in low for k in (
            "allowed by", "forwarded", "send to", "run helper", "enter fast path",
            "offloading", "existing session", "snat ", "dnat ")):
        t.verdict = "allowed"


def parse_flow(text: str) -> List[FlowTrace]:
    """Format-agnostic: handles wrapped ('id=.. trace_id=N .. msg="..."') and clean
    message-only output. A new trace starts at each 'received a packet' line."""
    traces: List[FlowTrace] = []
    cur: Optional[FlowTrace] = None
    auto = 0
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        mm = re.search(r'msg="(.*)"', line)
        if mm:
            msg = mm.group(1)
        else:
            # skip echoes / prompts / debug-control lines in clean output
            if re.match(r"(config |edit |end\b|next\b|diagnose |get |execute )", raw, re.I):
                continue
            if re.match(r"^\S+\s*(\([^)]*\))?\s*[#$]\s*$", raw):
                continue
            msg = raw
        tid_m = re.search(r"trace_id=(\d+)", line)
        if "received a packet" in msg.lower():
            auto += 1
            cur = FlowTrace(trace_id=(tid_m.group(1) if tid_m else str(auto)))
            traces.append(cur)
        if cur is None:
            continue
        _apply(cur, msg)
    return traces


# --------------------------------------------------------------------------
# 3) Conclusions -- map notable messages to plain-language root cause.
_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"reverse path check fail", re.I),
     "RPF / anti-spoofing drop: the source IP is not reachable back through the "
     "ingress interface. Usually asymmetric routing or a missing/incorrect route "
     "to the source. Check the route back to the source, or relax src-check on the interface."),
    (re.compile(r"iprope_in_check\(\) check failed on policy 0|denied by forward policy check|policy 0, drop", re.I),
     "No firewall policy allows this traffic (implicit deny / policy 0). Check that a "
     "policy matches src/dst interface, addresses, service and that it is enabled and above any deny."),
    (re.compile(r"iprope_in_check\(\) check failed", re.I),
     "Policy lookup failed for this packet -- no matching allow policy at this stage."),
    (re.compile(r"denied by policy-?(\d+)", re.I),
     "Explicitly DENIED by the matched firewall policy. Review that policy's action/objects."),
    (re.compile(r"no matching ippool|cannot get a pip", re.I),
     "SNAT failed: no usable IP-pool address. Check the IP pool / outgoing interface IP."),
    (re.compile(r"denied by quota|session limit", re.I),
     "Dropped by a resource limit (quota/session). Check shapers and session limits."),
    (re.compile(r"no session matched|session not found", re.I),
     "Reply/again packet with no matching session (session may have timed out or never formed)."),
    (re.compile(r"ttl=0|exceeded", re.I),
     "TTL expired -- a routing loop or too many hops."),
]


def conclude(traces: List[FlowTrace]) -> List[str]:
    out: List[str] = []
    seen = set()
    for t in traces:
        blob = "\n".join(t.msgs)
        for pat, expl in _RULES:
            if pat.search(blob) and expl not in seen:
                seen.add(expl)
                out.append(expl)
    # positive conclusion if everything was allowed and nothing dropped
    if traces and not any(t.verdict == "dropped" for t in traces):
        allowed = [t for t in traces if t.verdict == "allowed"]
        if allowed:
            pols = sorted({t.policy_id for t in allowed if t.policy_id})
            msg = "Traffic is allowed end-to-end"
            if pols:
                msg += " (matched Policy-" + ", ".join(pols) + ")"
            nat = [t for t in allowed if t.snat or t.dnat]
            if nat:
                msg += "; NAT is applied"
            out.insert(0, msg + ".")
    return out


# --------------------------------------------------------------------------
# 4) Bounded runner with guaranteed teardown.
def build_sequence(filter_cmds: List[str], count: int) -> Tuple[List[str], List[str]]:
    setup = (["diagnose debug reset"] + filter_cmds +
             ["diagnose debug flow show function-name enable",
              "diagnose debug flow show iprope enable",
              "diagnose debug flow trace start " + str(int(count)),
              "diagnose debug enable"])
    teardown = ["diagnose debug flow trace stop",
                "diagnose debug disable",
                "diagnose debug flow filter clear",
                "diagnose debug reset"]
    return setup, teardown


def run_debug_flow(channel, vdom: str, filter_cmds: List[str], count: int = 10,
                   timeout: float = 30.0, settle: float = 3.0, in_vdom: bool = True,
                   should_stop=None, on_progress=None) -> str:
    """Run the bounded debug-flow sequence on `channel`, capture the stream, and
    ALWAYS tear the debug down (trace stop / disable / filter clear / reset)."""
    setup, teardown = build_sequence(filter_cmds, count)
    captured: List[str] = []

    def drain() -> str:
        try:
            return channel.read_available()
        except Exception:
            return ""

    try:
        if in_vdom and vdom:
            channel.send_line("config vdom")
            channel.send_line("edit " + vdom)
            time.sleep(0.3); captured.append(drain())
        for c in setup:
            channel.send_line(c)
            time.sleep(0.15); captured.append(drain())
        deadline = time.time() + timeout
        last = time.time()
        started = False
        while time.time() < deadline:
            if should_stop is not None and should_stop():
                break
            chunk = drain()
            if chunk:
                captured.append(chunk); last = time.time(); started = True
                if on_progress is not None:
                    on_progress(chunk)
            elif started and (time.time() - last) > settle:
                break
            else:
                time.sleep(0.2)
    finally:
        for c in teardown:
            try:
                channel.send_line(c); time.sleep(0.1); captured.append(drain())
            except Exception:
                pass
        if in_vdom and vdom:
            try:
                channel.send_line("end"); time.sleep(0.1); captured.append(drain())
            except Exception:
                pass
    return "".join(captured)


_DEMO_FLOW = """id=20085 trace_id=1 func=print_pkt_detail line=5640 msg="vd-root:0 received a packet(proto=6, 10.10.10.50:51234->8.8.8.8:443) from port2. flag [S], seq 100, ack 0, win 64240"
id=20085 trace_id=1 func=init_ip_session_common line=5824 msg="allocate a new session-0001a2b3"
id=20085 trace_id=1 func=__vf_ip_route_input_common line=2605 msg="find a route: flag=04000000 gw-203.0.113.1 via port1"
id=20085 trace_id=1 func=__iprope_check_one_policy line=2089 msg="checked gnum-100004 policy-1, ret-matched"
id=20085 trace_id=1 func=fw_forward_handler line=990 msg="Allowed by Policy-1: SNAT"
id=20085 trace_id=1 func=__ip_session_run_tuple line=3471 msg="SNAT 10.10.10.50->203.0.113.2:51234"
id=20085 trace_id=1 func=ips_receive_handler line=410 msg="send to ips"
id=20085 trace_id=1 func=fw_offload_check line=2034 msg="offload session, ka=0"
id=20086 trace_id=2 func=print_pkt_detail line=5640 msg="vd-root:0 received a packet(proto=1, 198.51.100.9:0->10.10.10.50:0) from port1."
id=20086 trace_id=2 func=__vf_ip_route_input_common line=2605 msg="reverse path check fail, drop"
id=20086 trace_id=2 func=ipv4_fast_cb line=53 msg="enter fast path, drop"
"""


class MockFlowChannel:
    """Demo channel: DRIPS a canned debug-flow trace line-by-line after 'trace
    start' so the live capture / packet counter behaves like a real stream."""

    def __init__(self):
        self._buf = ""
        self._pending: List[str] = []

    @property
    def is_open(self) -> bool:
        return True

    def open(self) -> None:
        pass

    def send_line(self, text: str) -> None:
        self._buf += text + "\n"
        if "trace start" in text:
            self._pending = [ln for ln in _DEMO_FLOW.splitlines() if ln.strip()]
        elif "iprope lookup" in text:
            self._buf += _DEMO_LOOKUP
        elif "session list" in text:
            self._buf += _DEMO_SESSIONS
        elif "sniffer packet" in text:
            from .sniffer import demo_capture_text
            self._pending = demo_capture_text("port1").splitlines()
        elif "test authserver" in text:
            self._buf += ("authenticate 'jdoe' against 'ldap' succeeded!\n"
                          "Group membership(s) - CN=VPN-Users,OU=Groups,DC=corp,DC=local "
                          "CN=Admins,OU=Groups,DC=corp,DC=local\n")

    def read_available(self) -> str:
        out = self._buf
        self._buf = ""
        if self._pending:                 # release ~2 lines per poll -> streams
            out += "\n".join(self._pending[:2]) + "\n"
            self._pending = self._pending[2:]
        return out

    def send_ctrl_c(self) -> None:
        rest = "\n".join(self._pending)
        self._pending = []
        self._buf += (rest + "\n" if rest else "") + "^C\n"

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------
# 5) Policy lookup -- predict the matching policy for a 5-tuple WITHOUT traffic.
def build_lookup_cmd(src: str, sport, dst: str, dport, proto, iface: str) -> str:
    return ("diagnose firewall iprope lookup " + str(src) + " " + str(sport or 0) + " " +
            str(dst) + " " + str(dport or 0) + " " + str(proto or 6) + " " +
            (iface or "any") + " policy")


def lookup_from_trace(t: "FlowTrace") -> str:
    def split(hp):
        return (hp.split(":") + ["0"])[:2] if hp else ["", "0"]
    s_ip, s_port = split(t.src)
    d_ip, d_port = split(t.dst)
    return build_lookup_cmd(s_ip, s_port, d_ip, d_port, t.proto or 6, t.iface_in or "any")


def parse_lookup(text: str) -> dict:
    """Best-effort: extract the matched policy id. Output format varies by MR --
    VALIDATE. Returns {matched: id|None, raw: text}."""
    low = text.lower()
    if "no matching" in low or "not match" in low or "no policy" in low:
        return {"matched": None, "raw": text}
    m = (re.search(r"polic[yies]*[\s\-_]*id[=:\s]+(\d+)", low) or
         re.search(r"policy[\s\-]?(\d+)\b", low) or
         re.search(r"\bid[=:\s]+(\d+)", low))
    return {"matched": (m.group(1) if m else None), "raw": text}


_DEMO_LOOKUP = """gnum=100004 policy match:
  iprope_in_check: matched policy-7 (action accept)
  best matched policy id=7
"""


# --------------------------------------------------------------------------
# 6) Session correlation -- find the live session(s) for the flow's tuple.
def session_from_trace(t: "FlowTrace") -> List[str]:
    def ip(hp):
        return hp.split(":")[0] if hp else ""
    cmds = ["diagnose sys session filter clear"]
    if t.proto:
        cmds.append("diagnose sys session filter proto " + str(t.proto))
    if ip(t.src):
        cmds.append("diagnose sys session filter src " + ip(t.src))
    if ip(t.dst):
        cmds.append("diagnose sys session filter dst " + ip(t.dst))
    cmds.append("diagnose sys session list")
    return cmds


def run_session(channel, vdom: str, cmds: List[str], in_vdom: bool = True,
                window: float = 4.0) -> str:
    captured: List[str] = []

    def drain():
        try:
            return channel.read_available()
        except Exception:
            return ""
    try:
        if in_vdom and vdom:
            channel.send_line("config vdom"); channel.send_line("edit " + vdom)
            time.sleep(0.3); captured.append(drain())
        for c in cmds:
            channel.send_line(c); time.sleep(0.15); captured.append(drain())
        deadline = time.time() + window
        last = time.time()
        while time.time() < deadline:
            chunk = drain()
            if chunk:
                captured.append(chunk); last = time.time()
            elif time.time() - last > 1.0:
                break
            else:
                time.sleep(0.2)
    finally:
        try:
            channel.send_line("diagnose sys session filter clear")
            if in_vdom and vdom:
                channel.send_line("end")
            time.sleep(0.1); captured.append(drain())
        except Exception:
            pass
    return "".join(captured)


_PROTO_NAME = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 58: "icmp6"}


def parse_sessions(text: str) -> List[dict]:
    out: List[dict] = []
    for b in re.split(r"(?=session info: proto=)", text):
        if "session info:" not in b:
            continue
        d: dict = {}
        m = re.search(r"proto=(\d+)", b)
        d["proto"] = _PROTO_NAME.get(int(m.group(1)), "proto" + m.group(1)) if m else "?"
        e = re.search(r"expire=(\d+)", b)
        if e:
            d["expire"] = e.group(1) + "s"
        st = re.search(r"^state=(.+)$", b, re.M)
        if st:
            d["state"] = st.group(1).strip()
        stat = re.search(r"statistic\(bytes/packets/allow_err\):\s*org=(\d+)/(\d+)/\d+\s*reply=(\d+)/(\d+)/\d+", b)
        if stat:
            d["org"] = stat.group(1) + "B / " + stat.group(2) + "pkt"
            d["reply"] = stat.group(3) + "B / " + stat.group(4) + "pkt"
        pol = re.search(r"policy_id=(\d+)", b)
        if pol and pol.group(1) != "4294967295":
            d["policy"] = "Policy-" + pol.group(1)
        sn = re.search(r"act=snat\s+([\d.]+:\d+)->[\d.]+:\d+\(([\d.]+:\d+)\)", b)
        if sn:
            d["SNAT"] = sn.group(1) + " -> " + sn.group(2)
        dn = re.search(r"act=dnat\s+([\d.]+:\d+)->([\d.]+:\d+)\(", b)
        if dn:
            d["DNAT"] = dn.group(1) + " -> " + dn.group(2)
        if re.search(r"\bofld-[OR]\b|npu info:", b):
            d["offload"] = "yes (NPU)"
        nor = re.search(r"no_ofld_reason:\s*(\S.+)$", b, re.M)
        if nor and "ofld-" not in b:
            d["offload"] = "no (" + nor.group(1).strip() + ")"
        out.append(d)
    return out


_DEMO_SESSIONS = """session info: proto=17 proto_state=01 duration=120 expire=59 timeout=0 flags=00000000 use=3
state=log may_dirty npu f00 
statistic(bytes/packets/allow_err): org=2664/3/1 reply=1346/2/1 tuples=2
orgin->sink: org pre->post, reply pre->post dev=35->5/5->35 gwy=192.168.1.1/192.168.11.20
hook=post dir=org act=snat 192.168.11.20:54617->216.58.205.246:443(192.168.1.100:54617)
hook=pre dir=reply act=dnat 216.58.205.246:443->192.168.1.100:54617(192.168.11.20:54617)
misc=0 policy_id=14 pol_uuid_idx=752 vd=0
npu_state=0x000c00 ofld-O ofld-R
npu info: flag=0x81/0x81, offload=8/8, ips_offload=0/0
session info: proto=6 proto_state=11 duration=120 expire=3579 timeout=3600 use=4
state=log may_dirty npu f00 log-start 
statistic(bytes/packets/allow_err): org=45408/620/1 reply=2392364/1676/1 tuples=3
orgin->sink: org pre->post, reply pre->post dev=34->5/5->34 gwy=192.168.1.1/192.168.30.34
hook=post dir=org act=snat 192.168.30.34:49668->74.125.97.168:443(192.168.1.100:49668)
hook=pre dir=reply act=dnat 74.125.97.168:443->192.168.1.100:49668(192.168.30.34:49668)
misc=0 policy_id=2 pol_uuid_idx=749 vd=0
npu_state=0x003408 ofld-O
no_ofld_reason: 
ofld_fail_reason(kernel, drv): none/mac-unresolved, unknown(1)/none(0)
total session: 2
"""
