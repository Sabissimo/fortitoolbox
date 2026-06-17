"""FortiToolbox dashboard (NiceGUI).

Design: an operator's instrumentation console. Ink/slate base, Fortinet-red
accent, verdict lamps as functional green/amber/red signals. The signature
element is the live verdict board (pass/warn/fail tally + device identity strip).
"""
from __future__ import annotations

import re

from typing import Dict, List, Optional

from nicegui import app, run, ui

from .connectors.base import DeviceInfo
from .connectors.mock import MockConnector
from .engine import Engine, load_catalog
from .obfuscation import obfuscate_bundle
from .verdict import CheckResult, Status

# ---- design tokens ---------------------------------------------------------
INK = "#0E1116"; PANEL = "#161B22"; PANEL2 = "#1C2330"; LINE = "#2A313C"
ACCENT = "#EE3124"            # Fortinet red, used with restraint
TXT = "#E6EDF3"; MUTED = "#8B949E"
LAMP = {
    Status.PASS: "#3FB950", Status.WARN: "#D29922", Status.FAIL: "#F85149",
    Status.INFO: "#58A6FF", Status.SKIPPED: "#6E7681", Status.ERROR: "#DB6D28",
}
LAMP_DEFAULT = "#30363D"

HEAD = f"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{ --ink:{INK}; --panel:{PANEL}; --line:{LINE}; --accent:{ACCENT}; }}
  body {{ background:{INK}; color:{TXT}; font-family:'Inter',sans-serif; }}
  .ftb-title {{ font-weight:700; letter-spacing:.5px; }}
  .ftb-mono, .nicegui-code, pre, code {{ font-family:'JetBrains Mono',monospace !important; }}
  .ftb-card {{ background:{PANEL}; border:1px solid {LINE}; border-radius:12px; }}
  .ftb-chip {{ background:{PANEL2}; color:{MUTED}; border:1px solid {LINE};
              border-radius:999px; padding:1px 9px; font-size:11px;
              font-family:'JetBrains Mono',monospace; }}
  .ftb-eyebrow {{ color:{MUTED}; font-size:11px; letter-spacing:2px; text-transform:uppercase; }}
  .ftb-lamp {{ width:11px; height:11px; border-radius:50%; box-shadow:0 0 8px currentColor; }}
  .ftb-totop {{ position:fixed; bottom:22px; right:22px; z-index:2000; opacity:0;
               transition:opacity .2s; pointer-events:none; }}
  .ftb-totop.show {{ opacity:1; pointer-events:auto; }}
</style>
<script>
  window.addEventListener('scroll', function() {{
    var b = document.querySelector('.ftb-totop');
    if (b) b.classList.toggle('show', window.scrollY > 300);
  }}, true);
</script>
"""


class State:
    def __init__(self):
        self.catalog = load_catalog()
        self.engine: Optional[Engine] = None
        self.device: Optional[DeviceInfo] = None
        self.results: Dict[str, CheckResult] = {}
        self.obf_serial = True
        self.token_style = "tagged"
        self.secret_policy = "drop"   # drop | mask
        self.filter_status = None     # drill-down: show only this Status
        self.busy = False             # a run is in progress
        self.console = None           # live SSH console session
        self.console_text = ""        # accumulated console output (for obfuscated copy)
        self.console_expert = False   # bypass the read-only denylist
        self.console_scroll = False   # force console to bottom after a send
        self.flow_filter = ""         # debug flow filter text
        self.flow_count = 10          # debug flow packet count
        self.flow_proto = "any"       # debug flow protocol filter
        self.flow_result = None       # {raw, traces, conclusions}
        self.flow_running = False
        self.flow_trace_idx = 0
        self.flow_stop = False        # operator pressed Stop
        self.flow_live_text = ""      # live capture tail
        self.flow_live_packets = 0    # packets seen so far
        self.flow_lookup = None       # policy-lookup result
        self.flow_raw_open = False    # keep Raw trace expansion open across packets
        self.flow_session = None      # live session correlation result
        self.snf_filter = ""          # sniffer filter text
        self.snf_count = 5000         # sniffer max packets
        self.snf_running = False
        self.snf_stop = False
        self.snf_live_text = ""
        self.snf_live_packets = 0
        self.snf_result = None        # {raw, summary, pcap, npk, cmd}
        self.auth_servers = None      # {proto: [server,...]} once enumerated
        self.auth_proto = "ldap"
        self.auth_server = ""
        self.auth_user = ""
        self.auth_scheme = "pap"
        self.auth_fnbamd = False
        self.auth_running = False
        self.auth_result = None        # {res, conclusions}  (password never stored)
        self.ref_filter = ""           # in-app reference search


S = State()


# ---- helpers ---------------------------------------------------------------
def _checks_in(module: str, advanced=False) -> List[dict]:
    return [c for c in S.catalog["checks"] if c["module"] == module
            and bool(c.get("advanced")) == advanced]


def _mask(serial: str) -> str:
    if not S.obf_serial or not serial or serial == "unknown":
        return serial or "—"
    return serial[:4] + "•" * max(0, len(serial) - 6) + serial[-2:]


# ---- refreshable pieces ----------------------------------------------------
@ui.refreshable
def identity_strip():
    d = S.device
    with ui.row().classes("items-center gap-6 w-full"):
        ui.label("FORTITOOLBOX").classes("ftb-title text-lg").style(f"color:{ACCENT}")
        ui.label("operator diagnostics").classes("ftb-eyebrow")
        ui.space()
        if d:
            for k, v in (("MODEL", d.model), ("VERSION", d.version),
                         ("SERIAL", _mask(d.serial)), ("HOST", d.hostname or "—")):
                with ui.column().classes("gap-0 items-end"):
                    ui.label(k).classes("ftb-eyebrow")
                    ui.label(v).classes("ftb-mono text-sm")
            cap = ("diagnose: enabled" if d.sysdiag_enabled
                   else "diagnose: OFF — click to override")
            ui.button(cap, on_click=_toggle_sysdiag).props("flat dense no-caps") \
                .classes("ftb-chip").tooltip(
                    "Toggle if your account has `system-diagnostics enable`") \
                .style(f"color:{'#3FB950' if d.sysdiag_enabled else '#D29922'}")
        else:
            ui.label("not connected").classes("ftb-chip")


def _set_filter(st):
    S.filter_status = None if (st is None or S.filter_status == st) else st
    tally_board.refresh()
    module_panel.refresh()


def _toggle_sysdiag():
    if not S.device:
        return
    S.device.sysdiag_enabled = not bool(S.device.sysdiag_enabled)
    identity_strip.refresh()
    ui.notify(
        f"diagnose {'enabled' if S.device.sysdiag_enabled else 'OFF'} "
        "(manual override) — re-run the sysdiag checks",
        type="info")


@ui.refreshable
def tally_board():
    counts = {s: 0 for s in Status}
    for r in S.results.values():
        counts[r.status] += 1
    order = [(Status.FAIL, "FAIL"), (Status.WARN, "WARN"), (Status.PASS, "PASS"),
             (Status.INFO, "INFO"), (Status.SKIPPED, "SKIP")]
    with ui.row().classes("gap-3 items-stretch"):
        for st, lbl in order:
            active = S.filter_status == st
            card = ui.card().classes("ftb-card items-center px-5 py-2 gap-0 cursor-pointer") \
                .style(f"min-width:78px;border-color:{LAMP[st] if active else LINE};"
                       f"box-shadow:{('0 0 0 1px ' + LAMP[st]) if active else 'none'}")
            with card:
                ui.label(str(counts[st])).classes("text-2xl ftb-title").style(f"color:{LAMP[st]}")
                ui.label(lbl).classes("ftb-eyebrow")
            card.on("click", lambda st=st: _set_filter(st))
        if S.filter_status is not None:
            with ui.column().classes("justify-center"):
                ui.button("show all", icon="filter_alt_off",
                          on_click=lambda: _set_filter(None)).props("flat dense no-caps") \
                    .style(f"color:{MUTED}")


def _lamp(color: str):
    ui.element("div").classes("ftb-lamp").style(f"background:{color};color:{color}")


def _render_card(check: dict):
    r = S.results.get(check["id"])
    status = r.status if r else None
    color = LAMP.get(status, LAMP_DEFAULT)
    with ui.card().classes("ftb-card w-full p-4 gap-2"):
        with ui.row().classes("items-center gap-3 w-full no-wrap"):
            _lamp(color)
            ui.label(check["title"]).classes("text-sm font-semibold")
            if check.get("verify"):
                ui.label("verify-syntax").classes("ftb-chip")
            if check.get("privilege") == "sysdiag":
                ui.label("diagnose").classes("ftb-chip")
            ui.space()
            ui.button(icon="play_arrow",
                      on_click=lambda c=check: run_ids([c["id"]], c["title"])) \
                .props("flat dense round size=sm").tooltip("Run this check")
            ui.label((status.value.upper() if status else "NOT RUN")).classes(
                "ftb-mono text-xs").style(f"color:{color}")
        ui.label(r.headline if r else "—").classes("text-xs").style(f"color:{MUTED}")
        if r and r.metrics:
            with ui.row().classes("gap-2 flex-wrap"):
                for k, v in r.metrics:
                    ui.label(f"{k}: {v}").classes("ftb-chip")
        if r and r.raw.strip():
            with ui.expansion("Raw output").classes("w-full ftb-mono").props("dense"):
                ui.code(r.raw).classes("w-full ftb-mono text-xs")


@ui.refreshable
def module_panel(module: str):
    cs = _checks_in(module)
    if S.filter_status is not None:
        cs = [c for c in cs
              if S.results.get(c["id"]) and S.results[c["id"]].status == S.filter_status]
        if not cs:
            ui.label(f"No {S.filter_status.value.upper()} checks in this module") \
                .classes("text-xs").style(f"color:{MUTED}")
            return
    for c in cs:
        _render_card(c)


def _do_flow(filter_text, count, proto="any"):
    from .debugflow import parse_filter, run_debug_flow, parse_flow, conclude, MockFlowChannel
    from .connectors.console import ConsoleSession
    conn = S.engine.conn
    vdom = S.engine.active_vdom or "root"
    if getattr(conn, "name", "") == "mock":
        ch, in_vdom, owned = MockFlowChannel(), False, True
    else:
        ch = ConsoleSession(conn.host, conn.username, conn.password,
                            getattr(conn, "port", 22), getattr(conn, "verify_host_key", False))
        ch.open()
        in_vdom, owned = bool(S.device and S.device.vdom_mode), True
    try:
        eff = filter_text + ((" " + proto) if proto and proto != "any" else "")
        cmds, _ = parse_filter(eff)
        raw = run_debug_flow(ch, vdom, cmds, int(count), in_vdom=in_vdom,
                             should_stop=lambda: S.flow_stop, on_progress=_flow_progress)
    finally:
        if owned:
            try:
                ch.close()
            except Exception:
                pass
    traces = parse_flow(raw)
    return {"raw": raw, "traces": traces, "conclusions": conclude(traces)}


def _flow_progress(chunk):
    S.flow_live_packets += chunk.count("received a packet")
    S.flow_live_text = (S.flow_live_text + chunk)[-4000:]


def _flow_stop_now():
    S.flow_stop = True
    ui.notify("Stopping capture and cleaning up…", type="info")


def _do_session(t):
    from .debugflow import session_from_trace, run_session, parse_sessions, MockFlowChannel
    from .connectors.console import ConsoleSession
    conn = S.engine.conn
    vdom = S.engine.active_vdom or "root"
    if getattr(conn, "name", "") == "mock":
        ch, in_vdom = MockFlowChannel(), False
    else:
        ch = ConsoleSession(conn.host, conn.username, conn.password,
                            getattr(conn, "port", 22), getattr(conn, "verify_host_key", False))
        ch.open()
        in_vdom = bool(S.device and S.device.vdom_mode)
    try:
        raw = run_session(ch, vdom, session_from_trace(t), in_vdom=in_vdom)
    finally:
        try:
            ch.close()
        except Exception:
            pass
    return parse_sessions(raw)


async def _flow_session():
    res = S.flow_result
    if not (res and res["traces"]):
        return
    t = res["traces"][min(S.flow_trace_idx, len(res["traces"]) - 1)]
    n = ui.notification("Looking up the live session…", spinner=True, timeout=None)
    try:
        S.flow_session = await run.io_bound(_do_session, t)
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Session lookup failed: {exc}", type="negative")
    finally:
        n.dismiss()
    flow_panel.refresh()


def _flow_to_sniffer():
    res = S.flow_result
    if not (res and res["traces"]):
        return
    t = res["traces"][min(S.flow_trace_idx, len(res["traces"]) - 1)]
    proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(t.proto, "")
    src = t.src.split(":")[0]
    dst = t.dst.split(":")[0]
    S.snf_filter = " ".join(x for x in [src, dst, proto] if x)
    ui.notify("Filter set in Packet Sniffer below", type="info")
    sniffer_panel.refresh()


def _flow_ai_copy():
    res = S.flow_result
    if not res:
        return
    summary = []
    for t in res["traces"]:
        summary.append(str(t.as_dict()))
    body = ("DEBUG FLOW\n" + res["raw"] + "\n\nPARSED:\n" + "\n".join(summary) +
            "\n\nCONCLUSIONS:\n" + "\n".join(res["conclusions"]))
    blob, obf = obfuscate_bundle({"debug_flow": body}, token_style=S.token_style,
                                 secret_policy=S.secret_policy, extra_literals=_console_literals())
    if obf.leak_check(blob):
        ui.notify("Leak-check not clean — not copied", type="negative")
        return
    ui.run_javascript(f"navigator.clipboard.writeText({blob!r})")
    ui.notify("Copied obfuscated flow for LLM", type="positive")


async def _run_debug_flow(filter_text, count, proto="any"):
    if not S.engine:
        ui.notify("Connect first", type="warning"); return
    if not (filter_text or "").strip():
        ui.notify("Enter a target: an IP, a port, or both (e.g. 10.0.0.5,443)", type="warning"); return
    if S.flow_running:
        ui.notify("A flow trace is already running", type="warning"); return
    S.flow_filter, S.flow_count, S.flow_proto = filter_text, int(count), proto
    S.flow_stop, S.flow_live_text, S.flow_live_packets = False, "", 0
    S.flow_lookup, S.flow_session = None, None
    S.flow_running = True
    flow_panel.refresh()
    try:
        S.flow_result = await run.io_bound(_do_flow, filter_text, int(count), proto)
        S.flow_trace_idx = 0
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Flow failed: {exc}", type="negative", multi_line=True)
    finally:
        S.flow_running = False
    flow_panel.refresh()


def _flow_step(delta):
    res = S.flow_result
    if not res or not res["traces"]:
        return
    S.flow_trace_idx = max(0, min(S.flow_trace_idx + delta, len(res["traces"]) - 1))
    flow_panel.refresh()


def _render_flow_pipeline(t):
    d = t.as_dict()
    dropped = t.verdict == "dropped"
    color = LAMP[Status.FAIL] if dropped else LAMP[Status.PASS]
    # (label, main, sub) -- IN carries the source, OUT the destination (origin/dest boxes)
    stages = [("IN", t.iface_in or "?", t.src or "")]
    if d.get("route"):
        stages.append(("ROUTE", d["route"], ""))
    if d.get("policy"):
        stages.append(("POLICY", d["policy"], ""))
    if d.get("SNAT"):
        stages.append(("SNAT", d["SNAT"], ""))
    if d.get("DNAT"):
        stages.append(("DNAT", d["DNAT"], ""))
    if d.get("inspected_by"):
        stages.append(("UTM", d["inspected_by"], ""))
    if d.get("offload"):
        stages.append(("OFFLOAD", d["offload"], ""))
    if not dropped:
        stages.append(("OUT", t.iface_out or "?", t.dst or ""))
    with ui.row().classes("items-stretch gap-1 flex-wrap w-full"):
        for i, (k, main, sub) in enumerate(stages):
            if i:
                ui.icon("arrow_forward").style(f"color:{MUTED};align-self:center")
            edge = k in ("IN", "OUT")
            with ui.column().classes("items-center gap-0 px-2 py-1") \
                    .style(f"background:{PANEL2};border:1px solid {color if edge else LINE};"
                           f"border-radius:8px;min-width:70px"):
                ui.label(k).classes("ftb-eyebrow").style(f"color:{color if edge else MUTED}")
                ui.label(str(main)).classes("text-xs ftb-mono")
                if sub:
                    ui.label(str(sub)).classes("text-xs ftb-mono").style(f"color:{MUTED}")
        if dropped:
            ui.icon("arrow_forward").style(f"color:{color};align-self:center")
            with ui.column().classes("items-center px-2 py-1") \
                    .style(f"background:{color}22;border:1px solid {color};border-radius:8px"):
                ui.label("DROP").classes("ftb-eyebrow").style(f"color:{color}")
                ui.label(t.drop_reason or "drop").classes("text-xs")
    ui.label(("DROPPED — " + (t.drop_reason or "")) if dropped else "ALLOWED") \
        .classes("text-xs font-semibold").style(f"color:{color}")


def _do_sniffer(filter_text, count):
    from .sniffer import parse_sniffer_filter, build_sniffer_cmd, run_sniffer, parse_sniffer, to_pcap
    from .connectors.console import ConsoleSession
    from .debugflow import MockFlowChannel
    conn = S.engine.conn
    vdom = S.engine.active_vdom or "root"
    if getattr(conn, "name", "") == "mock":
        ch, in_vdom = MockFlowChannel(), False
    else:
        ch = ConsoleSession(conn.host, conn.username, conn.password,
                            getattr(conn, "port", 22), getattr(conn, "verify_host_key", False))
        ch.open()
        in_vdom = bool(S.device and S.device.vdom_mode)
    iface, bpf = parse_sniffer_filter(filter_text)
    cmd = build_sniffer_cmd(iface, bpf, int(count))
    try:
        raw = run_sniffer(ch, vdom, cmd, in_vdom=in_vdom,
                          should_stop=lambda: S.snf_stop, on_progress=_snf_progress)
    finally:
        try:
            ch.close()
        except Exception:
            pass
    summary = parse_sniffer(raw)
    pcap, npk = to_pcap(raw)
    return {"raw": raw, "summary": summary, "pcap": pcap, "npk": npk, "cmd": cmd}


def _snf_progress(chunk):
    S.snf_live_packets += chunk.count("0x0000")
    S.snf_live_text = (S.snf_live_text + chunk)[-4000:]


def _snf_stop_now():
    S.snf_stop = True
    ui.notify("Stopping capture…", type="info")


def _snf_download():
    res = S.snf_result
    if not res or not res.get("pcap") or not res.get("npk"):
        ui.notify("Nothing captured to download", type="warning"); return
    ui.download(res["pcap"], "fortitoolbox-capture.pcap")


async def _run_sniffer(filter_text, count):
    if not S.engine:
        ui.notify("Connect first", type="warning"); return
    if S.snf_running:
        ui.notify("A capture is already running", type="warning"); return
    S.snf_filter, S.snf_count = filter_text, int(count)
    S.snf_stop, S.snf_live_text, S.snf_live_packets, S.snf_result = False, "", 0, None
    S.snf_running = True
    sniffer_panel.refresh()
    try:
        S.snf_result = await run.io_bound(_do_sniffer, filter_text or "any", int(count))
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Sniffer failed: {exc}", type="negative", multi_line=True)
    finally:
        S.snf_running = False
    sniffer_panel.refresh()


@ui.refreshable
def sniffer_panel():
    with ui.card().classes("ftb-card w-full p-4 gap-3"):
        with ui.row().classes("items-center gap-2"):
            ui.icon("wifi_tethering").style(f"color:{ACCENT}")
            ui.label("Packet Sniffer — capture to .pcap").classes("ftb-title text-sm")
        ui.label("Type what to capture — IP, port, protocol, and optionally an interface "
                 "(e.g.  wan1 tcp 443  or  tcp,443,8.8.8.8). No interface = any. Always "
                 "per-VDOM, full-frame so the .pcap opens straight in Wireshark.") \
            .classes("text-xs").style(f"color:{MUTED}")
        with ui.row().classes("items-end gap-3 w-full"):
            sflt = ui.input("Capture filter", value=S.snf_filter,
                            placeholder="e.g.  wan1 tcp 443   or   host 8.8.8.8") \
                .props("dark dense outlined").classes("grow ftb-mono")
            scnt = ui.number("Max packets", value=S.snf_count, min=1, max=100000) \
                .props("dark dense outlined").style("width:130px")
            run_props = "unelevated" + (" disable" if S.snf_running else "")
            ui.button("Capture", icon="fiber_manual_record",
                      on_click=lambda: _run_sniffer(sflt.value, scnt.value or 5000)) \
                .props(run_props).style(f"background:{ACCENT}")

        if S.snf_running:
            with ui.card().classes("ftb-card w-full p-3 gap-2").style(f"border-color:{ACCENT}55"):
                with ui.row().classes("items-center gap-3 w-full"):
                    ui.spinner(size="sm").style(f"color:{ACCENT}")
                    ui.label(f"Capturing… {S.snf_live_packets} packet(s)").classes("text-sm")
                    ui.space()
                    ui.button("Stop", icon="stop", on_click=_snf_stop_now) \
                        .props("dense unelevated").style(f"background:{LAMP[Status.FAIL]}")
                if S.snf_live_text.strip():
                    ui.code(S.snf_live_text[-1000:]).classes("w-full ftb-mono text-xs") \
                        .style("max-height:150px;overflow:auto")
            return

        res = S.snf_result
        if not res:
            return
        with ui.row().classes("items-center gap-2 flex-wrap"):
            ui.label(f"{res['npk']} packet(s) captured").classes("ftb-chip")
            dl_props = "unelevated" + ("" if res["npk"] else " disable")
            ui.button("Download .pcap", icon="download", on_click=_snf_download) \
                .props(dl_props).style(f"background:{ACCENT}")
            ui.label(res["cmd"]).classes("ftb-chip ftb-mono").style(f"color:{MUTED}")
        summ = res["summary"]
        if summ:
            if len(summ) > 300:
                ui.label(f"Showing first 300 of {len(summ)} packets (the .pcap has them all)") \
                    .classes("text-xs").style(f"color:{MUTED}")
            with ui.column().classes("w-full gap-0").style("max-height:430px;overflow:auto"):
                for pk in summ[:300]:
                    title = (pk["time"] + "   " + (pk["iface"] + "   " if pk["iface"] else "") +
                             pk["src"] + " → " + pk["dst"] + "   :   " + pk["info"])
                    with ui.expansion(title).classes("w-full ftb-mono").props("dense"):
                        ui.code(pk["raw"]).classes("w-full ftb-mono text-xs") \
                            .style("max-height:260px;overflow:auto")
        with ui.expansion("Full raw capture").classes("w-full ftb-mono").props("dense"):
            ui.code(res["raw"][-12000:]).classes("w-full ftb-mono text-xs") \
                .style("max-height:320px;overflow:auto")


@ui.refreshable
def flow_panel():
    with ui.card().classes("ftb-card w-full p-4 gap-3"):
        with ui.row().classes("items-center gap-2"):
            ui.icon("travel_explore").style(f"color:{ACCENT}")
            ui.label("Debug Flow — live packet trace").classes("ftb-title text-sm")
        ui.label("Trace live packets through the kernel. Enter what you want to follow — "
                 "an IP, a port, or both — and it picks the right filters for you.") \
            .classes("text-xs").style(f"color:{MUTED}")
        with ui.row().classes("items-end gap-3 w-full"):
            flt = ui.input("Target", value=S.flow_filter,
                           placeholder="e.g.  10.0.0.5,443   or   192.168.1.11   or   53") \
                .props("dark dense outlined").classes("grow ftb-mono")
            proto = ui.select(["any", "tcp", "udp", "icmp"], value=S.flow_proto, label="Protocol") \
                .props("dark dense outlined").style("width:120px")
            cnt = ui.number("Packets", value=S.flow_count, min=1, max=1000) \
                .props("dark dense outlined").style("width:110px")
            run_props = "unelevated" + (" disable" if S.flow_running else "")
            ui.button("Run flow", icon="play_arrow",
                      on_click=lambda: _run_debug_flow(flt.value, cnt.value or 10, proto.value)) \
                .props(run_props).style(f"background:{ACCENT}")

        # --- live comfort while capturing, with a Stop button ---
        if S.flow_running:
            with ui.card().classes("ftb-card w-full p-3 gap-2").style(f"border-color:{ACCENT}55"):
                with ui.row().classes("items-center gap-3 w-full"):
                    ui.spinner(size="sm").style(f"color:{ACCENT}")
                    ui.label(f"Capturing… {S.flow_live_packets} packet(s) so far") \
                        .classes("text-sm")
                    ui.space()
                    ui.button("Stop", icon="stop", on_click=_flow_stop_now) \
                        .props("dense unelevated").style(f"background:{LAMP[Status.FAIL]}")
                ui.label("Trace stops at the packet count, when traffic goes quiet, or when you "
                         "press Stop — then the debug is cleaned up automatically.") \
                    .classes("text-xs").style(f"color:{MUTED}")
                if S.flow_live_text.strip():
                    ui.code(S.flow_live_text[-1200:]).classes("w-full ftb-mono text-xs") \
                        .style(f"max-height:160px;overflow:auto")
            return

        res = S.flow_result
        if not res:
            return
        if res["conclusions"]:
            with ui.card().classes("ftb-card w-full p-3").style(f"border-color:{ACCENT}55"):
                ui.label("Conclusions").classes("ftb-eyebrow")
                for c in res["conclusions"]:
                    ui.label("• " + c).classes("text-xs")
        traces = res["traces"]
        if not traces:
            ui.label("No matching packets traced (no traffic hit the filter, or it was offloaded "
                     "before tracing).").classes("text-xs").style(f"color:{MUTED}")
            return
        # tools: policy lookup (no traffic) + obfuscated copy for LLM
        with ui.row().classes("items-center gap-2 flex-wrap"):
            ui.button("Live session", icon="lan", on_click=_flow_session) \
                .props("outline dense").tooltip("diagnose sys session list — the live session "
                                                "for this tuple (NAT, offload, bytes, expiry)")
            ui.button("Sniff this flow", icon="wifi_tethering", on_click=_flow_to_sniffer) \
                .props("outline dense").tooltip("Pre-fill the Packet Sniffer with this tuple")
            ui.button("Copy for LLM", icon="content_copy", on_click=_flow_ai_copy).props("flat dense")
        if S.flow_session is not None:
            with ui.card().classes("ftb-card w-full p-2 gap-1"):
                ui.label("Live session — " + (str(len(S.flow_session)) + " match(es)"
                         if S.flow_session else "no matching session")).classes("ftb-eyebrow")
                for sess in S.flow_session[:4]:
                    with ui.row().classes("gap-2 flex-wrap items-center"):
                        for k, v in sess.items():
                            ui.label(k + ": " + str(v)).classes("ftb-chip")
        n = len(traces)
        idx = min(S.flow_trace_idx, n - 1)
        with ui.row().classes("items-center gap-2"):
            ui.button(icon="chevron_left", on_click=lambda: _flow_step(-1)).props("flat dense round")
            ui.label(f"packet {idx + 1} / {n}").classes("ftb-chip")
            ui.button(icon="chevron_right", on_click=lambda: _flow_step(1)).props("flat dense round")
        _render_flow_pipeline(traces[idx])
        with ui.expansion("Raw trace", value=S.flow_raw_open).classes("w-full ftb-mono") \
                .props("dense").bind_value(S, "flow_raw_open"):
            ui.code("\n".join(traces[idx].msgs)).classes("w-full ftb-mono text-xs")


def _auth_load_servers():
    from .authtest import ENUM_CMDS, parse_servers
    out = {}
    for proto, cmd in ENUM_CMDS.items():
        try:
            out[proto] = parse_servers(
                S.engine.conn.run(cmd, scope="vdom", vdom=S.engine.active_vdom))
        except Exception:
            out[proto] = []
    return out


async def _auth_servers_click():
    if not S.engine:
        ui.notify("Connect first", type="warning"); return
    n = ui.notification("Loading auth servers…", spinner=True, timeout=None)
    try:
        S.auth_servers = await run.io_bound(_auth_load_servers)
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Could not load servers: {exc}", type="negative")
    finally:
        n.dismiss()
    auth_panel.refresh()


def _do_authtest(proto, server, user, pwd, scheme, fnbamd):
    from .authtest import run_authtest, parse_authtest, conclude_authtest
    from .connectors.console import ConsoleSession
    from .debugflow import MockFlowChannel
    conn = S.engine.conn
    vdom = S.engine.active_vdom or "root"
    if getattr(conn, "name", "") == "mock":
        ch, in_vdom = MockFlowChannel(), False
    else:
        ch = ConsoleSession(conn.host, conn.username, conn.password,
                            getattr(conn, "port", 22), getattr(conn, "verify_host_key", False))
        ch.open()
        in_vdom = bool(S.device and S.device.vdom_mode)
    try:
        raw = run_authtest(ch, vdom, proto, server, user, pwd, scheme, fnbamd, in_vdom=in_vdom)
    finally:
        try:
            ch.close()
        except Exception:
            pass
    res = parse_authtest(raw)
    return {"res": res, "conclusions": conclude_authtest(res)}


async def _run_authtest(proto, server, user, pwd, scheme, fnbamd):
    if not S.engine:
        ui.notify("Connect first", type="warning"); return
    if not (server and user):
        ui.notify("Pick a server and enter a username", type="warning"); return
    if not pwd:
        ui.notify("Enter the test password", type="warning"); return
    if S.auth_running:
        ui.notify("A test is already running", type="warning"); return
    S.auth_user, S.auth_server = user, server     # persist non-secret only
    S.auth_running = True
    auth_panel.refresh()
    n = ui.notification("Testing authentication…", spinner=True, timeout=None)
    try:
        S.auth_result = await run.io_bound(_do_authtest, proto, server, user, pwd, scheme, fnbamd)
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Auth test failed: {exc}", type="negative", multi_line=True)
    finally:
        S.auth_running = False
        n.dismiss()
    auth_panel.refresh()   # rebuilds the password field empty (never persisted)


@ui.refreshable
def auth_panel():
    from .authtest import RADIUS_SCHEMES
    with ui.card().classes("ftb-card w-full p-4 gap-3"):
        with ui.row().classes("items-center gap-2"):
            ui.icon("vpn_key").style(f"color:{ACCENT}")
            ui.label("Authentication test — LDAP / RADIUS / TACACS+").classes("ftb-title text-sm")
        ui.label("Test a configured auth server with operator credentials. The matched groups "
                 "are the key result. SAML is not testable via CLI. The password is sent only to "
                 "run the test — masked, never stored, never copied, scrubbed from output.") \
            .classes("text-xs").style(f"color:{MUTED}")
        if not S.auth_servers:
            ui.button("Load servers", icon="refresh", on_click=_auth_servers_click).props("outline dense")
        with ui.row().classes("items-end gap-3 w-full flex-wrap"):
            ui.select(["ldap", "radius", "tacacs+"], value=S.auth_proto, label="Protocol",
                      on_change=lambda e: (setattr(S, "auth_proto", e.value), auth_panel.refresh())) \
                .props("dark dense outlined").style("width:120px")
            servers = (S.auth_servers or {}).get(S.auth_proto, [])
            if servers:
                srv = ui.select(servers, value=(S.auth_server if S.auth_server in servers else servers[0]),
                                label="Server").props("dark dense outlined").style("width:180px")
            else:
                srv = ui.input("Server", value=S.auth_server).props("dark dense outlined").style("width:180px")
            usr = ui.input("Username", value=S.auth_user).props("dark dense outlined").style("width:160px")
            apwd = ui.input("Password", password=True).props("dark dense outlined").style("width:160px")
            sch = None
            if S.auth_proto == "radius":
                sch = ui.select(RADIUS_SCHEMES, value=S.auth_scheme, label="Scheme",
                                on_change=lambda e: setattr(S, "auth_scheme", e.value)) \
                    .props("dark dense outlined").style("width:120px")
        with ui.row().classes("items-center gap-3"):
            ui.switch("fnbamd verbose").bind_value(S, "auth_fnbamd") \
                .tooltip("Capture diagnose debug application fnbamd -1 during the test (auto-cleanup)")
            run_props = "unelevated" + (" disable" if S.auth_running else "")
            ui.button("Test auth", icon="login",
                      on_click=lambda: _run_authtest(S.auth_proto, srv.value, usr.value, apwd.value,
                                                     (sch.value if sch else "pap"), S.auth_fnbamd)) \
                .props(run_props).style(f"background:{ACCENT}")
        result = S.auth_result
        if not result:
            return
        res = result["res"]
        color = {"ok": LAMP[Status.PASS], "fail": LAMP[Status.FAIL]}.get(res["status"], LAMP[Status.INFO])
        ui.label(res["status"].upper()).classes("text-sm font-semibold").style(f"color:{color}")
        if res["groups"]:
            ui.label("Groups returned").classes("ftb-eyebrow")
            with ui.row().classes("gap-2 flex-wrap"):
                for g in res["groups"][:20]:
                    ui.label(g).classes("ftb-chip")
        for c in result["conclusions"]:
            ui.label("• " + c).classes("text-xs")
        with ui.expansion("Raw output (password scrubbed)").classes("w-full ftb-mono").props("dense"):
            ui.code(res["raw"][-6000:]).classes("w-full ftb-mono text-xs").style("max-height:260px;overflow:auto")


@ui.refreshable
def _ref_list():
    from .reference import REFERENCE, TOOLS_REF
    q = (S.ref_filter or "").lower()
    modules = []
    for c in S.catalog["checks"]:
        if not c.get("advanced") and c["module"] not in modules:
            modules.append(c["module"])
    for mod in modules:
        rows = []
        for c in S.catalog["checks"]:
            if c["module"] != mod or c.get("advanced"):
                continue
            cmds = [it["cmd"] if isinstance(it, dict) else it for it in c["cmds"]]
            ref = REFERENCE.get(c["id"], ("", ""))
            blob = (c["title"] + " " + " ".join(cmds) + " " + ref[0] + " " + ref[1]).lower()
            if q and q not in blob:
                continue
            rows.append((c, cmds, ref))
        if not rows:
            continue
        ui.label(mod).classes("ftb-eyebrow").style(f"color:{ACCENT}")
        for c, cmds, ref in rows:
            with ui.card().classes("ftb-card w-full p-3 gap-1"):
                with ui.row().classes("items-center gap-2 flex-wrap"):
                    ui.label(c["title"]).classes("text-sm font-semibold")
                    ui.label("scope: " + str(c.get("scope", "-"))).classes("ftb-chip")
                    ui.label(c.get("privilege", "read")).classes("ftb-chip")
                for cm in cmds:
                    ui.code(cm).classes("w-full ftb-mono text-xs")
                if ref[0]:
                    ui.label("Detects: " + ref[0]).classes("text-xs").style(f"color:{MUTED}")
                if ref[1]:
                    ui.label("Verdict: " + ref[1]).classes("text-xs")
    tools = [t for t in TOOLS_REF
             if not q or q in (t[0] + " " + " ".join(t[1]) + " " + t[2]).lower()]
    if tools:
        ui.label("Advanced — interactive tools").classes("ftb-eyebrow").style(f"color:{ACCENT}")
        for name, cmds, desc in tools:
            with ui.card().classes("ftb-card w-full p-3 gap-1"):
                ui.label(name).classes("text-sm font-semibold")
                for cm in cmds:
                    ui.code(cm).classes("w-full ftb-mono text-xs")
                ui.label(desc).classes("text-xs").style(f"color:{MUTED}")


def reference_panel():
    with ui.row().classes("items-center gap-2 w-full"):
        ui.icon("menu_book").style(f"color:{ACCENT}")
        ui.label("Command & verdict reference").classes("ftb-title text-sm")
        ui.label("works offline").classes("ftb-chip")
        ui.space()
        ui.input(placeholder="filter commands / checks…") \
            .props("dark dense outlined clearable").classes("ftb-mono").style("width:280px") \
            .bind_value(S, "ref_filter").on_value_change(_ref_list.refresh)
    _ref_list()


@ui.refreshable
def advanced_panel():
    with ui.card().classes("ftb-card w-full p-4").style(f"border-color:{ACCENT}55"):
        ui.label("Advanced connectivity required").classes("font-semibold").style(f"color:{ACCENT}")
        ui.markdown(
            "These are **stateful / interactive / write** tools and are never run "
            "automatically. To enable them on the FortiGate:\n"
            "- An admin profile with **`system-diagnostics enable`** (read-grade) for the deeper diagnoses.\n"
            "- `diagnose debug flow` / `sniffer` run a **global, timed** debug — impact + cleanup apply.\n"
            "- `diagnose test authserver` needs **operator-supplied credentials**; SAML is not CLI-testable.\n"
            "- Any write step is **generated for the operator to run**, never executed by the tool."
        ).classes("text-xs")
    sniffer_panel()
    flow_panel()
    auth_panel()
    for c in _checks_in(module="Advanced", advanced=True):
        if c["id"] in ("debug_flow", "sniffer", "auth_test"):   # replaced by interactive panels above
            continue
        with ui.card().classes("ftb-card w-full p-3 gap-1"):
            with ui.row().classes("items-center gap-3"):
                _lamp(LAMP_DEFAULT)
                ui.label(c["title"]).classes("text-sm font-semibold")
                ui.label("stateful").classes("ftb-chip")
            if c.get("note"):
                ui.label(c["note"]).classes("text-xs").style(f"color:{MUTED}")


@ui.refreshable
def vdom_selector():
    d = S.device
    if not (d and d.vdom_mode and d.vdoms):
        return
    with ui.row().classes("items-center gap-2"):
        ui.label("VDOM").classes("ftb-eyebrow")
        ui.select(options=d.vdoms, value=S.engine.active_vdom,
                  on_change=lambda e: _on_vdom_change(e.value)) \
            .props("dark dense outlined options-dense").style("min-width:170px")


def _on_vdom_change(v):
    if S.engine:
        S.engine.set_vdom(v)
        S.auth_servers = None
        ui.timer(0.3, _auth_servers_click, once=True)
        ui.notify(f"Active VDOM: {v}", type="info")


def _refresh_all():
    # NiceGUI's refreshable.refresh(*args) OVERWRITES the stored args of EVERY
    # target of the refreshable (refreshable.py: `target.args = args or
    # target.args`). Passing the module name therefore re-rendered all tabs with
    # the last module. Refresh with no args so each panel keeps its own module.
    identity_strip.refresh(); tally_board.refresh(); vdom_selector.refresh()
    module_panel.refresh()


# ---- actions ---------------------------------------------------------------
async def do_connect(host, user, pwd, use_mock, dialog, use_vdom_demo=False, force_diag=False):
    n = ui.notification("Connecting…", spinner=True, timeout=None)
    try:
        if use_mock:
            S.engine = Engine(MockConnector(vdom=use_vdom_demo))
        else:
            from .connectors.ssh import SSHConnector
            raw = (host.value or "").strip()
            mport = re.match(r"^(.*\S):(\d{1,5})$", raw)
            h, port = (mport.group(1), int(mport.group(2))) if mport else (raw, 22)
            S.engine = Engine(SSHConnector(h, user.value, pwd.value, port=port))
        force = True if force_diag else None
        S.device = await run.io_bound(S.engine.connect_and_probe, force)
        S.results.clear()
        n.dismiss()
        dialog.close()
        _refresh_all()
        S.auth_servers = None
        ui.timer(0.5, _auth_servers_click, once=True)   # auto-populate auth-server dropdowns
        ui.notify(f"Connected: {S.device.model} {S.device.version}", type="positive")
    except Exception as exc:  # noqa: BLE001
        n.dismiss()
        ui.notify(f"Connection failed: {exc}", type="negative", multi_line=True)


async def run_ids(ids: List[str], label: str):
    if not S.engine:
        ui.notify("Connect first", type="warning"); return
    if S.busy:
        ui.notify("A run is already in progress", type="warning"); return
    S.busy = True
    n = ui.notification(f"Running {label}…", spinner=True, timeout=None)
    try:
        res = await run.io_bound(S.engine.run_many, ids)
    finally:
        S.busy = False
        n.dismiss()
    for r in res:
        S.results[r.id] = r
    _refresh_all()
    fails = sum(1 for r in res if r.status == Status.FAIL)
    warns = sum(1 for r in res if r.status == Status.WARN)
    skips = sum(1 for r in res if r.status == Status.SKIPPED)
    tail = f", {skips} skipped (need diagnose)" if skips else ""
    ui.notify(f"{label}: {fails} fail, {warns} warn{tail}",
              type="negative" if fails else ("warning" if (warns or skips) else "positive"))


def open_connect_dialog():
    with ui.dialog() as dialog, ui.card().classes("ftb-card p-5 gap-3").style("min-width:360px"):
        ui.label("Connect to FortiGate").classes("ftb-title")
        mock = ui.switch("Demo mode (simulated device)", value=False)
        vdom_demo = ui.switch("Simulate VDOMs (demo)", value=False)
        vdom_demo.bind_enabled_from(mock, "value")
        diagcap = ui.switch("Account has diagnose (system-diagnostics)", value=False)
        host = ui.input("Host / IP", placeholder="host  or  host:port  (default 22)").classes("w-full").props("dark dense outlined")
        user = ui.input("Username (read-only)").classes("w-full").props("dark dense outlined")
        pwd = ui.input("Password", password=True).classes("w-full").props("dark dense outlined")
        for f in (host, user, pwd):
            f.bind_enabled_from(mock, "value", lambda v: not v)
        pwd.on("keydown.enter", lambda: do_connect(
            host, user, pwd, mock.value, dialog, vdom_demo.value, diagcap.value))
        with ui.row().classes("w-full justify-end gap-2"):
            ui.button("Connect", on_click=lambda: do_connect(
                host, user, pwd, mock.value, dialog, vdom_demo.value, diagcap.value)) \
                .props("unelevated").style(f"background:{ACCENT}")
            ui.button("Cancel", on_click=dialog.close).props("flat")
    dialog.open()


def open_llm_dialog():
    if not S.results:
        ui.notify("Run some checks first", type="warning"); return
    raws = {cid: r.raw for cid, r in S.results.items() if r.raw.strip()}

    def _build():
        lits = []
        if S.device:
            if S.device.hostname:
                lits.append(S.device.hostname)
            lits += (S.device.vdoms or [])
        blob, obf = obfuscate_bundle(raws, token_style=S.token_style,
                                     secret_policy=S.secret_policy, extra_literals=lits)
        return blob, obf, obf.leak_check(blob)

    leak_state = {"leaks": []}
    blob, obf, leaks = _build()
    leak_state["leaks"] = leaks
    with ui.dialog() as dialog, ui.card().classes("ftb-card p-5 gap-3").style("min-width:680px;max-width:90vw"):
        with ui.row().classes("items-center w-full"):
            ui.label("Copy for LLM — obfuscated").classes("ftb-title")
            ui.space()
            vault_chip = ui.label(f"{len(obf.vault)} tokens vaulted").classes("ftb-chip")
            leak_chip = ui.label("LEAK CHECK: CLEAN" if not leaks else f"LEAKS: {len(leaks)}") \
                .classes("ftb-chip").style(f"color:{'#3FB950' if not leaks else '#F85149'}")
        desc = ui.label("").classes("text-xs").style(f"color:{MUTED}")
        ta = ui.textarea(value=blob).classes("w-full ftb-mono").props("dark outlined readonly rows=14")

        def _refresh():
            b, o, lk = _build()
            leak_state["leaks"] = lk
            ta.value = b
            copy_btn.set_enabled(not lk)
            copy_btn.tooltip("" if not lk else "Blocked: leak-check found un-obfuscated data")
            vault_chip.text = f"{len(o.vault)} tokens vaulted"
            leak_chip.text = "LEAK CHECK: CLEAN" if not lk else f"LEAKS: {len(lk)}"
            leak_chip.style(f"color:{'#3FB950' if not lk else '#F85149'}")
            desc.text = ("Serials, IPs, MACs, hosts, emails tokenized (reversible, vault stays "
                         "local). Secrets " + ("MASKED as <SECRET_n> — value discarded, never "
                         "vaulted nor sent." if S.secret_policy == "mask"
                         else "DROPPED entirely."))

        def _toggle(e):
            S.secret_policy = "mask" if e.value else "drop"
            _refresh()

        with ui.row().classes("items-center gap-2"):
            ui.switch("Mask secret fields as <SECRET_n> (vs drop)",
                      value=(S.secret_policy == "mask"), on_change=_toggle)

        def _do_copy():
            if leak_state["leaks"]:
                ui.notify("Copy blocked: leak-check is not clean", type="negative")
                return
            ui.run_javascript(f"navigator.clipboard.writeText({ta.value!r})")
            ui.notify("Copied obfuscated text", type="positive")

        with ui.row().classes("w-full justify-end gap-2"):
            ui.button("Close", on_click=dialog.close).props("flat")
            copy_btn = ui.button("Copy", on_click=_do_copy) \
                .props("unelevated").style(f"background:{ACCENT}")
        _refresh()
    dialog.open()


# ---- live SSH console -------------------------------------------------------
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|[\r\x00]")


def _console_literals():
    lits = []
    if S.device:
        if S.device.hostname:
            lits.append(S.device.hostname)
        lits += (S.device.vdoms or [])
    return lits


def _ensure_console() -> bool:
    if S.console is not None and S.console.is_open:
        return True
    if not S.engine:
        ui.notify("Connect first", type="warning")
        return False
    from .connectors.console import ConsoleSession, MockConsole
    conn = S.engine.conn
    try:
        if getattr(conn, "name", "") == "mock":
            S.console = MockConsole(hostname=(S.device.hostname if S.device else "FortiGate"))
        else:
            S.console = ConsoleSession(conn.host, conn.username, conn.password,
                                       getattr(conn, "port", 22),
                                       getattr(conn, "verify_host_key", False))
        S.console.open()
        return True
    except Exception as exc:  # noqa: BLE001
        ui.notify(f"Console failed: {exc}", type="negative", multi_line=True)
        S.console = None
        return False


def _copy_console():
    if not S.console_text.strip():
        ui.notify("Console is empty", type="warning"); return
    blob, obf = obfuscate_bundle({"console": S.console_text}, token_style=S.token_style,
                                 secret_policy=S.secret_policy, extra_literals=_console_literals())
    if obf.leak_check(blob):
        ui.notify("Leak-check not clean — not copied", type="negative"); return
    ui.run_javascript(f"navigator.clipboard.writeText({blob!r})")
    ui.notify("Copied obfuscated console", type="positive")


def _download_report():
    if not S.results:
        ui.notify("Run some checks first", type="warning"); return
    from .report import build_report_pdf
    ordered = [S.results[c["id"]] for c in S.catalog["checks"] if c["id"] in S.results]
    pdf = build_report_pdf(S.device, ordered,
                           active_vdom=(S.engine.active_vdom if S.engine else None))
    ui.download(pdf, "fortitoolbox-report.pdf")
    ui.notify("Report generated", type="positive")


# ---- layout ----------------------------------------------------------------
def build():
    ui.add_head_html(HEAD)
    ui.dark_mode().enable()
    ui.colors(primary=ACCENT, dark=INK)

    # --- live SSH console (right drawer) ---
    with ui.right_drawer(value=False, fixed=True).props("width=560 bordered") \
            .style(f"background:{PANEL};border-left:1px solid {LINE}") as console_drawer:
        with ui.column().classes("w-full h-full gap-2 p-3"):
            with ui.row().classes("items-center w-full gap-2"):
                ui.icon("terminal").style(f"color:{ACCENT}")
                ui.label("LIVE SSH CONSOLE").classes("ftb-title text-sm")
                ui.space()
                ui.button(icon="close", on_click=lambda: console_drawer.set_value(False)) \
                    .props("flat dense round")
            ui.label("RAW OUTPUT — not obfuscated. Do not paste into external tools.") \
                .classes("ftb-chip").style(f"color:{LAMP[Status.WARN]}")
            console_log = ui.log(max_lines=3000).classes("w-full ftb-mono text-xs grow") \
                .style(f"background:{INK};border:1px solid {LINE};border-radius:8px;min-height:340px")
            cmd_in = ui.input(placeholder="command + Enter  (read-only; expert mode to override)") \
                .classes("w-full ftb-mono").props("dark dense outlined")

            def _drain_console():
                if not S.console:
                    return
                try:
                    txt = S.console.read_available()
                except Exception:
                    return
                if txt:
                    clean = _ANSI.sub("", txt)
                    S.console_text += clean
                    if len(S.console_text) > 200000:
                        S.console_text = S.console_text[-200000:]
                    console_log.push(clean.rstrip("\n"))
                    if S.console_scroll:
                        S.console_scroll = False
                        ui.run_javascript(
                            "var e=document.querySelector('.nicegui-log');"
                            "if(e){e.scrollTop=e.scrollHeight;}")

            def _send_console():
                cmd = (cmd_in.value or "").strip()
                if not cmd or not _ensure_console():
                    return
                from .connectors.console import is_blocked
                if is_blocked(cmd) and not S.console_expert:
                    ui.notify("Blocked by read-only guard — enable expert to override",
                              type="negative")
                    return
                S.console.send_line(cmd)
                S.console_scroll = True
                cmd_in.value = ""

            cmd_in.on("keydown.enter", lambda: _send_console())

            with ui.row().classes("w-full gap-2 flex-wrap items-center"):
                ui.button("Send", icon="keyboard_return", on_click=_send_console) \
                    .props("dense unelevated").style(f"background:{ACCENT}")
                ui.button("Ctrl-C", icon="block",
                          on_click=lambda: _ensure_console() and S.console.send_ctrl_c()).props("dense outline")
                ui.button("Kill debug", icon="cleaning_services",
                          on_click=lambda: _ensure_console() and S.console.kill_debug()).props("dense outline")
                ui.button("Clear", icon="clear_all",
                          on_click=lambda: (console_log.clear(), setattr(S, "console_text", ""))).props("dense flat")
                ui.switch("expert").bind_value(S, "console_expert").props("dense")
                ui.space()
                ui.button("Obfuscate & copy", icon="content_copy", on_click=_copy_console).props("dense flat")

    ui.timer(0.15, _drain_console)
    ui.timer(0.4, lambda: (flow_panel.refresh() if S.flow_running else None,
                           sniffer_panel.refresh() if S.snf_running else None))

    with ui.header().classes("items-center px-6 py-3").style(f"background:{PANEL};border-bottom:1px solid {LINE}"):
        identity_strip()

    with ui.column().classes("w-full max-w-screen-xl mx-auto px-6 py-4 gap-4"):
        with ui.row().classes("items-center w-full gap-3"):
            tally_board()
            ui.space()
            ui.button("Connect", icon="cable", on_click=open_connect_dialog) \
                .props("unelevated").style(f"background:{ACCENT}")
            vdom_selector()
            ui.button("Quick health", icon="bolt",
                      on_click=lambda: run_ids(S.engine.kit("quick"), "Quick health")) \
                .props("outline")
            ui.button("Full sweep", icon="checklist",
                      on_click=lambda: run_ids(S.engine.kit("full"), "Full sweep")) \
                .props("outline")
            ui.button("Copy for LLM", icon="content_copy", on_click=open_llm_dialog).props("flat")
            ui.button("Report", icon="picture_as_pdf", on_click=_download_report).props("flat")
            ui.button("Console", icon="terminal",
                      on_click=lambda: (_ensure_console(), console_drawer.toggle())).props("flat")

        modules = [c["module"] for c in S.catalog["checks"]]
        modules = list(dict.fromkeys(modules))
        tab_names = modules + ["Reference"]
        with ui.tabs().classes("w-full").props("dense") as tabs:
            for m in tab_names:
                ui.tab(m)
        with ui.tab_panels(tabs, value=modules[0]).classes("w-full").style("background:transparent"):
            for m in tab_names:
                with ui.tab_panel(m).classes("gap-3"):
                    if m == "Reference":
                        reference_panel()
                        continue
                    with ui.row().classes("w-full justify-end"):
                        if m != "Advanced":
                            ui.button(f"Run all in {m}", icon="play_arrow",
                                      on_click=lambda mm=m: run_ids(
                                          [c["id"] for c in _checks_in(mm)], f"{mm}")).props("flat dense")
                    if m == "Advanced":
                        advanced_panel()
                    else:
                        module_panel(m)

    ui.button(icon="keyboard_arrow_up",
              on_click=lambda: ui.run_javascript("window.scrollTo({top:0,behavior:'smooth'})")) \
        .props("round").classes("ftb-totop").style(f"background:{ACCENT};color:white")


def main():
    """Console-script entry. Launching is centralized in __main__.serve()."""
    from .__main__ import serve
    serve(show=False)

