"""Packet sniffer: smart filter -> diagnose sniffer packet (always per-VDOM,
verbosity 6 so the full Ethernet frame is captured), live streaming with Stop,
a readable packet summary, and a dependency-free hex->pcap writer (replicates
fgt2eth.pl logic in pure Python -- no scapy).

Output format per docs.fortinet.com "Performing a sniffer trace" (680228).
Verbosity 6 (= 3 + interface) gives the Ethernet frame hex needed for pcap.
"""
from __future__ import annotations

import datetime as _dt
import re
import struct
import time
from typing import List, Tuple

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IFACE = re.compile(r"^[A-Za-z][\w.\-]*$")
_PROTO = {"tcp", "udp", "icmp", "icmp6", "arp"}
# Structural BPF keywords -> if present, the user is writing raw BPF; pass through.
_BPF_STRUCT = {"host", "port", "net", "src", "dst", "and", "or", "not", "proto",
               "gateway", "less", "greater", "portrange"}


# --------------------------------------------------------------------------
def parse_sniffer_filter(text: str) -> Tuple[str, str]:
    """`tcp,443,1.1.1.1` -> ('any', 'host 1.1.1.1 and tcp and port 443').
    A leading interface name (`wan1 tcp 443`) is pulled out; raw BPF passes
    through untouched. Interface defaults to 'any'."""
    tokens = [t for t in re.split(r"[\s,;]+", text.strip()) if t]
    iface = "any"
    if tokens:
        t0 = tokens[0]
        low = t0.lower()
        if (_IFACE.match(t0) and low not in _PROTO and low not in _BPF_STRUCT
                and not _IPV4.match(t0) and not t0.isdigit()):
            iface = t0
            tokens = tokens[1:]
    if any(t.lower() in _BPF_STRUCT for t in tokens):
        bpf = " ".join(tokens)
    else:
        ips = [t for t in tokens if _IPV4.match(t)]
        ports = [t for t in tokens if t.isdigit() and 1 <= int(t) <= 65535]
        protos = [t.lower() for t in tokens if t.lower() in _PROTO]
        parts = ["host " + ip for ip in ips] + protos + ["port " + p for p in ports]
        bpf = " and ".join(parts)
    return iface, bpf


def build_sniffer_cmd(iface: str, bpf: str, count: int, verbosity: int = 6,
                      tsformat: str = "a") -> str:
    return ("diagnose sniffer packet " + (iface or "any") + " '" + (bpf or "") + "' " +
            str(verbosity) + " " + str(int(count)) + " " + tsformat)


# --------------------------------------------------------------------------
# Readable summary (Wireshark-like list) from the verbose header lines.
def parse_sniffer(text: str) -> List[dict]:
    """One dict per packet with summary fields + its own raw block (header + hex),
    so the UI can expand each packet to see its capture."""
    pkts: List[dict] = []
    cur = None
    for line in text.splitlines():
        m = re.match(
            r"\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+|\d+\.\d{3,})\s+"
            r"(.*?)(\d+\.\d+\.\d+\.\d+)\.?(\d+)?\s*->\s*"
            r"(\d+\.\d+\.\d+\.\d+)\.?(\d+)?:?\s*(.*)", line)
        if m:
            src = m.group(3) + ((":" + m.group(4)) if m.group(4) else "")
            dst = m.group(5) + ((":" + m.group(6)) if m.group(6) else "")
            cur = {"time": m.group(1), "iface": (m.group(2) or "").strip(),
                   "src": src, "dst": dst, "info": m.group(7).strip(), "raw": [line]}
            pkts.append(cur)
        elif cur is not None and re.match(r"\s*0x[0-9a-fA-F]", line):
            cur["raw"].append(line)
    for p in pkts:
        p["raw"] = "\n".join(p["raw"])
    return pkts


# --------------------------------------------------------------------------
# hex dump -> pcap (DLT_EN10MB). Pure struct, no dependencies.
def _parse_ts(line: str):
    m = re.match(r"\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)", line)
    if m:
        dt = _dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
        return int(dt.timestamp()), dt.microsecond
    m = re.match(r"\s*(\d+)\.(\d{3,})\b", line)
    if m:
        base = int(time.time())
        return base + int(m.group(1)), int(m.group(2).ljust(6, "0")[:6])
    return None


def _is_header(line: str) -> bool:
    return _parse_ts(line) is not None


def to_pcap(text: str, dlt: int = 1, snaplen: int = 65535) -> bytes:
    packets: List[Tuple[int, int, bytes]] = []
    cur_hex: List[str] = []
    cur_ts = None

    def flush():
        if cur_hex and cur_ts is not None:
            try:
                data = bytes.fromhex("".join(cur_hex))
            except ValueError:
                return
            if data:
                packets.append((cur_ts[0], cur_ts[1], data))

    for line in text.splitlines():
        hm = re.match(r"\s*0x[0-9a-fA-F]+\s+(.*)", line)
        if hm:
            chunk = re.split(r"\s{2,}", hm.group(1).rstrip(), 1)[0]   # hex before ASCII
            cur_hex.append("".join(re.findall(r"[0-9a-fA-F]{2,4}", chunk)))
            continue
        if _is_header(line):
            flush()
            cur_hex = []
            cur_ts = _parse_ts(line)
    flush()

    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, dlt)
    for sec, usec, data in packets:
        out += struct.pack("<IIII", sec, usec, len(data), len(data))
        out += data
    return bytes(out), len(packets)


# --------------------------------------------------------------------------
# Demo capture built from REAL frame bytes (so the demo pcap opens in Wireshark).
def _fgt_hexdump(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        words = " ".join((chunk[i:i + 2]).hex() for i in range(0, len(chunk), 2))
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("0x%04x   %-40s   %s" % (off, words, ascii_))
    return "\n".join(lines)


def _frame(src_mac, dst_mac, src_ip, dst_ip, proto, sport, dport, payload=b""):
    def ipb(s):
        return bytes(int(x) for x in s.split("."))
    eth = bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"
    if proto == 6:
        l4 = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 64240, 0, 0)
    else:
        l4 = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(l4)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0) + ipb(src_ip) + ipb(dst_ip)
    return eth + ip + l4


def demo_capture_text(iface="port1") -> str:
    now = _dt.datetime.now()
    f1 = _frame("18:c0:4d:aa:97:54", "d4:76:a0:90:af:00", "192.168.1.100", "8.8.8.8", 17, 51234, 53, b"\x12\x34")
    f2 = _frame("18:c0:4d:aa:97:54", "d4:76:a0:90:af:00", "192.168.1.100", "142.250.1.1", 6, 49668, 443)
    out = ["interfaces=[" + iface + "]", "filters=[host 8.8.8.8 or host 142.250.1.1]"]
    t1 = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    t2 = (now + _dt.timedelta(milliseconds=12)).strftime("%Y-%m-%d %H:%M:%S.%f")
    out.append(t1 + " " + iface + " out 192.168.1.100.51234 -> 8.8.8.8.53: udp 2")
    out.append(_fgt_hexdump(f1))
    out.append(t2 + " " + iface + " out 192.168.1.100.49668 -> 142.250.1.1.443: syn 100")
    out.append(_fgt_hexdump(f2))
    out.append("")
    out.append("2 packets received by filter")
    out.append("0 packets dropped by kernel")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
def run_sniffer(channel, vdom: str, cmd: str, in_vdom: bool = True,
                should_stop=None, on_progress=None, max_time: float = 180.0,
                settle: float = 2.0) -> str:
    """Run the sniffer (per-VDOM), stream output, stop on count / quiet / Stop
    (Ctrl-C), and always end the capture cleanly."""
    cap: List[str] = []
    stopped = False

    def drain():
        try:
            return channel.read_available()
        except Exception:
            return ""
    try:
        if in_vdom and vdom:
            channel.send_line("config vdom"); channel.send_line("edit " + vdom)
            time.sleep(0.3); cap.append(drain())
        channel.send_line(cmd)
        deadline = time.time() + max_time
        last = time.time()
        started = False
        while time.time() < deadline:
            if should_stop is not None and should_stop():
                if hasattr(channel, "send_ctrl_c"):
                    channel.send_ctrl_c()
                stopped = True
                end = time.time() + 1.5
                while time.time() < end:
                    c = drain()
                    if c:
                        cap.append(c)
                    time.sleep(0.2)
                break
            chunk = drain()
            if chunk:
                cap.append(chunk); last = time.time(); started = True
                if on_progress is not None:
                    on_progress(chunk)
                if "packets received by filter" in chunk:   # sniffer finished (count)
                    break
            elif started and time.time() - last > settle:
                break
            else:
                time.sleep(0.2)
    finally:
        try:
            if not stopped and hasattr(channel, "send_ctrl_c"):
                channel.send_ctrl_c()
            if in_vdom and vdom:
                channel.send_line("end")
            time.sleep(0.1); cap.append(drain())
        except Exception:
            pass
    return "".join(cap)
