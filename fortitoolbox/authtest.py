"""Authentication test (diagnose test authserver) for LDAP / RADIUS / TACACS+.
The matched groups are the key output. Optional fnbamd verbose for deep failures.
SAML is NOT testable via CLI.

Syntax (docs.fortinet.com 283783396):
  diagnose test authserver ldap    <server> <user> <pass>
  diagnose test authserver tacacs+ <server> <user> <pass>
  diagnose test authserver radius  <server> <scheme> <user> <pass>   (pap|chap|mschap|mschap2)

SECURITY: the operator's password is sent only to run the test; it is masked in
the UI, never persisted, never copied for the LLM, and SCRUBBED from captured
output (the command echo and fnbamd debug would otherwise contain it).
"""
from __future__ import annotations

import re
import time
from typing import Dict, List

ENUM_CMDS = {"ldap": "get user ldap", "radius": "get user radius",
             "tacacs+": "get user tacacs+"}
RADIUS_SCHEMES = ["pap", "chap", "mschap", "mschap2"]


def parse_servers(text: str) -> List[str]:
    names = re.findall(r"^==\s*\[\s*(\S+)\s*\]", text, re.M)
    if not names:
        names = re.findall(r"^name\s*[:=]\s*\"?([^\"\n]+)\"?", text, re.M)
    out: List[str] = []
    for n in names:
        n = n.strip()
        if n and n not in out:
            out.append(n)
    return out


def build_authtest_cmd(proto: str, server: str, user: str, pwd: str,
                       scheme: str = "pap") -> str:
    srv = '"' + server + '"' if " " in server else server
    if proto == "radius":
        return "diagnose test authserver radius %s %s %s %s" % (srv, scheme, user, pwd)
    return "diagnose test authserver %s %s %s %s" % (proto, srv, user, pwd)


def run_authtest(channel, vdom, proto, server, user, pwd, scheme="pap",
                 fnbamd=False, in_vdom=True) -> str:
    cap: List[str] = []

    def drain():
        try:
            return channel.read_available()
        except Exception:
            return ""
    cmd = build_authtest_cmd(proto, server, user, pwd, scheme)
    try:
        if in_vdom and vdom:
            channel.send_line("config vdom"); channel.send_line("edit " + vdom)
            time.sleep(0.3); cap.append(drain())
        if fnbamd:
            channel.send_line("diagnose debug reset")
            channel.send_line("diagnose debug application fnbamd -1")
            channel.send_line("diagnose debug enable")
            time.sleep(0.2); cap.append(drain())
        channel.send_line(cmd)
        deadline = time.time() + 15
        last = time.time()
        started = False
        while time.time() < deadline:
            c = drain()
            if c:
                cap.append(c); last = time.time(); started = True
            elif started and time.time() - last > 2.0:
                break
            else:
                time.sleep(0.2)
    finally:
        try:
            if fnbamd:
                channel.send_line("diagnose debug disable")
                channel.send_line("diagnose debug reset")
            if in_vdom and vdom:
                channel.send_line("end")
            time.sleep(0.1); cap.append(drain())
        except Exception:
            pass
    raw = "".join(cap)
    if pwd:
        raw = raw.replace(pwd, "********")     # scrub password from echo / debug
    return raw


def parse_authtest(text: str) -> dict:
    low = text.lower()
    status = "unknown"
    if re.search(r"\bfail|denied|reject|wrong|no such|invalid|timed?\s*out|unreachable|no response", low):
        status = "fail"
    if "succeeded" in low or "authentication success" in low or re.search(r"auth.*succe", low):
        status = "ok"
    groups: List[str] = []
    m = re.search(r"group membership\(s\)[^\n]*?[-:]\s*(.+)", text, re.I)
    if m:
        groups = [g.strip(",") for g in m.group(1).split() if g.strip(",")]
    if not groups:
        groups = re.findall(r"_?group(?:name)?\s*[:=]\s*\"?([^\"\n,]+)", text, re.I)
    return {"status": status, "groups": [g for g in groups if g], "raw": text}


def conclude_authtest(res: dict) -> List[str]:
    out: List[str] = []
    low = res["raw"].lower()
    if res["status"] == "ok":
        msg = "Authentication succeeded"
        if res["groups"]:
            msg += " — groups returned: " + ", ".join(res["groups"][:8])
        else:
            msg += " (no group membership returned — check group mapping if you rely on it)"
        out.append(msg + ".")
    elif res["status"] == "fail":
        if any(k in low for k in ("timed", "unreachable", "no response", "cannot connect")):
            out.append("Server unreachable / no response — check IP/port, routing from the "
                       "source interface, and that the FortiGate is an allowed NAS client.")
        elif any(k in low for k in ("wrong", "invalid cred", "denied", "reject", "bad password")):
            out.append("Credentials rejected — wrong user/password, or (RADIUS) wrong auth "
                       "scheme; try pap or mschap2. Enable fnbamd verbose for the exact reason.")
        elif any(k in low for k in ("no such user", "not found", "does not exist")):
            out.append("User not found on the server / outside the search base-DN.")
        else:
            out.append("Authentication failed — see raw output; enable fnbamd verbose for the "
                       "negotiation detail.")
    else:
        out.append("Could not determine the result — check the raw output.")
    return out
