"""Read-only SSH connector (netmiko).

Least-privilege design: a plain read-only admin runs get/show plus the diagnose
reads that an accprofile with `system-diagnostics enable` permits -- it writes
no config. The stock netmiko fortinet driver tries to DISABLE OUTPUT PAGING via
config ("config system console" / "set output standard" / "end"); a read-only
admin cannot enter config, the commands are rejected, netmiko still flips its
flag, paging stays in "more", the `--More--` pager is never consumed and the
session desyncs. Fix: `_ReadOnlyFortinetSSH` never sends config and `run()`
consumes the pager itself.

Multi-VDOM scoping (`scope="global"|"vdom"`) wraps the command in
`config global` or `config vdom` + `edit <vdom>` (navigation only -- no `set`),
with the matching `end` always issued in a finally block. NOTE: that read-only
admins may navigate config submodes is environment/role dependent -- VALIDATE on
a real multi-VDOM device.

netmiko is imported lazily so logic/mock mode work without it installed.
"""
from __future__ import annotations

import re

from .base import Connector, DeviceInfo

_PROMPT = r"[#$]\s*$"            # FortiGate prompt (root/global/vdom all end #/$)
_NAV = r"[)#$]\s*$"             # prompt after entering config global/vdom
_MORE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|--More--|\r")  # pager + CR + ANSI


def _strip_more(text: str) -> str:
    """Remove FortiGate `--More--` pager artefacts and stray CRs/ANSI."""
    text = re.sub(r"\x08+\s*\x08*", "", text)          # backspace erase runs
    text = _MORE_RE.sub("", text)                       # --More--, ANSI, CR
    text = re.sub(r"[ \t]+\n", "\n", text)              # trailing ws
    text = re.sub(r"\n{3,}", "\n\n", text)              # collapse blank runs
    return text


class SSHConnector(Connector):
    name = "ssh"

    def __init__(self, host: str, username: str, password: str,
                 port: int = 22, timeout: int = 20, verify_host_key: bool = False):
        self.host, self.username, self.password = host, username, password
        self.port, self.timeout = port, timeout
        self.verify_host_key = verify_host_key  # True => reject unknown host keys (MITM-safe)
        self._conn = None
        self._vdom_mode = False
        self._mgmt_vdom = "root"

    def connect(self) -> None:
        from netmiko.fortinet.fortinet_ssh import FortinetSSH  # lazy

        class _ReadOnlyFortinetSSH(FortinetSSH):
            """Fortinet driver that issues no config. A read-only admin cannot
            run `config system console`; leave paging as-is and consume the
            --More-- pager in SSHConnector.run()."""

            def disable_paging(self, *args, **kwargs):  # noqa: D401
                return ""

            def cleanup(self, command: str = "exit"):
                try:
                    return super(FortinetSSH, self).cleanup(command=command)
                except Exception:
                    return None

        self._conn = _ReadOnlyFortinetSSH(
            host=self.host, username=self.username, password=self.password,
            port=self.port, conn_timeout=self.timeout, fast_cli=False,
            ssh_strict=self.verify_host_key, system_host_keys=self.verify_host_key,
        )

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.disconnect()
            finally:
                self._conn = None

    # -- command execution --------------------------------------------------
    def _run_paged(self, command: str, read_timeout: int = 90) -> str:
        conn = self._conn
        wait = r"--More--|" + _PROMPT
        out = conn.send_command(command, expect_string=wait, read_timeout=read_timeout,
                                strip_prompt=False, strip_command=False)
        pages = [out]
        guard = 0
        while "--More--" in out[-40:]:
            guard += 1
            if guard > 5000:
                break
            conn.write_channel(" ")
            try:
                out = conn.read_until_pattern(pattern=wait, read_timeout=read_timeout)
            except Exception:
                break
            pages.append(out)
        return _strip_more("".join(pages)).strip("\n")

    def run(self, command: str, scope=None, vdom=None) -> str:
        if not self._conn:
            raise RuntimeError("not connected")
        if not (self._vdom_mode and scope in ("global", "vdom")):
            return self._run_paged(command)
        conn = self._conn
        if scope == "global":
            enter = ["config global"]
        else:
            enter = ["config vdom", f"edit {vdom or self._mgmt_vdom or 'root'}"]
        for c in enter:
            conn.send_command(c, expect_string=_NAV, read_timeout=30,
                              strip_prompt=False, strip_command=False)
        try:
            return self._run_paged(command)
        finally:
            try:  # always leave the config context, even on read error
                conn.send_command("end", expect_string=_NAV, read_timeout=30,
                                  strip_prompt=False, strip_command=False)
            except Exception:
                pass

    # -- identity / capability ---------------------------------------------
    def device_info(self) -> DeviceInfo:
        raw = self.run("get system status")
        info = DeviceInfo()
        for line in raw.splitlines():
            low = line.lower().strip()
            if low.startswith("version:"):
                info.full_version = line.split(":", 1)[1].strip()
                toks = info.full_version.split()
                if toks:                       # model = platform string, any family
                    info.model = toks[0]       # FortiGate-100F, FortiWiFi-80F-2R, ...
                for tok in toks:
                    if tok.startswith("v") and "." in tok:
                        info.version = ".".join(tok.lstrip("v").split(".")[:2])
            elif low.startswith("serial-number:"):
                info.serial = line.split(":", 1)[1].strip()
            elif low.startswith("hostname:"):
                info.hostname = line.split(":", 1)[1].strip()
            elif low.startswith("current time:"):
                info.now = _parse_device_time(line.split(":", 1)[1].strip())
            elif low.startswith("virtual domain configuration:"):
                mode = line.split(":", 1)[1].strip().lower()
                info.vdom_mode = mode in ("enable", "multiple", "split-task")
            elif low.startswith("current virtual domain:"):
                info.mgmt_vdom = line.split(":", 1)[1].strip() or "root"
        # remember for scoped run() calls
        self._vdom_mode = info.vdom_mode
        self._mgmt_vdom = info.mgmt_vdom or "root"
        return info


def _parse_device_time(s: str):
    """Parse 'Tue Jun  9 09:14:02 2026' (FortiGate get system status clock)."""
    import datetime as _dt
    s = " ".join(s.split())
    for fmt in ("%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y"):
        try:
            return _dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None
