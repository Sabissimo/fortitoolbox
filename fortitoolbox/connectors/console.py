"""Live SSH console — a DEDICATED PTY channel, independent from the engine's
netmiko connection. A free-form console (arbitrary typing, --More--, Ctrl+C,
streaming debug) would desync netmiko's request/response state machine and could
break the automated checks; an isolated paramiko shell can desync or die without
touching them.

`MockConsole` mirrors the catalog fixtures so the demo console works with no
device. The account is read-only server-side; the client-side denylist is
defense-in-depth (and prevents accidental disruptive commands).
"""
from __future__ import annotations

import re

# Write/disruptive lines the read-only console always refuses to send.
_DENY = re.compile(
    r"^\s*("
    r"config\b(?!\s+(global|vdom))"                # config ... (except global/vdom navigation)
    r"|set\b|unset\b|delete\b|purge\b|append\b"     # config-mode writes
    r"|execute\s+(factoryreset|restore|reboot|shutdown|formatlogdisk|backup|disconnect-admin-session)"
    r")",
    re.IGNORECASE,
)


def is_blocked(cmd: str) -> bool:
    return bool(_DENY.match(cmd or ""))


class ConsoleSession:
    """Dedicated interactive shell over its own paramiko transport."""

    def __init__(self, host: str, username: str, password: str, port: int = 22,
                 verify_host_key: bool = False):
        self.host, self.username, self.password = host, username, password
        self.port, self.verify_host_key = port, verify_host_key
        self._client = None
        self._chan = None
        self._prelude = ""

    def open(self) -> None:
        import paramiko  # lazy (ships with netmiko)
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        c.set_missing_host_key_policy(
            paramiko.RejectPolicy() if self.verify_host_key else paramiko.AutoAddPolicy())
        c.connect(self.host, port=self.port, username=self.username,
                  password=self.password, timeout=15,
                  look_for_keys=False, allow_agent=False)
        self._client = c
        ch = c.invoke_shell(width=220, height=50)
        ch.settimeout(0.0)
        try:
            ch.get_transport().set_keepalive(30)
        except Exception:
            pass
        self._chan = ch
        # Prime: drain the login banner / first prompt before any command is sent,
        # otherwise the first command races the shell startup and is lost.
        import time as _t
        buf = b""
        end = _t.time() + 2.5
        last = _t.time()
        while _t.time() < end:
            try:
                if ch.recv_ready():
                    buf += ch.recv(65536); last = _t.time()
                elif buf and _t.time() - last > 0.4:
                    break
                else:
                    _t.time() and _t.sleep(0.1)
            except Exception:
                break
        self._prelude = buf.decode("utf-8", "replace")

    @property
    def is_open(self) -> bool:
        return self._chan is not None and not self._chan.closed

    def read_available(self) -> str:
        pre, self._prelude = self._prelude, ""
        if not self._chan:
            return pre
        out = b""
        try:
            while self._chan.recv_ready():
                out += self._chan.recv(65536)
        except Exception:
            pass
        return pre + out.decode("utf-8", "replace")

    def send_line(self, text: str) -> None:
        if self._chan:
            self._chan.send(text + "\n")

    def send_ctrl_c(self) -> None:
        if self._chan:
            self._chan.send("\x03")

    def kill_debug(self) -> None:
        """Cancel any running debug: Ctrl+C, then disable + reset (FortiOS canon)."""
        if not self._chan:
            return
        self._chan.send("\x03")
        self._chan.send("diagnose debug disable\n")
        self._chan.send("diagnose debug reset\n")

    def close(self) -> None:
        try:
            if self._chan:
                self._chan.close()
            if self._client:
                self._client.close()
        finally:
            self._chan = None
            self._client = None


class MockConsole:
    """Demo console: echoes catalog fixtures so the panel works without a device."""

    def __init__(self, hostname: str = "FW-EDGE-MAD-01"):
        from .mock import _FIXTURES
        self._fx = _FIXTURES
        self._host = hostname
        self._buf = self._prompt()

    def _prompt(self) -> str:
        return self._host + " # "

    def open(self) -> None:
        pass

    @property
    def is_open(self) -> bool:
        return True

    def read_available(self) -> str:
        b, self._buf = self._buf, ""
        return b

    def send_line(self, text: str) -> None:
        cmd = text.strip()
        if not cmd:
            self._buf += "\n" + self._prompt()
            return
        out = self._fx.get(cmd)
        if out is None:
            for key in self._fx:
                if key.startswith("execute ping") and cmd.split()[0:2] == key.split()[0:2]:
                    out = self._fx[key]
                    break
        if out is None:
            out = "(mock) no fixture for: " + cmd + "\n"
        self._buf += text + "\n" + out + self._prompt()

    def send_ctrl_c(self) -> None:
        self._buf += "^C\n" + self._prompt()

    def kill_debug(self) -> None:
        self._buf += "^C\ndiagnose debug disable\ndiagnose debug reset\n" + self._prompt()

    def close(self) -> None:
        pass
