"""Connector interface. A connector turns a CLI command into raw text.

The whole pipeline downstream (parse -> verdict -> obfuscate -> present) is
identical regardless of which connector produced the text, so adding a new
transport (API, paste-mode) never touches the engine or the UI.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DeviceInfo:
    model: str = "unknown"
    version: str = "unknown"      # e.g. "7.6"
    full_version: str = ""        # e.g. "v7.6.2 build1234"
    serial: str = "unknown"
    hostname: str = ""
    sysdiag_enabled: Optional[bool] = None   # filled by capability probe
    now: Optional[_dt.datetime] = None       # device clock (get system status Current Time)
    vdom_mode: bool = False                   # multi-VDOM device?
    vdoms: List[str] = field(default_factory=list)   # all VDOM names
    mgmt_vdom: str = "root"                    # management / current VDOM


class Connector:
    name = "base"

    def connect(self) -> None: ...
    def close(self) -> None: ...

    def run(self, command: str, scope: Optional[str] = None,
            vdom: Optional[str] = None) -> str:
        """Run one read-grade command, return raw text output.

        scope: None | "global" | "vdom". On multi-VDOM devices the connector
        scopes the command (config global / config vdom + edit). Connectors
        that do not need scoping (mock, paste) ignore it.
        """
        raise NotImplementedError

    # capability probe: can this account run diagnose (system-diagnostics)?
    def probe_sysdiag(self) -> bool:
        out = self.run("diagnose sys top 1 1")
        bad = ("permission" in out.lower() or "unknown action" in out.lower()
               or "command parse error" in out.lower() or out.strip() == "")
        return not bad
