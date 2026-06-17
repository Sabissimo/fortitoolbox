"""Engine: orchestrates connect -> detect version -> capability probe ->
run selected checks -> parse -> verdict. Connector-agnostic.
"""
from __future__ import annotations

import os
import re
import threading
from typing import Dict, List, Optional

import yaml

from .connectors.base import Connector, DeviceInfo
from .parsers import get_parser
from .verdict import CheckResult, Status

_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "catalog.yaml")


def load_catalog(path: str = _CATALOG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class Engine:
    def __init__(self, connector: Connector, catalog: Optional[dict] = None):
        self.conn = connector
        self.catalog = catalog or load_catalog()
        self.device = DeviceInfo()
        self.active_vdom: Optional[str] = None
        self._lock = threading.Lock()  # serialize device access (single SSH channel)
        self.checks = {c["id"]: c for c in self.catalog["checks"]}

    # -- lifecycle ----------------------------------------------------------
    def connect_and_probe(self, force_sysdiag: Optional[bool] = None) -> DeviceInfo:
        self.conn.connect()
        if hasattr(self.conn, "device_info"):
            self.device = self.conn.device_info()
        if self.device.sysdiag_enabled is None:
            if force_sysdiag is not None:
                # Operator asserts capability -> skip the (interactive) probe.
                self.device.sysdiag_enabled = force_sysdiag
            else:
                try:
                    self.device.sysdiag_enabled = self.conn.probe_sysdiag()
                except Exception:
                    self.device.sysdiag_enabled = False
        if self.device.vdom_mode and not self.device.vdoms:
            try:
                self.device.vdoms = self._enumerate_vdoms()
            except Exception:
                self.device.vdoms = []
        if self.device.vdom_mode:
            vs = self.device.vdoms
            self.active_vdom = ("root" if "root" in vs
                                else (vs[0] if vs else (self.device.mgmt_vdom or "root")))
        else:
            self.active_vdom = None
        return self.device

    def _enumerate_vdoms(self) -> List[str]:
        cmd = self.catalog.get("vdom_list_cmd", "diagnose sys vd list")
        raw = self.conn.run(cmd, scope="global")
        seen: List[str] = []
        for n in re.findall(r"name=([\w.\-]+)", raw):
            if n.startswith("vsys_"):   # hidden system vdoms (vsys_ha, vsys_fgfm...)
                continue
            if n not in seen:
                seen.append(n)
        return seen

    def set_vdom(self, vdom: str) -> None:
        self.active_vdom = vdom

    def close(self):
        self.conn.close()

    # -- selection ----------------------------------------------------------
    def modules(self) -> List[str]:
        seen = []
        for c in self.catalog["checks"]:
            if c["module"] not in seen:
                seen.append(c["module"])
        return seen

    def selectable(self, include_advanced: bool = False) -> List[dict]:
        return [c for c in self.catalog["checks"]
                if include_advanced or not c.get("advanced")]

    def kit(self, name: str) -> List[str]:
        return [c["id"] for c in self.catalog["checks"] if name in (c.get("kits") or [])]

    # -- execution ----------------------------------------------------------
    def run_check(self, check_id: str) -> CheckResult:
        meta = self.checks[check_id]
        title, module = meta["title"], meta["module"]
        if meta.get("privilege") == "sysdiag" and self.device.sysdiag_enabled is False:
            r = CheckResult(check_id, module, title, status=Status.SKIPPED)
            r.headline = "Needs `system-diagnostics enable` on the admin profile"
            return r
        check_scope = meta.get("scope")
        out: Dict[str, str] = {}
        required: Dict[str, str] = {}   # non-optional cmds -> reject-guard scope
        try:
            for item in meta["cmds"]:
                cmd, cscope, optional = self._cmd_item(item, check_scope)
                cmd = self._fill(cmd)
                txt = self.conn.run(cmd, scope=cscope, vdom=self.active_vdom)
                out[cmd] = txt
                if not optional:
                    required[cmd] = txt
            # Optional per-interface hardware NIC expansion (diagnose-grade).
            if meta.get("expand_nic") and self.device.sysdiag_enabled:
                phys = out.get("get system interface physical", "")
                for port in re.findall(r"name:\s*(\S+)", phys):
                    c = f"diagnose hardware deviceinfo nic {port}"
                    out[c] = self.conn.run(c, scope=check_scope, vdom=self.active_vdom)
        except Exception as exc:  # noqa: BLE001
            r = CheckResult(check_id, module, title, status=Status.ERROR)
            r.headline = f"Execution error: {exc}"
            r.raw = "\n".join(f"{k}\n{v}" for k, v in out.items())
            return r
        # Reject-guard only on REQUIRED cmds (optional ones may fail silently).
        reject = re.compile(
            r"command parse error|unknown action|permission denied|"
            r"command fail|return code -\d", re.I)
        if any(reject.search(v or "") for v in required.values()):
            r = CheckResult(check_id, module, title, status=Status.ERROR)
            r.headline = "Device rejected the command (privilege or syntax)"
            r.raw = "\n".join(f"{k}\n{v}" for k, v in out.items())
            return r
        try:
            return get_parser(check_id)(meta, out, self.device)
        except Exception as exc:  # noqa: BLE001 - never let a parser kill the run
            r = CheckResult(check_id, module, title, status=Status.ERROR)
            r.headline = f"Parser error: {exc}"
            r.raw = "\n".join(f"{k}\n{v}" for k, v in out.items())
            return r

    def run_many(self, check_ids: List[str]) -> List[CheckResult]:
        with self._lock:
            return [self.run_check(cid) for cid in check_ids]

    @staticmethod
    def _cmd_item(item, default_scope):
        """A cmds entry is either a string (inherits check scope) or a dict
        {cmd, scope?, optional?}."""
        if isinstance(item, dict):
            return item["cmd"], item.get("scope", default_scope), bool(item.get("optional"))
        return item, default_scope, False

    def _fill(self, cmd: str) -> str:
        if "{fqdn}" in cmd:
            fqdns = self.catalog.get("critical_fqdns") or ["www.fortinet.com"]
            cmd = cmd.replace("{fqdn}", fqdns[0])
        return cmd
