# FortiSwitch / FortiAP daily-check work — progress & next steps

> Working handoff doc. Last updated: 2026-06-19.
> Companion to the auto-memory note `fortiswitch-fortiap-validation-pending.md`.

## TL;DR — where we are

- The **existing** FortiSwitch + FortiAP checks (6 of them) are **shipped and validated** against real device output.
- **DONE this session (uncommitted, in working tree):**
  - `fap_radio` (#6–9) — new check: channel utilisation / noise / firmware / uptime from `-c wtp`. Validated in Demo (WARN) and against the **real `GC-AP-09`** output (PASS, peak util 3%).
  - `fsw_poe` (#5) — extended to flag per-port PoE faults (overload/short/denied) from the `poe summary` table it already parses. Demo seeds a faulted port → WARN.
- **Next action when we resume:** decide #2 (FortiSwitch firmware compliance) — see below — then optionally commit. Medium/high items (#1, #3, #4, #10, #11) deferred.

---

## 1. What already exists and is DONE (do not redo)

Shipped on `main`, all parsers calibrated to real FortiOS 7.6 output and matching mock fixtures updated:

| Check | Command | Commit |
|---|---|---|
| `fsw_managed` | `execute switch-controller get-conn-status` | `43313c6` |
| `fsw_sync` | `execute switch-controller get-sync-status all` | `b984177` |
| `fsw_poe` | `diagnose switch-controller switch-info poe summary` | `084b9eb` |
| `fap_managed` | `diagnose wireless-controller wlac -c wtp` | `084b9eb` |
| `fap_clients` | `diagnose wireless-controller wlac -c sta` | `084b9eb` |
| `fap_health` | `diagnose wireless-controller wlac -d wtp` | `084b9eb` |

- `fap_managed` PASS path was additionally confirmed 2026-06-19 against a real **connected** AP (`GC-AP-09`, serial `PU431FTH...`) — extracts name, serial, `connection state : Connected` → PASS.
- Feature base = original commit `b6aba78` ("Add FortiSwitch (7.6.x) and FortiAP (7.x.x) diagnostics").

## 2. Key technical facts learned (so we don't re-derive them)

- **Engine runs STATIC command strings.** `engine.py` only does `{fqdn}` substitution plus one hardcoded `expand_nic` (per-interface follow-up). There is **no per-switch / per-AP enumeration** mechanism. Adding one (e.g. `expand_switch`) would be a **core change** — the project prefers "one catalog entry + one parser, no core changes."
- **Mock fixtures are matched by exact command string** (`connectors/mock.py`, `_FIXTURES` dict). A new check that reuses an existing command automatically gets that command's fixture.
- **The FortiAP `-c wtp` output is rich.** It already contains, per radio: `oper chan`, `noise_floor`, `chutil` + `oper chutil data : ... ->newer` (newest value is rightmost), plus per-AP `active sw ver` (firmware), `join_time` (uptime), `Temperature in Celsius`, `antenna RSSI ... (age=N)`, and LAN stats. → Several recommended checks need **no new command**, just a new parser.
- **Parser file locations:** `fortitoolbox/parsers.py` — the 6 `@parser` funcs are `fsw_managed` (~L844), `fsw_sync` (~L879), `fsw_poe` (~L916), `fap_managed` (~L965), `fap_clients` (~L997), `fap_health` (~L1025).
- **Gotchas observed in real `-c wtp`:**
  - `last failure` can be **stale** (older than current `join_time`) → must compare against `join_time`, don't blindly WARN.
  - Trust `chutil`/`antenna RSSI` only when `age=` is small (a 2.4 GHz radio with 0 clients showed `age=64854`).
  - `Temperature in Celsius: 1 (64)` → the real value is the parenthesized number, not the leading `1`.

## 3. Recommendations on the table (the full list)

### FortiSwitch
| # | Check | Command | Verdict | Cost |
|---|---|---|---|---|
| 1 | Port error counters | `diagnose switch-controller switch-info port-stats <sw>` | WARN/FAIL on rising CRC / input-errors / drops | **Higher** — per-switch cmd → needs engine tweak + real capture |
| 2 | Firmware compliance | `get switch-controller managed-switch` | WARN if switch off recommended image | Low — partly covered by `fsw_managed` (7.6.x check) |
| 3 | MCLAG / trunk / ICL | `diagnose switch-controller switch-info trunk` | FAIL if trunk member / ICL down | Medium — only if MCLAG used |
| 4 | STP topology | `diagnose switch-controller switch-info stp <sw>` | WARN on unexpected root / topo changes | Medium — per-switch |
| 5 | PoE per-port detail | `diagnose switch-controller switch-info poe <sw>` | WARN on port fault / over-budget | Low-ish — summary already in `fsw_poe` |

### FortiAP
| # | Check | Command | Verdict | Cost |
|---|---|---|---|---|
| 6 | Channel utilization | *(none — reuse `wlac -c wtp`)* | WARN if any radio chutil > ~70% | **Lowest — parser only** |
| 7 | Noise floor | *(none — reuse `wlac -c wtp`)* | WARN on elevated noise (esp. 2.4 GHz) | **Lowest — same cmd** |
| 8 | AP firmware compliance | *(none — reuse `wlac -c wtp`)* | WARN on AP off recommended image | **Lowest — same cmd** |
| 9 | AP uptime / recent reboot | *(none — `join_time` in `-c wtp`)* | WARN on recent unexpected reboot | **Lowest — same cmd** |
| 10 | Rogue AP / WIDS | rogue listing via `wlac` / WIDS profile | WARN/FAIL on on-wire rogues; flag monitor radio w/ no WIDS profile | Medium — new cmd, security-leaning |
| 11 | Client RF quality | `wlac -d sta` (RSSI/SNR) | WARN on clients with low SNR | Medium — new cmd |

## 4. Status by item

- ✅ **#5 PoE per-port fault** — DONE. `fsw_poe` extended (parser + fixture + reference). No new command.
- ✅ **#6–9 FortiAP radio/noise/firmware/uptime** — DONE as `fap_radio` (catalog + parser + fixture + reference). No new command. Validated vs real `GC-AP-09`.
- ✅ **#2 FortiSwitch firmware compliance** — DONE via option (b): the `7.6` target is now a catalog field `target_fw` on the `fsw_managed` entry (default `"7.6"`); parser reads `meta.get("target_fw")`, builds prefix `v<target>`, and reports a `Target firmware` metric. Verified: target 7.6 → PASS, target 7.4 → WARN. No new command.
- 🔒 Deferred (medium/high, on demand): **#1** port errors (needs `expand_switch` engine change + real `port-stats`), **#3** MCLAG/trunk, **#4** STP, **#10** rogue/WIDS, **#11** client RF quality (`-d sta`).

## 5. What was built this session (files touched)

- `fortitoolbox/catalog.yaml` — added `fap_radio` entry after `fap_health`.
- `fortitoolbox/parsers.py` — added `@parser("fap_radio")`; extended `_fsw_poe` with per-port fault detection.
- `fortitoolbox/connectors/mock.py` — enriched the `-c wtp` fixture with `Radio`/firmware/`join_time` blocks (one busy 5 GHz radio); added a faulted `port4` to the `poe summary` fixture.
- `fortitoolbox/reference.py` — added `fap_radio`; updated `fsw_poe` and `fsw_managed` descriptions.
- `fortitoolbox/catalog.yaml` — also added `target_fw: "7.6"` to `fsw_managed`; `parsers.py` `_fsw_managed` now reads it (configurable firmware target, #2).

Verified in Demo via the mock: `fap_radio` WARN (busy radio) / PASS on real `GC-AP-09`; `fsw_poe` WARN (port fault); `fap_managed` unchanged. **Not yet committed.**

### `fap_radio` design notes (as built)
- Verdict priority: busy radio (≥70% newest chutil) → recent reboot (join_time <24h) → firmware drift (>1 distinct version) → PASS. Noise floor is a metric only (threshold pending real-world tuning).
- Only `Radio N : AP` sections counted (skips Monitor / Virtual Lan AP / Not Exist).
- Gotcha handled: `active sw ver` regex uses `[ \t]` (not `\s`) so an empty version line doesn't swallow the next line.

### Open question before `fsw_port_errors` (#1, deferred)
- Confirm the single-shot vs per-switch form of `port-stats` on the target MR + capture real output; decide whether to add an `expand_switch` engine step or use an all-switches command.
