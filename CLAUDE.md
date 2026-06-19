# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

FortiToolbox is a read-only diagnostic dashboard for FortiGate firewalls (FortiOS 7.4 / 7.6 / 8.0). It SSHes into a device (or a built-in mock), runs a curated set of `get`/`diagnose` commands, and renders each as a PASS/WARN/FAIL **verdict plus the one metric that matters** — conclusions, not raw dumps. Pure Python, NiceGUI UI, runs locally in the browser on `127.0.0.1:8080`.

It also covers **FortiLink-managed FortiSwitches (7.6.x)** and **wireless-controller-managed FortiAPs (7.x.x)** — queried *from the FortiGate* via `switch-controller` / `wireless-controller` commands, so there is no separate transport and the tool stays fully offline. These appear as their own `FortiSwitch` and `FortiAP` tabs.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .          # editable dev install
fortitoolbox              # run; or: python -m fortitoolbox
```

There is **no test suite, linter, or build step** configured. The mock connector is the de facto test harness — it makes Demo mode deterministic, so develop and validate against it. The shipped `fortitoolbox-0.4.4-py3-none-any.whl` is a prebuilt artifact, not something you regenerate during normal work.

## Architecture

The pipeline is connector-agnostic end to end:

```
connector (ssh | mock) → Engine(catalog.yaml) → @parser(id) → CheckResult → Obfuscator → NiceGUI
```

- **`catalog.yaml` is the source of truth.** Checks, their CLI commands, the module/tab they appear under, privilege level, scope, and one-click "kits" (`quick`, `full`) are all data. The UI, tabs, and kits are *derived* from it — `app.py` reads the catalog, it does not hardcode the check list.
- **`engine.py`** orchestrates: connect → detect version → capability-probe (`system-diagnostics`) → enumerate VDOMs → run a check's commands → hand raw output to the parser. It serializes all device access through one lock (`run_many`) because there is a single SSH channel. It guards against rejected commands (privilege/syntax) and never lets a parser exception kill the run — failures become an `ERROR` `CheckResult`.
- **`parsers.py`** holds one `@parser("<id>")` function per check, keyed to the catalog `id`. A parser receives `out` (`{command: raw_text}`) plus `DeviceInfo` and returns a `CheckResult` (`status` + `headline` + `metrics`). Unregistered ids fall back to a generic raw INFO capture.
- **`connectors/`** — `base.Connector` defines the interface (`run(command, scope, vdom) -> str`). `ssh.py` is the live netmiko transport; `mock.py` serves canned fixtures for Demo mode; `console.py` backs the live SSH console. Adding a new transport (API, paste-mode) touches nothing downstream.
- **`obfuscation.py`** — reversible, dependency-free (pure regex) anonymizer for "Copy for LLM". Two policies per entity class: OBFUSCATE (reversible token, deterministic within a session) or DROP (secrets never emitted). A leak-check blocks the copy if the payload isn't clean.
- **`verdict.py`** — the `Status` enum, `CheckResult` dataclass, and `roll_up` tally. **`reference.py`** documents each verdict's meaning. **`report.py`** builds the PDF. **`debugflow.py` / `sniffer.py` / `authtest.py`** back the interactive Advanced-tab tools.

## Adding a check (the core workflow)

One catalog entry + one parser, no core changes:

1. Add an entry to `fortitoolbox/catalog.yaml` (`id`, `module`, `title`, `cmds`, `scope`, `privilege`, `kits`).
2. Write `@parser("<id>")` in `fortitoolbox/parsers.py` returning a `CheckResult` — status, headline, and the single metric that matters.
3. Add a fixture for the command(s) in `fortitoolbox/connectors/mock.py` so it runs in Demo mode, and document the verdict in `fortitoolbox/reference.py`.

## Conventions that matter

- **Read-only by default.** Checks must not write to the device. If something needs a write, generate the command line for the operator to run — don't run it. Stateful debug/enable commands live behind the Advanced tab (`stateful: true` / `advanced: true` in the catalog).
- **Never log, store, or transmit credentials.** Secrets are dropped/masked before any export; the obfuscation vault never leaves the machine.
- **One check = one verdict + one number.** Headlines are conclusions, not dumps.
- **Catalog privilege/scope semantics:** `privilege: sysdiag` checks need `system-diagnostics enable` and return `SKIPPED` if the account lacks it (operator can force-run). `scope` is `global` or `vdom`; on multi-VDOM devices the connector scopes the command accordingly. Many catalog entries carry `verify: true` and `CONFIRM`-style comments — the exact CLI syntax/output is calibrated against docs+lab but should be validated against the target MR before trusting in production.
