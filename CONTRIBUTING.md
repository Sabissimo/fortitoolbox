# Contributing

Thanks for looking. This started as a personal tool, so PRs and issues are genuinely
welcome — especially from people who run FortiGates every day.

## The most useful things you can do

1. **Parser fixes for real-device output.** The check commands are calibrated against
   the docs and my lab, but FortiOS output shifts between MRs and platforms. If a
   check parses wrong on your box, open an issue and paste the raw output of the
   command (mask anything sensitive) — that's the single most valuable contribution.
2. **New checks.** If there's a `diagnose`/`get` you reach for that isn't here, add it.
3. **Validate `verify: true` commands** against the MR you run.

## How it's built

```
connector (ssh | mock) -> Engine(catalog.yaml) -> @parser(id) -> CheckResult -> Obfuscator -> NiceGUI
```

The catalog is data. Adding a check is **one YAML entry + one parser**:

1. Add an entry to `fortitoolbox/catalog.yaml` (id, module, title, cmds, scope, …).
2. Write `@parser("<id>")` in `fortitoolbox/parsers.py` returning a `CheckResult`
   (status + headline + the metric that matters).
3. Add a fixture for the command in `fortitoolbox/connectors/mock.py` so it runs in
   demo mode, and document the verdict in `fortitoolbox/reference.py`.

## Dev setup

```bash
git clone https://github.com/Sabissimo/fortitoolbox.git
cd fortitoolbox
python3 -m venv .venv && source .venv/bin/activate
pip install -e .          # editable install
fortitoolbox              # Demo mode needs no device
```

Run against the mock connector while developing — it's deterministic. Keep checks
read-only: if something needs a write, generate the command line for the operator to
run, don't run it.

## Ground rules

- Keep it read-only by default.
- Never log, store, or send credentials. Secrets get dropped/masked before any export.
- One check = one verdict + one number. Conclusions, not dumps.

Open an issue first if it's a big change, so we don't duplicate work.
