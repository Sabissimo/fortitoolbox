"""Reversible obfuscation for safe upload of FortiGate output to a public LLM.

Design goals (per spec):
  * Two policies per entity class: OBFUSCATE (reversible) or DROP (never emitted).
  * Deterministic within a session: the same real value always maps to the same
    token, so cross-table correlation survives in the LLM's reasoning.
  * Reversible: a local vault maps token -> original; restore() puts originals
    back into the LLM's returned analysis before it is shown to the operator.
  * The vault never leaves the machine. A leak-check guards the outbound payload.

This is intentionally dependency-free (pure regex). It can be swapped for a
Microsoft Presidio + PresidioReversibleAnonymizer backend later without changing
callers, because the public surface is anonymize()/deanonymize().
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Pattern, Tuple

# --- entity recognizers -----------------------------------------------------
# Order matters: longer / more specific patterns first so they win the match.

_RE_FGT_SERIAL = re.compile(r"\bFG[A-Z0-9]{2}[0-9A-Z]{2}[0-9A-Z]{10}\b")  # e.g. FGT60FTK20012345
_RE_GENERIC_SERIAL = re.compile(r"\b(?:FG|FW|FAZ|FMG|FPX)[A-Z0-9]{10,16}\b")
_RE_IPV6 = re.compile(
    r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b"  # x::y first
    r"|::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}\b"            # ::y
    r"|\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b")       # 4+ groups (avoids HH:MM:SS)
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_RE_MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# public-ish FQDN (has a dot, not an IP, not a bare interface name)
_RE_FQDN = re.compile(r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

# Values matching these are DROPPED entirely (never sent, even obfuscated).
# We blank the *value* after the key token, keeping the key for context.
_DROP_LINE_PATTERNS: List[Pattern] = [
    re.compile(r"(?i)(password|passwd|psksecret|psk|pre-shared|preshared|secret|"
               r"private-key|priv-key|passphrase|community|auth-pwd|key-passwd|"
               r"ppk-secret|api[-_ ]?key|token)\b(\s*[:=]?\s*).+"),
    re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)",
               re.DOTALL),
]

ENTITY_ORDER: List[Tuple[str, Pattern]] = [
    ("SERIAL", _RE_FGT_SERIAL),
    ("SERIAL", _RE_GENERIC_SERIAL),
    ("EMAIL", _RE_EMAIL),
    ("MAC", _RE_MAC),
    ("IPV6", _RE_IPV6),
    ("IPV4", _RE_IPV4),
    ("HOST", _RE_FQDN),
]

# FQDNs that are operational constants, not customer data -> keep readable.
# IPs that are never sensitive unicast hosts: any-address and 255.x (netmasks,
# broadcast). First-octet-255 is reserved, so real hosts never start with 255.
def _ip_is_constant(ip: str) -> bool:
    return ip == "0.0.0.0" or ip.startswith("255.")


ALLOW_LIST = {
    "fortinet.com", "fortiguard.com", "forticloud.com", "fortimanager.com",
    "update.fortiguard.net", "service.fortiguard.net", "globalupdate.fortinet.net",
}


@dataclass
class Obfuscator:
    """Stateful, deterministic, reversible obfuscator. One per diagnostic run."""
    token_style: str = "tagged"          # "tagged" -> <IPV4_3> | "fake" -> realistic fake
    secret_policy: str = "drop"          # "drop" -> [DROPPED] | "mask" -> <SECRET_n> (value discarded, never vaulted)
    vault: Dict[str, str] = field(default_factory=dict)   # token -> original
    _rev: Dict[str, str] = field(default_factory=dict)    # original -> token
    _counters: Dict[str, int] = field(default_factory=dict)
    _literals: List[str] = field(default_factory=list)

    def prime(self, literals) -> None:
        """Register known-sensitive literals (hostname, VDOM names) to tokenize
        wherever they appear -- they have no generic regex (e.g. no dot)."""
        for lit in literals or []:
            if lit and len(lit) >= 3 and lit not in self._literals:
                self._literals.append(lit)
        self._literals.sort(key=len, reverse=True)

    def _token_for(self, entity: str, value: str) -> str:
        if value in self._rev:
            return self._rev[value]
        self._counters[entity] = self._counters.get(entity, 0) + 1
        n = self._counters[entity]
        token = self._make_token(entity, n, value)
        self.vault[token] = value
        self._rev[value] = token
        return token

    def _make_token(self, entity: str, n: int, value: str) -> str:
        if self.token_style == "fake":
            if entity == "IPV4":
                return f"10.{(n // 254) % 254}.{n % 254}.{(n * 7) % 254 + 1}"
            if entity == "MAC":
                h = f"{n:06x}"
                return f"02:00:00:{h[0:2]}:{h[2:4]}:{h[4:6]}"
            if entity == "SERIAL":
                return f"FGTREDACT{n:07d}"
            if entity == "HOST":
                return f"host{n}.redacted.example"
            if entity == "EMAIL":
                return f"user{n}@redacted.example"
            if entity == "IPV6":
                return f"fd00::{n:x}"
        return f"<{entity}_{n}>"

    def _secret_repl(self) -> str:
        if self.secret_policy != "mask":
            return "[DROPPED]"
        self._counters["SECRET"] = self._counters.get("SECRET", 0) + 1
        return f"<SECRET_{self._counters['SECRET']}>"  # value intentionally discarded

    def anonymize(self, text: str) -> str:
        if not text:
            return text
        # 1) Handle secrets first. "drop" emits [DROPPED] (irreversible, nothing
        #    leaves). "mask" emits a <SECRET_n> placeholder so the LLM sees that
        #    a secret field exists (context) -- but the real value is discarded,
        #    NOT vaulted, so it is unrecoverable and never transmitted.
        for pat in _DROP_LINE_PATTERNS:
            if pat.groups >= 3:
                text = pat.sub(lambda m: f"{m.group(1)}{self._secret_repl()}{m.group(3)}", text)
            else:
                text = pat.sub(lambda m: f"{m.group(1)}{m.group(2) or ' '}{self._secret_repl()}", text)
        # 1b) Tokenize primed literals (hostname, VDOM names).
        for lit in self._literals:
            if lit in text:
                text = text.replace(lit, self._token_for("NAME", lit))
        # 2) OBFUSCATE entities, specific-first.
        for entity, pat in ENTITY_ORDER:
            def _repl(m: re.Match) -> str:
                val = m.group(0)
                low = val.lower()
                if entity == "HOST" and (low in ALLOW_LIST or any(
                        low.endswith("." + d) or low == d for d in ALLOW_LIST)):
                    return val
                if entity == "IPV4" and _ip_is_constant(val):
                    return val  # 0.0.0.0 / netmask / broadcast - not sensitive
                if entity in ("IPV4", "IPV6") and val in self.vault:
                    return val  # already a token (fake-style) - skip
                return self._token_for(entity, val)
            text = pat.sub(_repl, text)
        return text

    def deanonymize(self, text: str) -> str:
        if not text:
            return text
        # Replace longest tokens first to avoid partial collisions.
        for token in sorted(self.vault, key=len, reverse=True):
            text = text.replace(token, self.vault[token])
        return text

    def leak_check(self, payload: str) -> List[str]:
        """Return any real entities/secrets that survived un-obfuscated. Empty == clean."""
        leaks: List[str] = []
        # Secrets: a DROP-pattern line whose value is not a redaction marker leaked.
        for pat in _DROP_LINE_PATTERNS:
            for m in pat.finditer(payload):
                seg = m.group(0)
                if "[DROPPED]" not in seg and "<SECRET_" not in seg:
                    leaks.append("SECRET:" + m.group(1))
        for entity, pat in ENTITY_ORDER:
            for m in pat.finditer(payload):
                val = m.group(0)
                low = val.lower()
                if entity == "HOST" and (low in ALLOW_LIST or any(
                        low.endswith("." + d) for d in ALLOW_LIST)):
                    continue
                if entity == "IPV4" and _ip_is_constant(val):
                    continue                   # 0.0.0.0 / netmask / broadcast (kept readable)
                if val in self.vault:          # it's a fake token, fine
                    continue
                if self.token_style == "tagged":
                    leaks.append(f"{entity}:{val}")
                elif val not in self.vault:
                    leaks.append(f"{entity}:{val}")
        return leaks


def obfuscate_bundle(results: Dict[str, str], token_style: str = "tagged",
                     secret_policy: str = "drop", extra_literals=None) -> Tuple[str, Obfuscator]:
    """Obfuscate a whole set of {check_id: raw_output} into one LLM-ready blob.

    A single Obfuscator is shared so an IP seen in routing and in sessions maps
    to the *same* token across checks -> correlation is preserved.
    """
    obf = Obfuscator(token_style=token_style, secret_policy=secret_policy)
    obf.prime(extra_literals)
    parts: List[str] = []
    for check_id, raw in results.items():
        parts.append(f"===== {check_id} =====\n{obf.anonymize(raw)}")
    blob = "\n\n".join(parts)
    return blob, obf
