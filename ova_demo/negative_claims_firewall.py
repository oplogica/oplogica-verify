"""Negative Claims Firewall (Oplogica v0.2).

A deterministic, runtime-safe guard that prevents Oplogica's OWN generated
outputs (API responses, UI labels, exported reports, reviewer-facing messages)
from using overclaiming language.

Scope and discipline
--------------------
* This firewall applies ONLY to system-generated text that Oplogica itself
  produces. It does NOT judge arbitrary user-provided prose, and it does NOT
  interpret free text with any model. It is a fixed, case-insensitive substring
  scan over a closed list of banned terms.
* It is deterministic: the same input always yields the same result. No LLM, no
  probabilistic scoring, no semantic interpretation.
* It exists because most AI-governance tooling drifts into marketing overclaim.
  Oplogica's discipline is that the system refuses to let its own surfaces say
  things the evidence cannot support.

Prior-art note
--------------
This is not claimed as novel research. Overclaim prevention is a narrow
engineering discipline; the contribution here is only that Oplogica applies it
to its own output surfaces deterministically.

There are two affirmative-claim phrasings that are ALWAYS banned (e.g. "proves
compliance"), and a set of sensitive single terms (e.g. "compliant") that are
banned as affirmative claims but are explicitly allowed inside a fixed
"does not ..." / "not ..." disclaimer context, because honest scope language
must be able to say "does not certify compliance".
"""

from __future__ import annotations

import re
from typing import Any

# Phrases that must NEVER appear in Oplogica output, in any context.
# These are affirmative overclaims with no legitimate disclaimer use.
ALWAYS_BANNED: tuple[str, ...] = (
    "proves compliance",
    "proves fairness",
    "proves correctness",
    "proves the decision is correct",
    "certifies compliance",
    "guarantees fairness",
    "legally valid",
    "clinically safe",
    "audit-certified",
    "correct decision",
)

# Sensitive single terms. Banned as AFFIRMATIVE claims, but permitted when they
# appear inside an explicit negation / scope-limiting context (the safe phrases
# below), because honest disclaimers must be able to name what is NOT proven.
SENSITIVE_TERMS: tuple[str, ...] = (
    "compliant",
    "certified",
    "fair",
    "unbiased",
    "approved",
)

# Fixed safe, bounded phrases Oplogica is allowed (indeed encouraged) to use.
SAFE_PHRASES: tuple[str, ...] = (
    "supports independent review",
    "supports tamper-evidence",
    "supports structural verification",
    "does not prove decision correctness",
    "does not certify compliance",
    "does not prove fairness",
    "outside verification scope",
    "not detectable from this bundle alone",
)

# Negation cues that legitimize a sensitive term (e.g. "does not certify
# compliance", "not compliant", "cannot certify"). These are matched immediately
# before the sensitive term.
_NEGATION_CUES: tuple[str, ...] = (
    "does not",
    "do not",
    "not ",
    "cannot",
    "can not",
    "no claim of",
    "without",
    "never",
)

# Fixed, intentional disclaimer fragments that are part of Oplogica's honest
# scope language. These are allowlisted verbatim because they are negated /
# scope-limiting by construction even when the negation sits far from the term
# (e.g. the canonical not-meaning sentence lists the things a result does NOT
# prove). Matching is case-insensitive substring containment.
ALLOWLISTED_FRAGMENTS: tuple[str, ...] = (
    "the ai decision is medically correct, unbiased, or legally compliant",
    "does not establish decision correctness, model behavior fairness, or legal",
    "model behavior fairness",
    "model fairness or absence of bias",
)


class FirewallFinding:
    """A single overclaim finding in a piece of system output."""

    __slots__ = ("term", "kind", "context")

    def __init__(self, term: str, kind: str, context: str) -> None:
        self.term = term
        self.kind = kind  # "always_banned" | "sensitive_affirmative"
        self.context = context

    def to_dict(self) -> dict[str, str]:
        return {"term": self.term, "kind": self.kind, "context": self.context}

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"FirewallFinding({self.term!r}, {self.kind!r})"


def _window(text_low: str, idx: int, span: int = 24) -> str:
    start = max(0, idx - span)
    return text_low[start : idx + span]


def _is_negated(text_low: str, idx: int) -> bool:
    """True if a negation cue appears in the same clause before position idx.

    Honest disclaimers often place the negation a few words before the sensitive
    term, e.g. "cannot establish that the decision is fair". But a negation in a
    *previous* sentence must not rescue a later affirmative overclaim, so the
    search window is cut at the nearest preceding clause boundary (. ; : !).
    """
    window = text_low[max(0, idx - 60) : idx]
    # Keep only the text after the last clause boundary.
    for sep in (". ", "; ", ": ", "! ", ".", ";", ":", "!"):
        pos = window.rfind(sep)
        if pos != -1:
            window = window[pos + len(sep) :]
    return any(cue in window for cue in _NEGATION_CUES)


def scan(text: str) -> list[FirewallFinding]:
    """Scan a single system-generated string for overclaim language.

    Deterministic, case-insensitive, substring-based. Returns a list of
    findings (empty if the text is clean).
    """
    if not text:
        return []
    low = text.lower()
    # Neutralize intentional disclaimer fragments so their sensitive terms are
    # not misread as affirmative overclaims. Replaced with spaces to preserve
    # offsets for everything else.
    for frag in ALLOWLISTED_FRAGMENTS:
        idx = low.find(frag)
        while idx != -1:
            low = low[:idx] + (" " * len(frag)) + low[idx + len(frag) :]
            idx = low.find(frag)
    findings: list[FirewallFinding] = []

    # 1) Always-banned affirmative phrases — no legitimate context.
    for phrase in ALWAYS_BANNED:
        start = 0
        while True:
            i = low.find(phrase, start)
            if i == -1:
                break
            findings.append(
                FirewallFinding(phrase, "always_banned", _window(low, i))
            )
            start = i + len(phrase)

    # 2) Sensitive single terms — banned only as affirmative (non-negated) use.
    for term in SENSITIVE_TERMS:
        for m in re.finditer(r"\b" + re.escape(term) + r"\b", low):
            i = m.start()
            if _is_negated(low, i):
                continue  # legitimate disclaimer use, e.g. "does not certify compliance"
            findings.append(
                FirewallFinding(term, "sensitive_affirmative", _window(low, i))
            )

    return findings


def is_safe(text: str) -> bool:
    """True if the text contains no overclaim findings."""
    return len(scan(text)) == 0


def assert_safe(text: str, where: str = "system output") -> None:
    """Raise ValueError if the text overclaims. For use in tests / CI guards."""
    findings = scan(text)
    if findings:
        terms = ", ".join(sorted({f.term for f in findings}))
        raise ValueError(
            f"Negative Claims Firewall blocked overclaim in {where}: {terms}"
        )


def sanitize(text: str) -> str:
    """Return a bounded, safe rewrite of an overclaiming string.

    Deterministic replacement: affirmative overclaims are replaced with a fixed
    scope-limiting clause. This is used to neutralize a message rather than emit
    it verbatim. Negated/disclaimer uses are left untouched.
    """
    if not text:
        return text
    result = text

    # Replace always-banned phrases with a fixed safe clause (case-insensitive).
    for phrase in ALWAYS_BANNED:
        result = re.sub(
            re.escape(phrase),
            "supports independent review (does not prove correctness)",
            result,
            flags=re.IGNORECASE,
        )

    # For sensitive terms used affirmatively, prefix a scope qualifier.
    # We only rewrite non-negated occurrences; re-scan to locate them.
    for finding in scan(result):
        if finding.kind != "sensitive_affirmative":
            continue
        # Replace a standalone affirmative term with a bounded phrase.
        result = re.sub(
            r"\b" + re.escape(finding.term) + r"\b",
            f"[scope-limited: not {finding.term}]",
            result,
            count=1,
            flags=re.IGNORECASE,
        )

    return result


def scan_mapping(obj: Any, path: str = "") -> list[dict[str, str]]:
    """Recursively scan all string values in a dict/list (e.g. an API response).

    Returns a list of {path, term, kind} for any overclaim found. Useful for a
    test that asserts an entire API/report payload is free of overclaim.
    """
    out: list[dict[str, str]] = []
    if isinstance(obj, str):
        for f in scan(obj):
            d = f.to_dict()
            d["path"] = path or "(root)"
            out.append(d)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(scan_mapping(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(obj, (list, tuple)):
        for idx, v in enumerate(obj):
            out.extend(scan_mapping(v, f"{path}[{idx}]"))
    return out
