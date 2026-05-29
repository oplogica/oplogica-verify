"""Tests for ova_demo.negative_claims_firewall (Oplogica v0.2).

Verifies the deterministic overclaim guard:
  * affirmative overclaims are caught,
  * safe bounded phrases pass,
  * the canonical not-meaning disclaimer is allowlisted (not flagged),
  * negated disclaimer uses of sensitive terms pass,
  * scanning a nested mapping (an API-like payload) works,
  * sanitize() neutralizes overclaims deterministically.

No model, no network, no free-text interpretation.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo import negative_claims_firewall as fw


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_always_banned_affirmative_phrases_are_caught():
    for phrase in ("Oplogica proves compliance.",
                   "This proves fairness.",
                   "The system proves correctness of the decision.",
                   "This output is legally valid.",
                   "Result: clinically safe."):
        findings = fw.scan(phrase)
        _assert(len(findings) >= 1, f"missed always-banned phrase: {phrase!r}")


def test_sensitive_terms_affirmative_are_caught():
    findings = fw.scan("This bundle is compliant and certified and fair.")
    terms = {f.term for f in findings}
    _assert("compliant" in terms, "missed affirmative 'compliant'")
    _assert("certified" in terms, "missed affirmative 'certified'")
    _assert("fair" in terms, "missed affirmative 'fair'")


def test_negated_disclaimer_uses_pass():
    for ok in ("Oplogica does not certify compliance.",
               "This is not compliant by our verification.",
               "We make no claim of fairness.",
               "This cannot establish that the decision is fair."):
        _assert(fw.is_safe(ok), f"false positive on negated use: {ok!r}")


def test_canonical_not_meaning_sentence_is_allowlisted():
    nm = ("Not meaning: the AI decision is medically correct, unbiased, "
          "or legally compliant.")
    _assert(fw.is_safe(nm),
            f"canonical not-meaning sentence wrongly flagged: {fw.scan(nm)}")


def test_all_safe_phrases_pass():
    for p in fw.SAFE_PHRASES:
        _assert(fw.is_safe(p), f"safe phrase wrongly flagged: {p!r}")


def test_scan_mapping_finds_nested_overclaim():
    payload = {
        "ok": "supports independent review",
        "nested": {"bad": "this decision is certified"},
        "list": ["fine", "proves compliance"],
    }
    found = fw.scan_mapping(payload)
    paths = {f["path"] for f in found}
    _assert(any("nested.bad" in p for p in paths),
            f"did not flag nested overclaim: {paths}")
    _assert(any("list[1]" in p for p in paths),
            f"did not flag list overclaim: {paths}")


def test_clean_mapping_has_no_findings():
    payload = {
        "a": "supports tamper-evidence",
        "b": "does not certify compliance",
        "c": ["outside verification scope", "not detectable from this bundle alone"],
    }
    _assert(fw.scan_mapping(payload) == [],
            f"clean mapping produced findings: {fw.scan_mapping(payload)}")


def test_sanitize_neutralizes_overclaim():
    out = fw.sanitize("Oplogica proves compliance and the result is compliant.")
    _assert(fw.is_safe(out), f"sanitize left an overclaim: {out!r} -> {fw.scan(out)}")


def test_assert_safe_raises_on_overclaim():
    raised = False
    try:
        fw.assert_safe("this is certified", where="unit test")
    except ValueError:
        raised = True
    _assert(raised, "assert_safe did not raise on overclaim")


def _run_all():
    test_fns = [
        test_always_banned_affirmative_phrases_are_caught,
        test_sensitive_terms_affirmative_are_caught,
        test_negated_disclaimer_uses_pass,
        test_canonical_not_meaning_sentence_is_allowlisted,
        test_all_safe_phrases_pass,
        test_scan_mapping_finds_nested_overclaim,
        test_clean_mapping_has_no_findings,
        test_sanitize_neutralizes_overclaim,
        test_assert_safe_raises_on_overclaim,
    ]
    failures = []
    for fn in test_fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}\n      {e}")
            failures.append(fn.__name__)
        except Exception as e:
            print(f"ERROR {fn.__name__}\n      {type(e).__name__}: {e}")
            failures.append(fn.__name__)
    print()
    if failures:
        print(f"{len(failures)} test(s) failed: {failures}")
        sys.exit(1)
    print(f"All {len(test_fns)} tests passed.")


if __name__ == "__main__":
    _run_all()
