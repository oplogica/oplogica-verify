"""Tests for ova_demo.verification_discipline (Oplogica v0.2).

Verifies the fixed, machine-readable scope posture:
  * the discipline block contains the required keys with the correct values,
  * it asserts deterministic / no-LLM / recomputed-from-bundle = true,
  * it asserts decision-correctness / compliance / fairness / omission = false,
  * the block's own text does not overclaim (firewall-clean).
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo.verification_discipline import discipline_block
from ova_demo import negative_claims_firewall as fw


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_required_true_flags():
    b = discipline_block()
    for key in ("deterministic", "checks_recomputed_from_bundle"):
        _assert(b.get(key) is True, f"{key} must be True")


def test_required_false_flags():
    b = discipline_block()
    for key in ("uses_llm_interpretation", "free_text_claim_extraction",
                "verifies_decision_correctness", "certifies_compliance",
                "establishes_fairness", "detects_silent_omission",
                "is_compliance_certificate", "is_a_standard"):
        _assert(b.get(key) is False, f"{key} must be False")


def test_block_is_a_copy_not_shared_state():
    a = discipline_block()
    a["deterministic"] = "mutated"
    b = discipline_block()
    _assert(b["deterministic"] is True,
            "discipline_block() must return an independent copy")


def test_discipline_note_is_firewall_clean():
    b = discipline_block()
    findings = fw.scan(b["note"])
    _assert(findings == [],
            f"discipline note overclaims: {[f.term for f in findings]}")


def test_note_states_does_not_prove_correctness():
    b = discipline_block()
    note = b["note"].lower()
    _assert("does not prove decision correctness" in note,
            "note must explicitly disclaim decision correctness")


def _run_all():
    test_fns = [
        test_required_true_flags,
        test_required_false_flags,
        test_block_is_a_copy_not_shared_state,
        test_discipline_note_is_firewall_clean,
        test_note_states_does_not_prove_correctness,
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
