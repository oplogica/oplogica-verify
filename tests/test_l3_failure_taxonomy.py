"""Tests for ova_demo.l3_failure_taxonomy (Oplogica v0.2).

Verifies deterministic classification over the real reconciled output:
  * clean bundle -> no failure classifications,
  * T4 tamper -> the two failed checks and two not-run checks classified,
  * every classification carries means / does_not_prove / detectability,
  * the silent-omission boundary is explicitly not detectable from bundle alone,
  * no classification text asserts the decision is correct or wrong,
  * classification is deterministic (same input -> same output).

Runs the real engine end-to-end; no mocking, no model.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo.checks import reconcile
from ova_demo.generate_bundle import generate
from ova_demo import tamper_examples
from ova_demo import l3_failure_taxonomy as tax


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


import json
import tempfile


def _load_arts(tmp):
    paths = generate(tmp)
    return {k: json.load(open(p, encoding="utf-8")) for k, p in paths.items()}


def _clean_reconciled(tmp):
    arts = _load_arts(tmp)
    raw = engine.verify_bundle(
        arts["bundle"],
        expected_input_data=arts["input_data"],
        governance_registry=arts["registry"],
        trusted_root_public_key=arts["trust_root"]["trusted_root_public_key"],
        allowed_registry_hashes=set(arts["trust_root"]["allowed_registry_hashes"]),
    )
    return reconcile(raw)


def _t4_reconciled(tmp):
    arts = _load_arts(tmp)
    bundle = arts["bundle"]
    # Apply the T4 mutation: dangling PoR reference.
    bundle["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
        "p1", "p2", "r1", "p_GHOST",
    ]
    raw = engine.verify_bundle(
        bundle,
        expected_input_data=arts["input_data"],
        governance_registry=arts["registry"],
        trusted_root_public_key=arts["trust_root"]["trusted_root_public_key"],
        allowed_registry_hashes=set(arts["trust_root"]["allowed_registry_hashes"]),
    )
    return reconcile(raw)


def test_clean_has_no_failure_classifications():
    with tempfile.TemporaryDirectory() as tmp:
        rec = _clean_reconciled(tmp)
    out = tax.classify(rec)
    _assert(out["l3_failure_classification"] == [],
            f"clean bundle produced classifications: {out['l3_failure_classification']}")


def test_t4_classifies_failed_and_not_run():
    with tempfile.TemporaryDirectory() as tmp:
        rec = _t4_reconciled(tmp)
    out = tax.classify(rec)
    by_check = {e["check"]: e for e in out["l3_failure_classification"]}
    _assert("por_structural_consistency" in by_check, "missing por_structural_consistency")
    _assert(by_check["por_structural_consistency"]["failure_class"]
            == "ghost_evidence_reference",
            f"wrong class: {by_check['por_structural_consistency']['failure_class']}")
    _assert(by_check["merkle_root_match"]["failure_class"] == "hash_mismatch",
            f"wrong class: {by_check['merkle_root_match']['failure_class']}")
    _assert(by_check["por_signature_binding_valid"]["failure_class"]
            == "declared_check_not_run", "not-run check misclassified")
    _assert(by_check["por_rule_policy_binding"]["failure_class"]
            == "declared_check_not_run", "not-run check misclassified")


def test_every_classification_has_meaning_and_does_not_prove():
    with tempfile.TemporaryDirectory() as tmp:
        rec = _t4_reconciled(tmp)
    out = tax.classify(rec)
    for e in out["l3_failure_classification"]:
        for key in ("explanation", "means", "does_not_prove",
                    "deterministic", "detectable_from_bundle_alone"):
            _assert(key in e, f"classification missing {key}: {e}")
        _assert(len(e["does_not_prove"]) > 0, "empty does_not_prove")


def test_silent_omission_is_not_detectable_from_bundle_alone():
    out = tax.classify({"failed": [], "not_run": []})
    note = out["scope_boundary_note"]
    _assert(note["code"] == "silent_omission_not_detectable_from_bundle_alone",
            "boundary note code wrong")
    _assert(note["detectable_from_bundle_alone"] is False,
            "silent omission must be marked NOT detectable from bundle alone")


def test_no_classification_asserts_decision_correct_or_wrong():
    # Scan all catalogue text for forbidden assertions about the decision.
    forbidden = ("decision is correct", "decision is wrong",
                 "decision was correct", "decision was wrong",
                 "decision is supported")
    for code, spec in tax.all_classes().items():
        blob = (spec["explanation"] + " " + spec["means"] + " "
                + spec["does_not_prove"]).lower()
        for bad in forbidden:
            _assert(bad not in blob,
                    f"class {code} asserts decision verdict: {bad!r}")


def test_classification_is_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        rec = _t4_reconciled(tmp)
    a = tax.classify(rec)
    b = tax.classify(rec)
    _assert(a == b, "classification is not deterministic")


def test_all_failure_classes_have_complete_reference():
    for code, spec in tax.all_classes().items():
        for key in ("explanation", "means", "does_not_prove",
                    "deterministic", "detectable_from_bundle_alone"):
            _assert(key in spec, f"class {code} missing {key}")


def _run_all():
    test_fns = [
        test_clean_has_no_failure_classifications,
        test_t4_classifies_failed_and_not_run,
        test_every_classification_has_meaning_and_does_not_prove,
        test_silent_omission_is_not_detectable_from_bundle_alone,
        test_no_classification_asserts_decision_correct_or_wrong,
        test_classification_is_deterministic,
        test_all_failure_classes_have_complete_reference,
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
