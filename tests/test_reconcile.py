"""Tests for ova_demo.checks.reconcile.

These tests run the *real* vendored engine end-to-end. There is no mocking of
the verifier — we want adversarial honesty, which means the invariant must
hold against the engine's actual emissions on:

  * a clean bundle,
  * the 6 real tamper cases,
  * 3 selected malicious-generator cases (MG_N, MG_P, MG_R per brief §5E),
  * two known short-circuit paths that drop emitted checks to 11
    (registry omitted; dangling PoR reference),
  * synthetic malformed engine output.

If any of these break the partition invariant, the test fails loudly.

This module makes no compliance, clinical, fairness, or production-grade
claims about the underlying decisions. It is a pure accounting test.
"""

from __future__ import annotations

import copy
import io
import os
import sys
import contextlib

# Make the package importable when running this file directly.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine  # noqa: E402
from ova_demo.checks import ALL_CHECKS, reconcile  # noqa: E402


# ----------------------------------------------------------------------
# Fixtures: produce one clean bundle + patient + registry, reused below.
# ----------------------------------------------------------------------

def _build_clean_inputs():
    """Run the engine's scenario once. Suppresses its stdout chatter."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        bundle, verifier_result, operator, patient_data = (
            engine.run_triage_scenario()
        )
    return bundle, verifier_result, patient_data, engine.GOVERNANCE_REGISTRY_V1


# ----------------------------------------------------------------------
# Invariant helpers
# ----------------------------------------------------------------------

def _assert_partition(reconciled: dict, label: str) -> None:
    """Hard invariant: passed + failed + not_run == len(ALL_CHECKS)."""
    p = reconciled["checks_passed_count"]
    f = reconciled["checks_failed_count"]
    n = reconciled["checks_not_run_count"]
    total = p + f + n
    assert total == len(ALL_CHECKS), (
        f"[{label}] partition broken: "
        f"passed={p} failed={f} not_run={n} sum={total} "
        f"expected={len(ALL_CHECKS)}"
    )
    # No name appears in more than one bucket.
    passed_names = set(reconciled["passed"])
    failed_names = {x["check"] for x in reconciled["failed"]}
    not_run_names = {x["check"] for x in reconciled["not_run"]}
    assert passed_names.isdisjoint(failed_names), (
        f"[{label}] name in both passed and failed: "
        f"{passed_names & failed_names}"
    )
    assert passed_names.isdisjoint(not_run_names), (
        f"[{label}] name in both passed and not_run: "
        f"{passed_names & not_run_names}"
    )
    assert failed_names.isdisjoint(not_run_names), (
        f"[{label}] name in both failed and not_run: "
        f"{failed_names & not_run_names}"
    )
    # Coverage: union equals ALL_CHECKS exactly.
    union = passed_names | failed_names | not_run_names
    assert union == set(ALL_CHECKS), (
        f"[{label}] coverage mismatch. "
        f"missing={set(ALL_CHECKS) - union} extra={union - set(ALL_CHECKS)}"
    )


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

def test_clean_bundle_reconciles_to_full_thirteen_passed():
    """A healthy bundle: passed=13, failed=0, not_run=0, status VALID."""
    bundle, verifier_result, _, _ = _build_clean_inputs()
    rec = reconcile(verifier_result)
    _assert_partition(rec, "clean")
    assert rec["status"] == "VALID", rec
    assert rec["checks_passed_count"] == len(ALL_CHECKS), rec
    assert rec["checks_failed_count"] == 0, rec
    assert rec["checks_not_run_count"] == 0, rec
    assert rec["unexpected"] == [], rec
    # All 13 canonical names must appear in passed, exactly.
    assert set(rec["passed"]) == set(ALL_CHECKS)


def _apply_tamper(label: str, bundle: dict) -> dict:
    """Mirror the engine's tamper mutations inline.

    The engine's tamper_* functions both mutate and verify, returning a test
    report — not a tampered bundle. For our reconcile tests we want the
    bundle to feed into our own verify_bundle call, so we replicate the
    one-line mutations here. These are exactly the mutations defined in
    ova_v2.py lines 2071-2259 (kept narrow on purpose — the point is the
    engine, not the wrapper).
    """
    t = copy.deepcopy(bundle)
    if label == "T1_pon_break_quorum_axiom":
        for v in t["constitutional_layer"]["pon"]["votes"]:
            if v["participant_id"] in (
                "regulator-MOH-TR-01", "ethics-board-IST-04"
            ):
                v["vote"] = "REJECT"
    elif label == "T2_poe_break_chain_link":
        poe = t["constitutional_layer"]["poe"]
        poe["versions"][1]["previous_version_hash"] = "sha256:" + "f" * 64
    elif label == "T3_poo_change_input_hash":
        t["operational_layer"]["poo"]["input_data_hash"] = (
            "sha256:" + "0" * 64
        )
    elif label == "T4_por_invalid_reference":
        t["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
            "p1", "p2", "r1", "p_GHOST"
        ]
    elif label == "T5_poc_silence_conflict":
        t["operational_layer"]["poc"]["conflicts"][0]["silenced"] = True
    elif label == "T6_merkle_root_direct_swap":
        t["merkle_root"] = "sha256:" + "1" * 64
    else:
        raise ValueError(f"unknown tamper label: {label}")
    return t


def test_invariant_holds_across_all_six_tamper_cases():
    """For each real tamper case, passed+failed+not_run == 13 and status is INVALID."""
    bundle, _, patient, reg = _build_clean_inputs()

    labels = [
        "T1_pon_break_quorum_axiom",
        "T2_poe_break_chain_link",
        "T3_poo_change_input_hash",
        "T4_por_invalid_reference",
        "T5_poc_silence_conflict",
        "T6_merkle_root_direct_swap",
    ]

    for label in labels:
        tampered = _apply_tamper(label, bundle)
        result = engine.verify_bundle(
            tampered,
            expected_input_data=patient,
            governance_registry=reg,
        )
        rec = reconcile(result)
        _assert_partition(rec, label)
        assert rec["status"] == "INVALID", (
            f"[{label}] expected INVALID, got {rec['status']}"
        )
        # At least one canonical check must fail OR be not_run for a tampered
        # bundle — otherwise tampering went undetected, which would be a real
        # security regression and worth shouting about.
        assert rec["checks_failed_count"] + rec["checks_not_run_count"] >= 1, (
            f"[{label}] tampering produced no failed/not_run checks"
        )
        assert rec["unexpected"] == [], (
            f"[{label}] unexpected check names emitted: {rec['unexpected']}"
        )


def test_invariant_holds_across_selected_malicious_generator_cases():
    """Per brief §5E, exercise MG_N, MG_P, MG_R as headline MG cases.

    The engine's malicious_* functions are end-to-end: they mutate, verify,
    and return a test report containing 'actual_failed_checks' and
    'actual_status'. We do not have direct access to the verifier_result
    dict here, so we synthesize a verifier_result-shaped object from those
    fields and reconcile against it. This is enough to assert the invariant
    we care about (passed + failed + not_run == 13). Per-check reasons in
    the synthesized 'failed' entries are deliberately marked as such.
    """
    bundle, _, patient, _ = _build_clean_inputs()

    mg_cases = [
        ("MG_N_unsigned_registry",
         engine.malicious_unsigned_registry),
        ("MG_P_policy_payload_substitution",
         engine.malicious_policy_payload_substitution),
        ("MG_R_cross_version_vote_grafting",
         engine.malicious_cross_version_vote_grafting),
    ]

    for label, mg_fn in mg_cases:
        report = mg_fn(copy.deepcopy(bundle), patient)
        failed_names = report["actual_failed_checks"]
        # Anything in ALL_CHECKS that wasn't reported as failed is treated
        # as passed for the synthesized verifier_result. Names emitted by
        # the engine but not in ALL_CHECKS would land in 'unexpected'.
        synthesized_passed = [
            name for name in ALL_CHECKS if name not in failed_names
        ]
        synthesized = {
            "status": report["actual_status"],
            "checks_passed": synthesized_passed,
            "checks_failed": [
                {
                    "check": name,
                    "reason": "(synthesized from MG wrapper report; "
                              "original reason not exposed by wrapper)",
                }
                for name in failed_names
            ],
            "checks_total": 13,
        }
        rec = reconcile(synthesized)
        _assert_partition(rec, label)
        assert rec["status"] == "INVALID", (
            f"[{label}] expected INVALID, got {rec['status']}"
        )
        assert report["expectation_satisfied"], (
            f"[{label}] engine's own expectation_satisfied was False: "
            f"{report}"
        )


def test_short_circuit_registry_omitted_surfaces_two_not_run_checks():
    """Known engine path: when no registry is passed, two PoR-nested checks
    never emit. Engine returns checks_total=13 hardcoded. The adapter must
    surface these as not_run (named, with reason), NOT silently drop them."""
    bundle, _, patient, _ = _build_clean_inputs()
    # Deliberately omit governance_registry.
    result = engine.verify_bundle(
        copy.deepcopy(bundle),
        expected_input_data=patient,
        governance_registry=None,
    )
    rec = reconcile(result)
    _assert_partition(rec, "registry_omitted")
    assert rec["status"] == "INVALID"
    not_run_names = {x["check"] for x in rec["not_run"]}
    # These two are the ones I empirically observed dropping to 11 emitted.
    expected_not_run = {
        "por_signature_binding_valid",
        "por_rule_policy_binding",
    }
    assert expected_not_run.issubset(not_run_names), (
        f"expected not_run to include {expected_not_run}, got {not_run_names}"
    )
    # Every not_run entry has a non-empty reason.
    for entry in rec["not_run"]:
        assert entry["reason"].strip(), entry
    assert rec["unexpected"] == []


def test_short_circuit_dangling_por_reference_surfaces_two_not_run_checks():
    """Known engine path: a PoR conclusion with a dangling derived_from
    reference fails structural and short-circuits the two nested checks."""
    bundle, _, patient, reg = _build_clean_inputs()
    bad = copy.deepcopy(bundle)
    bad["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
        "does_not_exist"
    ]
    result = engine.verify_bundle(
        bad,
        expected_input_data=patient,
        governance_registry=reg,
    )
    rec = reconcile(result)
    _assert_partition(rec, "por_dangling_ref")
    assert rec["status"] == "INVALID"
    not_run_names = {x["check"] for x in rec["not_run"]}
    expected_not_run = {
        "por_signature_binding_valid",
        "por_rule_policy_binding",
    }
    assert expected_not_run.issubset(not_run_names), (
        f"expected not_run to include {expected_not_run}, got {not_run_names}"
    )
    # And por_structural_consistency itself should have failed.
    failed_names = {x["check"] for x in rec["failed"]}
    assert "por_structural_consistency" in failed_names, failed_names
    assert rec["unexpected"] == []


def test_synthetic_unknown_emitted_name_surfaces_as_unexpected():
    """If the engine ever emits a name not in ALL_CHECKS, reconcile() must
    surface it under 'unexpected' rather than silently absorb it. This guards
    against future engine drift."""
    synthetic = {
        "status": "VALID",
        "checks_passed": list(ALL_CHECKS) + ["a_check_we_did_not_register"],
        "checks_failed": [],
        "checks_total": 13,  # the engine's hardcoded literal
    }
    rec = reconcile(synthetic)
    _assert_partition(rec, "synthetic_unknown_emit")
    assert "a_check_we_did_not_register" in rec["unexpected"]
    # And because unexpected is non-empty, reconciled status must NOT be VALID
    # even though the engine claimed VALID. This is the stricter contract.
    assert rec["status"] == "INVALID", rec


def test_synthetic_malformed_failed_entry_does_not_drop_information():
    """If the engine ever returned a string in checks_failed instead of a
    dict, reconcile() should normalize it rather than crash, and the result
    must remain accounted for."""
    synthetic = {
        "status": "INVALID",
        "checks_passed": list(ALL_CHECKS[:-1]),  # 12 passed
        "checks_failed": ["merkle_root_match"],   # a bare string, not a dict
        "checks_total": 13,
    }
    rec = reconcile(synthetic)
    _assert_partition(rec, "synthetic_malformed_failed")
    failed_names = {x["check"] for x in rec["failed"]}
    assert "merkle_root_match" in failed_names
    # The reason was reconstructed, not silently empty.
    merkle_entry = next(
        x for x in rec["failed"] if x["check"] == "merkle_root_match"
    )
    assert merkle_entry["reason"].strip()


# ----------------------------------------------------------------------
# Lightweight test runner so this file works without pytest.
# ----------------------------------------------------------------------

def _run_all():
    test_fns = [
        test_clean_bundle_reconciles_to_full_thirteen_passed,
        test_invariant_holds_across_all_six_tamper_cases,
        test_invariant_holds_across_selected_malicious_generator_cases,
        test_short_circuit_registry_omitted_surfaces_two_not_run_checks,
        test_short_circuit_dangling_por_reference_surfaces_two_not_run_checks,
        test_synthetic_unknown_emitted_name_surfaces_as_unexpected,
        test_synthetic_malformed_failed_entry_does_not_drop_information,
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
