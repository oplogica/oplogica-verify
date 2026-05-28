"""Tests for ova_demo.tamper_examples.

Proves:
  * all 6 canonical tamper cases are generated (with files on disk),
  * every tampered bundle reconciles to INVALID,
  * every result went through reconcile() (counts partition to 13),
  * every failed and not_run check carries an explanation snippet,
  * no banned overclaiming terms appear anywhere in the manifest text.

Uses a temp directory. Real engine, no mocks.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo import tamper_examples
from ova_demo.checks import ALL_CHECKS


EXPECTED_IDS = {
    "T1_pon_break_quorum_axiom",
    "T2_poe_break_chain_link",
    "T3_poo_change_input_hash",
    "T4_por_invalid_reference",
    "T5_poc_silence_conflict",
    "T6_merkle_root_direct_swap",
}

BANNED_TERMS = (
    "100%",
    "compliant",
    "compliance",
    "certified",
    "certification",
    "clinically correct",
    "clinical correctness",
    "medically correct",
    "unbiased",
    "bias-free",
    "production-grade",
    "production grade",
    "guarantee",
    "guaranteed",
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _walk_strings(obj):
    """Yield every string value in a nested JSON-like structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(k)
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_strings(item)


def test_all_six_cases_generated_with_files():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        ids = {c["test_id"] for c in manifest["cases"]}
        _assert(ids == EXPECTED_IDS, f"case ids mismatch: {ids}")
        _assert(len(manifest["cases"]) == 6, "expected exactly 6 cases")
        # Manifest file exists.
        manifest_path = os.path.join(tmp, "tamper_manifest.json")
        _assert(os.path.isfile(manifest_path), "manifest file not written")
        # Each tampered bundle file exists and is valid JSON.
        for case in manifest["cases"]:
            abs_path = os.path.join(_ROOT, case["tampered_bundle_path"])
            # tampered_bundle_path is relative to _ROOT; but in tests we built
            # into tmp, so resolve against tmp by basename as a fallback.
            if not os.path.isfile(abs_path):
                abs_path = os.path.join(
                    tmp, os.path.basename(case["tampered_bundle_path"])
                )
            _assert(
                os.path.isfile(abs_path),
                f"tampered bundle missing for {case['test_id']}: {abs_path}",
            )
            with open(abs_path, "r", encoding="utf-8") as f:
                json.load(f)  # must parse


def test_every_tampered_bundle_is_invalid():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        for case in manifest["cases"]:
            _assert(
                case["reconciled_status"] == "INVALID",
                f"{case['test_id']} expected INVALID, "
                f"got {case['reconciled_status']}",
            )


def test_every_result_went_through_reconcile_partition():
    """passed + failed + not_run == 13 for every case (the reconcile contract)."""
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        for case in manifest["cases"]:
            total = (
                case["passed_count"]
                + case["failed_count"]
                + case["not_run_count"]
            )
            _assert(
                total == len(ALL_CHECKS),
                f"{case['test_id']} partition broken: "
                f"{case['passed_count']}+{case['failed_count']}+"
                f"{case['not_run_count']} = {total} != {len(ALL_CHECKS)}",
            )
            _assert(
                case["checks_total"] == len(ALL_CHECKS),
                f"{case['test_id']} checks_total != {len(ALL_CHECKS)}",
            )
            # At least one failed or not_run, else tampering went undetected.
            _assert(
                case["failed_count"] + case["not_run_count"] >= 1,
                f"{case['test_id']} produced no failed/not_run checks",
            )


def test_failed_and_not_run_checks_have_explanations():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        for case in manifest["cases"]:
            failed_names = {c["check"] for c in case["failed_checks"]}
            not_run_names = {c["check"] for c in case["not_run_checks"]}
            expl_failed = {
                e["check"] for e in case["explanations"]["failed"]
            }
            expl_not_run = {
                e["check"] for e in case["explanations"]["not_run"]
            }
            _assert(
                failed_names == expl_failed,
                f"{case['test_id']} failed explanations mismatch: "
                f"{failed_names} vs {expl_failed}",
            )
            _assert(
                not_run_names == expl_not_run,
                f"{case['test_id']} not_run explanations mismatch: "
                f"{not_run_names} vs {expl_not_run}",
            )
            # Each explanation snippet for a canonical check carries the
            # boundary fields.
            for e in (case["explanations"]["failed"]
                      + case["explanations"]["not_run"]):
                if e["check"] in ALL_CHECKS:
                    for key in ("meaning", "failure_means", "does_not_mean"):
                        _assert(
                            key in e and str(e[key]).strip(),
                            f"{case['test_id']} explanation for "
                            f"{e['check']} missing '{key}'",
                        )


def test_manifest_contains_no_banned_terms():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        # Drop the internal _manifest_path key (a filesystem path, not copy).
        manifest_for_scan = {
            k: v for k, v in manifest.items() if k != "_manifest_path"
        }
        offenders = []
        for s in _walk_strings(manifest_for_scan):
            low = s.lower()
            for term in BANNED_TERMS:
                if term in low:
                    offenders.append((term, s[:80]))
        _assert(not offenders, f"banned terms in manifest: {offenders}")


def test_t4_por_invalid_reference_shape():
    """Spot-check the headline example: T4 must show the two PoR-nested
    checks under not_run, with por_structural_consistency failing."""
    with tempfile.TemporaryDirectory() as tmp:
        manifest = tamper_examples.build(tmp)
        t4 = next(
            c for c in manifest["cases"]
            if c["test_id"] == "T4_por_invalid_reference"
        )
        _assert(t4["reconciled_status"] == "INVALID", t4)
        failed_names = {c["check"] for c in t4["failed_checks"]}
        not_run_names = {c["check"] for c in t4["not_run_checks"]}
        _assert(
            "por_structural_consistency" in failed_names,
            f"T4 should fail por_structural_consistency: {failed_names}",
        )
        _assert(
            {"por_signature_binding_valid", "por_rule_policy_binding"}
            .issubset(not_run_names),
            f"T4 should mark two PoR checks not_run: {not_run_names}",
        )


def _run_all():
    tests = [
        test_all_six_cases_generated_with_files,
        test_every_tampered_bundle_is_invalid,
        test_every_result_went_through_reconcile_partition,
        test_failed_and_not_run_checks_have_explanations,
        test_manifest_contains_no_banned_terms,
        test_t4_por_invalid_reference_shape,
    ]
    failures = []
    for fn in tests:
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
    print(f"All {len(tests)} tests passed.")


if __name__ == "__main__":
    _run_all()
