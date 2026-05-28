"""Demonstrate raw engine output vs reconciled output on a failing bundle
where only 11 named checks were actually emitted by the engine.

The case: a dangling PoR reference (one conclusion's derived_from points at
an id that does not exist). The engine's PoR block short-circuits past the
two nested checks (por_signature_binding_valid, por_rule_policy_binding),
so the raw verifier_result emits only 11 named checks. The engine still
reports checks_total=13 because that field is a hardcoded literal in the
engine — which is exactly the accounting gap reconcile() closes.

This script is not a test. It is the on-demand artifact for the demo brief.
"""

from __future__ import annotations

import copy
import io
import json
import os
import sys
import contextlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo.checks import ALL_CHECKS, reconcile


def main() -> None:
    # 1. Get a clean bundle from the engine.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        bundle, _, _operator, patient_data = engine.run_triage_scenario()

    # 2. Apply the dangling-reference mutation.
    bad = copy.deepcopy(bundle)
    bad["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
        "does_not_exist"
    ]

    # 3. Run the unmodified engine verifier.
    raw = engine.verify_bundle(
        bad,
        expected_input_data=patient_data,
        governance_registry=engine.GOVERNANCE_REGISTRY_V1,
    )

    raw_passed = list(raw["checks_passed"])
    raw_failed = [f["check"] for f in raw["checks_failed"]]
    raw_named = raw_passed + raw_failed

    print("=" * 70)
    print(" RAW engine output (the field shipped today by ova_v2.verify_bundle)")
    print("=" * 70)
    print(f"  status:             {raw['status']}")
    print(f"  checks_total field: {raw['checks_total']}   "
          "  <-- hardcoded literal in engine")
    print(f"  checks_passed:      {len(raw_passed)} names")
    print(f"  checks_failed:      {len(raw_failed)} names")
    print(f"  named checks total: {len(raw_named)}")
    print(f"  canonical 13 not emitted by engine on this bundle: "
          f"{sorted(set(ALL_CHECKS) - set(raw_named))}")
    print()
    print("  Reading the raw output naively, a UI would render '11 passed, "
          "1 failed' alongside a 'checks_total: 13' field, with no named "
          "indication of what happened to the other 2 checks. That is the "
          "accounting gap.")
    print()

    # 4. Reconcile.
    rec = reconcile(raw)

    print("=" * 70)
    print(" RECONCILED output (what the demo's report layer will use)")
    print("=" * 70)
    print(f"  status (stricter):  {rec['status']}")
    print(f"  checks_total:       {rec['checks_total']}   "
          "  <-- computed from len(ALL_CHECKS)")
    print(f"  passed  ({rec['checks_passed_count']}):")
    for name in rec["passed"]:
        print(f"      PASS  {name}")
    print(f"  failed  ({rec['checks_failed_count']}):")
    for entry in rec["failed"]:
        print(f"      FAIL  {entry['check']}")
        print(f"            reason: {entry['reason']}")
    print(f"  not_run ({rec['checks_not_run_count']}):")
    for entry in rec["not_run"]:
        print(f"      SKIP  {entry['check']}")
        print(f"            reason: {entry['reason']}")
    print(f"  unexpected: {rec['unexpected']}")
    print()
    print(f"  Invariant: passed + failed + not_run = "
          f"{rec['checks_passed_count']} + {rec['checks_failed_count']} + "
          f"{rec['checks_not_run_count']} = "
          f"{rec['checks_passed_count'] + rec['checks_failed_count'] + rec['checks_not_run_count']} "
          f"== len(ALL_CHECKS) = {len(ALL_CHECKS)}.")
    print()
    print("Scope reminder (will live in the Evidence Integrity Report):")
    print("  This reconciliation confirms the demo's accounting invariant.")
    print("  It does not assert: regulatory compliance, clinical correctness,")
    print("  model fairness, or production-grade readiness. Those are out of")
    print("  scope for the OVA verifier and for this adapter.")


if __name__ == "__main__":
    main()
