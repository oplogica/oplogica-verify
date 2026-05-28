"""Canonical 13-check registry and reconciliation adapter for OVA demo output.

Why this module exists
----------------------
The vendored engine (``ova_v2.py``) returns ``checks_total: 13`` as a hardcoded
literal, and it appends check names to ``checks_passed`` / ``checks_failed``
imperatively as each block runs. On some failing inputs (e.g. a malformed PoR
reference, or the registry being omitted by the caller), two PoR-nested checks
never emit at all — only 11 names appear, while the result still claims a
denominator of 13. The engine's ``status`` is still correctly ``INVALID`` in
those cases, so this is not a security defect. But it is an *accounting* one:
a report rendered straight from ``verifier_result`` could truthfully say
"INVALID" while implicitly representing a 13-denominator that does not match
the 11 checks that actually ran.

For a project whose headline UI line is literally a fraction with 13 in the
denominator, that is the kind of thing an adversarial reviewer will catch.
This module fixes it at the edge, without modifying the engine.

What ``reconcile()`` guarantees
-------------------------------
For any ``verifier_result`` produced by ``ova_v2.verify_bundle``:

  * Every name in ``ALL_CHECKS`` lands in exactly one of: ``passed``,
    ``failed``, ``not_run``.
  * ``len(passed) + len(failed) + len(not_run) == len(ALL_CHECKS) == 13``,
    always. This is asserted, not hoped for.
  * If the engine emits a check name not present in ``ALL_CHECKS``, it is
    surfaced under ``unexpected`` rather than silently dropped — because
    silent dropping would be the exact kind of dishonesty this adapter exists
    to prevent.
  * ``checks_total`` in the reconciled output is computed from
    ``len(ALL_CHECKS)``, never copied from the engine's hardcoded literal.

What this module does NOT do
----------------------------
  * It does not claim any verification result implies regulatory compliance,
    clinical correctness, model fairness, production-grade readiness, or any
    similar property. Reconciliation is an accounting transform over the
    engine's output. Scope statements live in the report layer (separate
    module) and in the bundle itself.
  * It does not modify the engine. If the engine's check set ever changes,
    ``ALL_CHECKS`` here must be updated deliberately and the test suite will
    fail loudly until it is.
"""

from __future__ import annotations

from typing import Any


# The 13 check names emitted by ova_v2.verify_bundle on a clean bundle,
# in the order specified in the demo brief §3.2. This tuple is the single
# source of truth for the demo's denominator. Do not edit casually.
ALL_CHECKS: tuple[str, ...] = (
    "registry_signature_valid",
    "registry_temporal_validity",
    "pon_quorum_integrity",
    "pon_vote_signatures_valid",
    "poe_chain_monotonicity",
    "policy_hash_consistency",
    "policy_consensus_execution_binding",
    "poo_signature_valid",
    "por_signature_binding_valid",
    "por_rule_policy_binding",
    "por_structural_consistency",
    "poc_record_integrity",
    "merkle_root_match",
)

_ALL_CHECKS_SET: frozenset[str] = frozenset(ALL_CHECKS)


def reconcile(verifier_result: dict[str, Any]) -> dict[str, Any]:
    """Reconcile a raw ``verify_bundle`` result against the canonical 13.

    Parameters
    ----------
    verifier_result : dict
        The dict returned by ``ova_v2.verify_bundle``. Must contain
        ``checks_passed`` (list of str) and ``checks_failed`` (list of
        dicts with a ``"check"`` key). Other fields are passed through
        as-is on the returned object's ``raw`` field for traceability.

    Returns
    -------
    dict
        ``{
            "status": "VALID" | "INVALID",
            "passed":   [str, ...],
            "failed":   [{"check": str, "reason": str, ...}, ...],
            "not_run":  [{"check": str, "reason": str}, ...],
            "unexpected": [str, ...],     # names emitted but not in ALL_CHECKS
            "checks_total": 13,           # always len(ALL_CHECKS)
            "checks_passed_count": int,
            "checks_failed_count": int,
            "checks_not_run_count": int,
            "raw": <verifier_result, unchanged>,
         }``

        Invariant: ``passed + failed + not_run`` partitions ``ALL_CHECKS``.

    Notes
    -----
    * ``status`` is recomputed from the reconciled counts ("VALID" iff
      ``failed`` is empty AND ``not_run`` is empty AND ``unexpected`` is
      empty). This is stricter than the engine's notion of VALID, which
      only requires ``checks_failed`` empty. A bundle where two checks
      silently did not run is not VALID under this adapter, even if the
      engine reported VALID — because we cannot honestly claim 13/13 if
      only 11 ran. In practice the engine's clean-bundle path emits all
      13, so the two definitions coincide for healthy bundles.
    * No semantic interpretation of any check is performed here. This is
      a pure accounting transform.
    """
    passed_raw = list(verifier_result.get("checks_passed", []))
    failed_raw = list(verifier_result.get("checks_failed", []))

    # Defensive: normalize failed entries (each should already be a dict
    # with at least "check", but we do not assume).
    normalized_failed: list[dict[str, Any]] = []
    for entry in failed_raw:
        if isinstance(entry, dict) and "check" in entry:
            normalized_failed.append(dict(entry))
        elif isinstance(entry, str):
            normalized_failed.append({
                "check": entry,
                "reason": "(no reason provided by engine)",
            })
        else:
            # Truly malformed — surface it explicitly rather than dropping.
            normalized_failed.append({
                "check": "<malformed_failed_entry>",
                "reason": f"engine returned non-dict failed entry: {entry!r}",
            })

    emitted_names: set[str] = set(passed_raw) | {
        f["check"] for f in normalized_failed
    }

    # Partition.
    passed = [name for name in passed_raw if name in _ALL_CHECKS_SET]
    failed = [f for f in normalized_failed if f["check"] in _ALL_CHECKS_SET]

    not_run: list[dict[str, str]] = []
    for name in ALL_CHECKS:
        if name not in emitted_names:
            not_run.append({
                "check": name,
                "reason": (
                    "Check did not execute. This typically means an upstream "
                    "block short-circuited before reaching this check (e.g. "
                    "registry not authentic, or a structural precondition "
                    "in the same proof layer failed first). The engine's "
                    "hardcoded checks_total=13 does not by itself confirm "
                    "all 13 checks ran; this reconciliation surfaces the gap."
                ),
            })

    # Names emitted by the engine but not in our canonical list — should
    # be empty under current engine, but if it ever happens we refuse to
    # hide it.
    unexpected = sorted(emitted_names - _ALL_CHECKS_SET)

    # Reconciled status: stricter than the engine's. We require all 13
    # to have actually run AND none to have failed AND no unexpected
    # names AND no malformed entries.
    has_malformed = any(
        f["check"] == "<malformed_failed_entry>" for f in failed
    ) or any(
        f["check"] == "<malformed_failed_entry>" for f in normalized_failed
    )
    status = (
        "VALID"
        if not failed and not not_run and not unexpected and not has_malformed
        else "INVALID"
    )

    reconciled = {
        "status": status,
        "passed": passed,
        "failed": failed,
        "not_run": not_run,
        "unexpected": unexpected,
        "checks_total": len(ALL_CHECKS),
        "checks_passed_count": len(passed),
        "checks_failed_count": len(failed),
        "checks_not_run_count": len(not_run),
        "raw": verifier_result,
    }

    # Hard invariant — if this ever trips, the adapter itself is wrong.
    assert (
        reconciled["checks_passed_count"]
        + reconciled["checks_failed_count"]
        + reconciled["checks_not_run_count"]
        == len(ALL_CHECKS)
    ), (
        "reconcile() invariant violated: "
        f"passed={reconciled['checks_passed_count']}, "
        f"failed={reconciled['checks_failed_count']}, "
        f"not_run={reconciled['checks_not_run_count']}, "
        f"expected total={len(ALL_CHECKS)}"
    )

    return reconciled
