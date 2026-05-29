"""Deterministic Post-Hoc Verification Discipline (Oplogica v0.2).

A small, fixed metadata block that makes Oplogica's verification posture
explicit on every result. It states plainly that all checks are recomputed
after the fact from the signed bundle, registry, trust root, and structured
fields — with no model interpretation and no claim about decision correctness,
fairness, legality, or completeness of omission detection.

This block is descriptive, not a certificate. It introduces no new authority and
makes no novelty claim. It exists so that any consumer of an Oplogica result can
see, in machine-readable form, exactly what the verification does and does not
do.
"""

from __future__ import annotations

from typing import Any

# Fixed, deterministic posture. These values never change at runtime; they
# describe how Oplogica verifies, by construction.
VERIFICATION_DISCIPLINE: dict[str, Any] = {
    "deterministic": True,
    "uses_llm_interpretation": False,
    "free_text_claim_extraction": False,
    "checks_recomputed_from_bundle": True,
    "verifies_decision_correctness": False,
    "certifies_compliance": False,
    "establishes_fairness": False,
    "detects_silent_omission": False,
    "is_compliance_certificate": False,
    "is_a_standard": False,
    "note": "All checks are recomputed after the fact from the signed bundle, "
    "registry, trust root, and structured fields. This supports independent "
    "review and tamper-evidence. It does not prove decision correctness, does "
    "not certify compliance, and does not establish fairness. Silent omissions "
    "that leave no structural trace are not detectable from the bundle alone.",
}


def discipline_block() -> dict[str, Any]:
    """Return a copy of the fixed verification-discipline metadata."""
    return dict(VERIFICATION_DISCIPLINE)
