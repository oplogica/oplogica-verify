"""L3 Coherence Failure Taxonomy (Oplogica v0.2).

Classifies verification failures into a fixed, deterministic set of failure
classes, operating ONLY on the structured fields already produced by the
reconciliation layer (the named failed / not_run checks and their reasons) plus
structured fields in the bundle. It never interprets free-text reasoning, never
uses a model, and never asserts that a decision is correct or supported.

What this adds over the existing reconcile() output
---------------------------------------------------
reconcile() already tells you WHICH checks failed or did not run. The taxonomy
adds a layer of meaning on top: for each failure it states a machine code, a
reviewer-facing explanation, what the failure *means*, what it explicitly *does
not prove*, whether it is deterministic, and whether it is detectable from the
bundle alone. This is the "what KIND of coherence failure" layer.

Discipline
----------
* Deterministic: derived by mapping known check names / reasons to fixed codes.
* No LLM, no free-text claim extraction, no probabilistic judgement.
* Never asserts a verdict on the decision (neither flawed nor supported). A failure
  means the *record cannot support independent review of that item* — not that
  the underlying decision is sound or flawed.
* Silent omission is explicitly represented as NOT detectable from the bundle
  alone, to avoid implying completeness we cannot deliver.

Prior-art note
--------------
Claim/evidence verification and supported/not-supported labelling exist in the
literature (e.g. ClaimVer, VERI-DPO). This taxonomy is not claimed as novel; it
is a narrow, deterministic mapping of Oplogica's own structured check results to
named coherence-failure classes, with explicit scope limits.
"""

from __future__ import annotations

from typing import Any

# ---- Failure class catalogue -------------------------------------------------
# Each entry is fixed reference text. "means" describes what a reviewer can
# conclude; "does_not_prove" fences the claim; flags state detectability.

FAILURE_CLASSES: dict[str, dict[str, Any]] = {
    "missing_evidence_reference": {
        "explanation": "A structured field refers to an evidence item that is "
        "required but absent from the bundle.",
        "means": "The recorded evidence bundle cannot support independent "
        "review of the referenced item.",
        "does_not_prove": "It does not establish that the underlying decision is "
        "flawed, nor that the missing evidence does not exist elsewhere.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "ghost_evidence_reference": {
        "explanation": "A reasoning or conclusion field references an evidence "
        "node that does not exist in the recorded graph.",
        "means": "The recorded reasoning graph is structurally broken for the "
        "referenced node, so it cannot be reviewed as-is.",
        "does_not_prove": "It does not establish that the reasoning was poor "
        "or the decision flawed — only that the recorded structure is broken.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "missing_policy_reference": {
        "explanation": "A recorded rule or action does not link to an approved "
        "policy constraint that is required for it.",
        "means": "The record cannot support review of the policy basis for the "
        "referenced rule or action.",
        "does_not_prove": "It does not prove the policy was violated or the "
        "decision was unfair.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "invalid_registry_reference": {
        "explanation": "The governance registry referenced by the bundle is "
        "not authentic under the pinned trust root, or its content hash is not "
        "in the allowed set.",
        "means": "The authority chain cannot be established, so downstream "
        "signature-dependent checks cannot be trusted.",
        "does_not_prove": "It does not prove malicious intent; it may indicate "
        "a configuration or cross-generation mismatch.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "hash_mismatch": {
        "explanation": "A recomputed hash (e.g. Merkle root or layer hash) does "
        "not match the stored value.",
        "means": "The bundle content changed relative to what was signed; "
        "chain-of-custody cannot be established for the affected layer.",
        "does_not_prove": "It does not establish who changed it or that the "
        "underlying decision is flawed.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "signature_invalid": {
        "explanation": "A cryptographic signature does not verify against the "
        "expected key.",
        "means": "Authenticity of the signed artifact cannot be established.",
        "does_not_prove": "It does not prove the content is false, only that it "
        "is not authenticated.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "timestamp_invalid_or_expired": {
        "explanation": "A temporal validity field is inconsistent or outside "
        "the registry's valid window.",
        "means": "The record cannot support review of the time validity of the "
        "referenced artifact.",
        "does_not_prove": "It does not prove the decision was made in bad faith.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "declared_check_not_run": {
        "explanation": "A check that is part of the canonical set did not "
        "execute (typically short-circuited after an earlier structural gate).",
        "means": "The reconciliation surfaces this gap by name; the hardcoded "
        "engine total does not by itself confirm all checks ran.",
        "does_not_prove": "It does not prove the check would have failed; only "
        "that it did not execute and the gap is visible.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "recorded_action_without_required_policy_reference": {
        "explanation": "A recorded action exists without the policy reference "
        "its schema requires.",
        "means": "The record cannot support review of the policy basis for the "
        "recorded action.",
        "does_not_prove": "It does not prove the action was unauthorized in "
        "reality.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "structured_claim_without_evidence_reference": {
        "explanation": "A structured claim present in the bundle has no link to "
        "any evidence item in the bundle.",
        "means": "The record cannot support independent review of that claim.",
        "does_not_prove": "It does not prove the claim is false or the decision "
        "incorrect.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "overclaim_detected_in_system_output": {
        "explanation": "Oplogica's own generated output attempted to use "
        "overclaiming language (caught by the Negative Claims Firewall).",
        "means": "A system-output surface was prevented from overstating what "
        "the evidence supports.",
        "does_not_prove": "It says nothing about the bundle's decision; it is a "
        "guard on Oplogica's own wording.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "outside_verification_scope": {
        "explanation": "The matter requested (e.g. legal compliance, fairness, "
        "factual truth) is outside what structural verification can address.",
        "means": "Oplogica does not produce a result on this dimension by "
        "design.",
        "does_not_prove": "It does not prove anything about that dimension "
        "either way.",
        "deterministic": True,
        "detectable_from_bundle_alone": True,
    },
    "silent_omission_not_detectable_from_bundle_alone": {
        "explanation": "Evidence or a conflict that was never recorded at all "
        "cannot be detected by inspecting the bundle by itself.",
        "means": "This is an explicit limit: absence that leaves no structural "
        "trace is outside what this bundle alone can reveal.",
        "does_not_prove": "It does not prove that no omission occurred; it "
        "states that the bundle alone cannot establish that.",
        "deterministic": True,
        "detectable_from_bundle_alone": False,
    },
}

# ---- Mapping from known check names to failure classes -----------------------
# These map the engine's existing check names to taxonomy codes deterministically.
_CHECK_TO_CLASS: dict[str, str] = {
    "registry_signature_valid": "invalid_registry_reference",
    "registry_temporal_validity": "timestamp_invalid_or_expired",
    "pon_quorum_integrity": "signature_invalid",
    "pon_vote_signatures_valid": "signature_invalid",
    "poe_chain_monotonicity": "hash_mismatch",
    "policy_hash_consistency": "hash_mismatch",
    "policy_consensus_execution_binding": "missing_policy_reference",
    "poo_signature_valid": "signature_invalid",
    "por_signature_binding_valid": "signature_invalid",
    "por_rule_policy_binding": "missing_policy_reference",
    "por_structural_consistency": "ghost_evidence_reference",
    "poc_record_integrity": "missing_evidence_reference",
    "merkle_root_match": "hash_mismatch",
}

# Reason-substring overrides: when a check's reason text clearly indicates a more
# specific class, prefer it. Deterministic substring match, not interpretation.
_REASON_OVERRIDES: tuple[tuple[str, str], ...] = (
    ("does not exist", "ghost_evidence_reference"),
    ("not in the pinned", "invalid_registry_reference"),
    ("not in allowed", "invalid_registry_reference"),
    ("root_public_key does not match", "invalid_registry_reference"),
    ("merkle", "hash_mismatch"),
    ("no expected_input_data", "missing_evidence_reference"),
    ("short-circuit", "declared_check_not_run"),
    ("did not run", "declared_check_not_run"),
    ("not run", "declared_check_not_run"),
)


def _classify_one(check: str, reason: str, bucket: str) -> str:
    """Return the failure class code for a single check, deterministically."""
    reason_low = (reason or "").lower()

    # not_run bucket is always the declared_check_not_run class.
    if bucket == "not_run":
        return "declared_check_not_run"

    # Reason-based override first (most specific).
    for needle, code in _REASON_OVERRIDES:
        if needle in reason_low:
            # Don't let a generic "not run" override a genuine failed check.
            if code == "declared_check_not_run" and bucket == "failed":
                continue
            return code

    # Fall back to the check-name mapping.
    return _CHECK_TO_CLASS.get(check, "outside_verification_scope")


def classify(reconciled: dict[str, Any]) -> dict[str, Any]:
    """Produce an L3 coherence-failure classification from a reconciled result.

    Input: the dict returned by ``ova_demo.checks.reconcile``.
    Output: an additive classification block (does not mutate the input).

    The output is safe to attach to an API response under an additive key.
    """
    classified: list[dict[str, Any]] = []

    for entry in reconciled.get("failed", []) or []:
        check = entry.get("check", "")
        reason = entry.get("reason", "")
        code = _classify_one(check, reason, "failed")
        classified.append(_make_entry(check, reason, code, "failed"))

    for entry in reconciled.get("not_run", []) or []:
        check = entry.get("check", "")
        reason = entry.get("reason", "")
        code = _classify_one(check, reason, "not_run")
        classified.append(_make_entry(check, reason, code, "not_run"))

    # Always include the silent-omission limit as an explicit standing note,
    # so every classification makes the boundary visible.
    boundary_note = _reference("silent_omission_not_detectable_from_bundle_alone")

    return {
        "l3_failure_classification": classified,
        "scope_boundary_note": {
            "code": "silent_omission_not_detectable_from_bundle_alone",
            **boundary_note,
        },
        "taxonomy_version": "0.2",
    }


def _make_entry(check: str, reason: str, code: str, bucket: str) -> dict[str, Any]:
    ref = _reference(code)
    return {
        "check": check,
        "bucket": bucket,
        "engine_reason": reason,
        "failure_class": code,
        **ref,
    }


def _reference(code: str) -> dict[str, Any]:
    spec = FAILURE_CLASSES[code]
    return {
        "explanation": spec["explanation"],
        "means": spec["means"],
        "does_not_prove": spec["does_not_prove"],
        "deterministic": spec["deterministic"],
        "detectable_from_bundle_alone": spec["detectable_from_bundle_alone"],
    }


def all_classes() -> dict[str, dict[str, Any]]:
    """Return the full catalogue (for docs/tests)."""
    return {k: dict(v) for k, v in FAILURE_CLASSES.items()}
