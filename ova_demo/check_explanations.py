"""Per-check explanation registry for the 13 canonical OVA checks.

Purpose
-------
When a check passes or fails, a report or UI needs to say, in auditor-readable
language, what the check actually confirmed (or what its failure indicates) —
without overclaiming. This module is the single source of those explanations.

Each entry maps a check name from ``ova_demo.checks.ALL_CHECKS`` to:

  * ``meaning``        — what a PASS confirms, stated narrowly.
  * ``fields_checked`` — the concrete bundle/registry fields the verifier
                         inspects or recomputes for this check. Grounded in
                         the actual engine logic, not aspirational.
  * ``failure_means``  — what a FAIL indicates about the recorded evidence.
  * ``does_not_mean``  — the boundary: what this check does NOT establish,
                         so a PASS is never read as more than it is.

Scope discipline
----------------
These explanations are about *evidence integrity and binding* — whether the
recorded artifacts are authentic, internally consistent, and untampered under
the demo trust root. They make no statement about whether a decision was
correct, whether a model behaves fairly, whether an institution meets any
legal or regulatory obligation, or whether any of this is fit for real-world
critical deployment. The ``does_not_mean`` fields exist precisely to keep that
line bright.

This module contains no scoring, no verification logic, and no I/O. It is a
static data table plus accessors.
"""

from __future__ import annotations

from ova_demo.checks import ALL_CHECKS


# Required keys for every explanation entry.
REQUIRED_FIELDS: tuple[str, ...] = (
    "meaning",
    "fields_checked",
    "failure_means",
    "does_not_mean",
)


_EXPLANATIONS: dict[str, dict[str, object]] = {
    "registry_signature_valid": {
        "meaning": (
            "The governance registry presented to the verifier is signed by "
            "the demo trust root, and the registry's content hash is in the "
            "verifier's pinned set of allowed registry hashes."
        ),
        "fields_checked": [
            "registry.registry_signature",
            "registry.registry_root_public_key",
            "trust_root.trusted_root_public_key (pinned, supplied independently)",
            "trust_root.allowed_registry_hashes (pinned, supplied independently)",
        ],
        "failure_means": (
            "The registry is unsigned, signed by a key the verifier does not "
            "trust, or its content hash is not in the pinned allow-list. The "
            "verifier will not anchor any participant or operator key from it, "
            "so dependent checks cannot proceed on a trusted basis."
        ),
        "does_not_mean": (
            "A valid signature does not establish that the policies in the "
            "registry are good, lawful, or appropriate — only that the "
            "registry came from the pinned authority and was not altered."
        ),
    },
    "registry_temporal_validity": {
        "meaning": (
            "The operation's decision timestamp falls inside the registry's "
            "stated validity window."
        ),
        "fields_checked": [
            "registry.valid_from",
            "registry.valid_until",
            "operational_layer.poo.decision_timestamp",
        ],
        "failure_means": (
            "The decision was recorded as occurring outside the window during "
            "which this registry was declared valid, or the timing fields are "
            "missing or malformed."
        ),
        "does_not_mean": (
            "Falling inside the window does not establish that the timestamp "
            "reflects when anything truly happened in the world; it confirms "
            "internal consistency between the recorded timestamp and the "
            "registry's declared bounds."
        ),
    },
    "pon_quorum_integrity": {
        "meaning": (
            "The recorded negotiation votes satisfy the registry's consensus "
            "rule: the accepting weight meets the threshold and at least one "
            "vote from a critical-acceptor role is an ACCEPT. Vote weights and "
            "roles are taken from the registry, not from the bundle."
        ),
        "fields_checked": [
            "constitutional_layer.pon.votes[].participant_id",
            "constitutional_layer.pon.votes[].vote",
            "registry.authorized_participants[].canonical_vote_weight",
            "registry.authorized_participants[].role",
            "registry.consensus_threshold",
            "registry.critical_acceptor_roles",
        ],
        "failure_means": (
            "The recorded votes do not meet the registry's quorum rule, a "
            "voter is not in the registry, or a vote value is not allowed. "
            "The recorded consensus does not satisfy the stated axiom."
        ),
        "does_not_mean": (
            "Meeting quorum does not establish that the decision was wise or "
            "that the authorized voters acted in good faith; collusion among "
            "authorized signers that meets quorum is outside what this check "
            "can detect."
        ),
    },
    "pon_vote_signatures_valid": {
        "meaning": (
            "Each recorded vote carries a signature that verifies against the "
            "voting participant's public key as resolved from the registry, "
            "over the canonical vote payload (including the policy hash the "
            "vote was cast on)."
        ),
        "fields_checked": [
            "constitutional_layer.pon.votes[].signature",
            "constitutional_layer.pon.votes[].vote",
            "constitutional_layer.pon.votes[].policy_hash",
            "constitutional_layer.pon.votes[].epoch_id",
            "registry.authorized_participants[].public_key",
        ],
        "failure_means": (
            "At least one vote signature does not verify, a vote lacks a "
            "signature, or the signer is not an authorized participant. A "
            "recorded vote cannot be cryptographically attributed to the "
            "participant it claims to come from."
        ),
        "does_not_mean": (
            "A valid signature attributes the vote to the holder of the key; "
            "it does not establish that the key was held only by the intended "
            "person or that it was uncompromised before signing."
        ),
    },
    "poe_chain_monotonicity": {
        "meaning": (
            "The policy-evolution chain is internally intact: each version's "
            "stored self-hash matches its recomputed hash, the genesis version "
            "has no predecessor, and every later version links to the prior "
            "version's self-hash."
        ),
        "fields_checked": [
            "constitutional_layer.poe.versions[].self_hash (recomputed)",
            "constitutional_layer.poe.versions[].previous_version_hash",
        ],
        "failure_means": (
            "A version's content was altered without updating its hash, a link "
            "to the previous version is broken, or the genesis is malformed. "
            "The recorded version history is not a consistent append-only "
            "chain."
        ),
        "does_not_mean": (
            "An intact chain does not establish that the policy versions it "
            "records are the only ones that ever existed, nor that any "
            "version's content is substantively sound."
        ),
    },
    "policy_hash_consistency": {
        "meaning": (
            "Each policy version's stored hash matches the hash recomputed "
            "from its raw constraints; every recorded vote references a policy "
            "hash that exists in the evolution chain; and the operation's "
            "declared policy version and hash agree with the chain."
        ),
        "fields_checked": [
            "constitutional_layer.poe.versions[].constraints (recomputed hash)",
            "constitutional_layer.poe.versions[].policy_hash",
            "constitutional_layer.pon.votes[].policy_hash",
            "operational_layer.poo.policy_version_id",
            "operational_layer.poo.policy_hash",
        ],
        "failure_means": (
            "Policy constraints were edited without updating the stored hash, "
            "a vote points at a policy hash absent from the chain, or the "
            "operation's policy reference does not match the chain. The "
            "recorded policy content and the references to it are inconsistent."
        ),
        "does_not_mean": (
            "Consistent hashes do not establish that the policy is correct or "
            "appropriate for the situation; the check binds references to "
            "content, not content to any external standard."
        ),
    },
    "policy_consensus_execution_binding": {
        "meaning": (
            "The operation executed the same policy the quorum approved: every "
            "ACCEPT vote counted toward consensus binds to the active epoch, "
            "policy version, and policy hash that the operation declares. "
            "Quorum is computed only from votes that bind to the active policy."
        ),
        "fields_checked": [
            "registry.epoch_id",
            "operational_layer.poo.policy_version_id",
            "operational_layer.poo.policy_hash",
            "constitutional_layer.pon.votes[].epoch_id",
            "constitutional_layer.pon.votes[].policy_version_id_anchor",
            "constitutional_layer.pon.votes[].policy_hash",
        ],
        "failure_means": (
            "Votes that approved one policy version or epoch are being used to "
            "authorize execution of a different one (cross-version grafting or "
            "cross-epoch replay), so the consensus on the active policy is not "
            "actually satisfied."
        ),
        "does_not_mean": (
            "Correct binding does not establish that executing the approved "
            "policy produced a correct or safe outcome; it establishes that "
            "the executed policy is the one consensus actually approved."
        ),
    },
    "poo_signature_valid": {
        "meaning": (
            "The operation record is signed by the operator's key as resolved "
            "from the registry, over the supplied raw input plus the policy "
            "version and decision timestamp; and the recorded input-data hash "
            "matches the hash of the supplied raw input."
        ),
        "fields_checked": [
            "operational_layer.poo.operator_id",
            "operational_layer.poo.operator_signature",
            "operational_layer.poo.input_data_hash",
            "operational_layer.poo.policy_version_id",
            "operational_layer.poo.decision_timestamp",
            "registry.authorized_operators[].public_key",
            "the separately supplied raw input (expected_input_data)",
        ],
        "failure_means": (
            "The operation signature does not verify, the operator is not "
            "authorized in the registry, or the supplied input does not hash "
            "to the recorded input-data hash. (If no raw input was supplied, "
            "this check is reported as not run rather than failed.)"
        ),
        "does_not_mean": (
            "A valid signature attributes the operation to the operator's key "
            "and ties it to the supplied input; it does not establish that the "
            "input data was true, or that the decision derived from it was "
            "correct."
        ),
    },
    "por_signature_binding_valid": {
        "meaning": (
            "The recorded reasoning is anchored to this bundle's operation: "
            "the reasoning record's anchor fields (operation hash, policy "
            "hash, policy version, decision timestamp) match the operation in "
            "the same bundle, defeating reuse of a reasoning record from "
            "another bundle."
        ),
        "fields_checked": [
            "operational_layer.por.poo_anchor.operational_hash",
            "operational_layer.por.poo_anchor.policy_hash",
            "operational_layer.por.poo_anchor.policy_version_id",
            "operational_layer.por.poo_anchor.decision_timestamp",
            "operational_layer.poo (the same fields, for comparison)",
        ],
        "failure_means": (
            "The reasoning record has no anchor or an anchor that does not "
            "match this bundle's operation, suggesting the reasoning may have "
            "been grafted from a different operation or bundle."
        ),
        "does_not_mean": (
            "A matching anchor does not establish that the reasoning is "
            "logically valid or that it actually drove the decision; it "
            "establishes that the reasoning record belongs to this operation."
        ),
    },
    "por_rule_policy_binding": {
        "meaning": (
            "Every rule invoked in the reasoning names a constraint that "
            "exists in the active policy, and the rule's declared policy hash "
            "and constraint hash match the verifier's recomputation from the "
            "active policy's raw constraints."
        ),
        "fields_checked": [
            "operational_layer.por.rules_applied[].from_constraint",
            "operational_layer.por.rules_applied[].policy_hash",
            "operational_layer.por.rules_applied[].constraint_hash",
            "constitutional_layer.poe.versions[active].constraints (recomputed)",
        ],
        "failure_means": (
            "A rule references a constraint that is not in the active policy, "
            "or its declared hashes do not match the recomputed policy/"
            "constraint hashes, indicating an injected or altered rule."
        ),
        "does_not_mean": (
            "A bound rule does not establish that applying the rule was the "
            "right thing to do; it establishes that the rule maps to a genuine "
            "constraint in the approved policy."
        ),
    },
    "por_structural_consistency": {
        "meaning": (
            "The reasoning graph is well formed and its signature verifies: "
            "every reference resolves to a real node, the conclusion graph "
            "contains no cycle, every conclusion has a derivation path "
            "reaching at least one premise, and the graph is signed by the "
            "operator's registry-anchored key."
        ),
        "fields_checked": [
            "operational_layer.por.premises[].id",
            "operational_layer.por.rules_applied[].id",
            "operational_layer.por.conclusions[].id",
            "operational_layer.por.conclusions[].derived_from",
            "operational_layer.por.graph_signature",
            "registry.authorized_operators[].public_key",
        ],
        "failure_means": (
            "A reference points to a non-existent node, the conclusion graph "
            "has a cycle, a conclusion does not trace back to any premise "
            "(a floating logic island), or the graph signature does not "
            "verify. The recorded reasoning structure is malformed or "
            "unauthenticated."
        ),
        "does_not_mean": (
            "A well-formed, signed graph does not establish that the reasoning "
            "is sound, persuasive, or that its conclusions are true; structure "
            "and authenticity are not the same as logical quality."
        ),
    },
    "poc_record_integrity": {
        "meaning": (
            "The recorded conflicts are intact: none is marked as silenced and "
            "each uses a recognized resolution protocol."
        ),
        "fields_checked": [
            "operational_layer.poc.conflicts[].silenced",
            "operational_layer.poc.conflicts[].resolution_protocol",
        ],
        "failure_means": (
            "A recorded conflict is marked silenced, or a conflict uses an "
            "unrecognized resolution protocol. A conflict that was recorded is "
            "not being kept visible and intact."
        ),
        "does_not_mean": (
            "This check covers the integrity of conflicts that were recorded. "
            "It does not establish that every conflict which should have been "
            "detected was in fact recorded; completeness of conflict capture "
            "is outside its scope."
        ),
    },
    "merkle_root_match": {
        "meaning": (
            "The Merkle root recomputed over the five proof layers matches the "
            "root stored in the bundle, so no layer was altered after the root "
            "was fixed."
        ),
        "fields_checked": [
            "constitutional_layer.pon (hashed)",
            "constitutional_layer.poe (hashed)",
            "operational_layer.poo (hashed)",
            "operational_layer.por (hashed)",
            "operational_layer.poc (hashed)",
            "bundle.merkle_root",
        ],
        "failure_means": (
            "At least one proof layer was changed after the root was computed, "
            "or the stored root was swapped. The bundle's layers and its "
            "claimed root no longer agree."
        ),
        "does_not_mean": (
            "A matching root establishes that the five layers are unaltered as "
            "a set; it does not by itself establish anything about the "
            "correctness of their contents. The tree is a simple binary Merkle "
            "tree and does not implement the RFC 6962 (Certificate "
            "Transparency) construction."
        ),
    },
}


def get_explanation(check_name: str) -> dict[str, object]:
    """Return the explanation entry for a canonical check name.

    Raises
    ------
    KeyError
        If ``check_name`` is not one of the canonical checks in ALL_CHECKS.
    """
    if check_name not in _EXPLANATIONS:
        raise KeyError(
            f"No explanation registered for check '{check_name}'. "
            "Only the canonical checks in ALL_CHECKS are explained."
        )
    # Return a shallow copy so callers cannot mutate the registry in place.
    entry = _EXPLANATIONS[check_name]
    return {
        "meaning": entry["meaning"],
        "fields_checked": list(entry["fields_checked"]),
        "failure_means": entry["failure_means"],
        "does_not_mean": entry["does_not_mean"],
    }


def all_explanations() -> dict[str, dict[str, object]]:
    """Return explanation entries for all canonical checks (copies)."""
    return {name: get_explanation(name) for name in ALL_CHECKS}
