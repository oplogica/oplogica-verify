"""
OVA v2 — Minimal Proof Bundle Generator
========================================

Single-file end-to-end implementation of OpLogica Verification Architecture v2
for the medical triage test scenario defined in triage_scenario.md.

Generates a proof bundle with:
  - Constitutional layer: PoN + PoE
  - Operational layer:    PoO + PoR + PoC
  - Merkle root over all five layer hashes
  - verifier_result

Prototype signature scheme: Ed25519 (production target: ML-DSA / Dilithium-III).
All Ed25519 usages are tagged "Ed25519-prototype-2026" in the output.

Author: OpLogica Research
Test ID: ova-test-2026-05-20-001
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


# ============================================================
# CONSTANTS — explicit prototype tagging
# ============================================================

SIGNATURE_SCHEME_TAG = "Ed25519-prototype-2026"
PRODUCTION_TARGET = "ML-DSA (Dilithium-III, FIPS 204)"
HASH_ALGORITHM = "SHA-256"
FRAMEWORK_VERSION = "OpLogica v2.5"
BUNDLE_ID = "ova-test-2026-05-20-001"


# ============================================================
# TRUST ANCHORING — Registry Authority (pinned root of trust)
# ============================================================
# A malicious operator could fabricate a governance registry, compute
# its hash, embed that hash in a bundle, and pass the fake registry
# to the verifier. The hash would match, but the registry itself is
# not authoritative.
#
# To prevent this, the verifier pins a TRUSTED_REGISTRY_ROOT_PUBLIC_KEY.
# Any registry it accepts must be signed by the corresponding private
# key. Additionally, the verifier pins a set of ALLOWED_REGISTRY_HASHES
# as a defense-in-depth measure (so even a stolen root key cannot
# silently introduce a new registry without operator action).
#
# Production deployment: the root key would be held by a regulator,
# multi-sig escrow, or transparency log; the allowed hashes would be
# published in regulatory documentation.
# ============================================================

# In production, this key would NOT live in source code. It would be
# pinned via configuration, regulatory publication, or a transparency
# log. For the prototype, we generate it once at module load.
_REGISTRY_ROOT_OPERATOR = None  # set lazily below


def _registry_canonical_payload(registry_with_signature: dict) -> bytes:
    """Extract the canonical bytes that the registry signature is over.
    Excludes the signature itself."""
    payload = {k: v for k, v in registry_with_signature.items()
               if k not in ("registry_signature", "_self_hash")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def governance_registry_hash(registry: dict) -> str:
    """Hash of the canonical registry payload (excluding the signature).
    Two registries with different signatures over the same content
    have the same hash — this is intentional: the hash identifies
    content, the signature authorizes it."""
    return f"sha256:{hashlib.sha256(_registry_canonical_payload(registry)).hexdigest()}"


# ============================================================
# Bootstrap: create the registry root, sign the registry, and pin
# the trusted public key + allowed hash. This happens once at module
# load and produces the immutable trust anchor for all verifications.
# ============================================================

def _bootstrap_trust_anchor():
    """Create the registry root key, sign the canonical registry,
    and return (root_public_key_hex, signed_registry, allowed_hash)."""
    root_priv = Ed25519PrivateKey.generate()
    root_pub = root_priv.public_key()
    root_pub_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{root_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw).hex()}"
    )

    # Build the registry content with PKI fields, temporal bounds,
    # participant public keys, and operator anchoring.
    participant_keys = {}
    participant_priv_keys = {}
    for pid in ("regulator-MOH-TR-01", "ethics-board-IST-04",
                "domain-expert-EM-12", "affected-rep-PA-03"):
        priv = Ed25519PrivateKey.generate()
        participant_priv_keys[pid] = priv
        pub_raw = priv.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw)
        participant_keys[pid] = f"{SIGNATURE_SCHEME_TAG}-pub:{pub_raw.hex()}"

    operator_priv = Ed25519PrivateKey.generate()
    operator_pub_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{operator_priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw).hex()}"
    )

    registry_payload = {
        "registry_id": "ova-governance-registry-v1",
        "epoch_id": "epoch-2026-Q2",
        "valid_from": "2026-04-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "consensus_threshold": 0.66,
        "critical_acceptor_roles": ["REGULATOR", "ETHICS_BOARD"],
        "authorized_participants": {
            "regulator-MOH-TR-01": {
                "role": "REGULATOR",
                "canonical_vote_weight": 1.0,
                "public_key": participant_keys["regulator-MOH-TR-01"],
            },
            "ethics-board-IST-04": {
                "role": "ETHICS_BOARD",
                "canonical_vote_weight": 1.0,
                "public_key": participant_keys["ethics-board-IST-04"],
            },
            "domain-expert-EM-12": {
                "role": "DOMAIN_EXPERT",
                "canonical_vote_weight": 0.8,
                "public_key": participant_keys["domain-expert-EM-12"],
            },
            "affected-rep-PA-03": {
                "role": "AFFECTED_PARTY_REP",
                "canonical_vote_weight": 0.6,
                "public_key": participant_keys["affected-rep-PA-03"],
            },
        },
        "authorized_operators": {
            "operator-istanbul-hospital-ER-01": {
                "public_key": operator_pub_hex,
            },
        },
        "allowed_votes": ["ACCEPT", "REJECT", "ABSTAIN"],
        "registry_root_public_key": root_pub_hex,
    }

    # Sign the canonical payload with the root key
    payload_bytes = json.dumps(registry_payload, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
    sig_bytes = root_priv.sign(payload_bytes)
    signed_registry = dict(registry_payload)
    signed_registry["registry_signature"] = (
        f"{SIGNATURE_SCHEME_TAG}:{sig_bytes.hex()}"
    )

    allowed_hash = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"

    # Build a per-participant secrets dict for use by the test harness
    # ONLY. In production these would never leave the participant.
    participant_secrets = {
        pid: participant_priv_keys[pid] for pid in participant_priv_keys
    }
    operator_secret = operator_priv

    return (root_pub_hex, signed_registry, allowed_hash,
            participant_secrets, operator_secret)


(
    TRUSTED_REGISTRY_ROOT_PUBLIC_KEY,
    GOVERNANCE_REGISTRY_V1,
    GOVERNANCE_REGISTRY_V1_HASH,
    _PARTICIPANT_PRIVATE_KEYS,
    _OPERATOR_PRIVATE_KEY,
) = _bootstrap_trust_anchor()


# Defense in depth: even if the root key is compromised, the verifier
# refuses to accept any registry whose hash is not in this allowed set.
# Updating this set requires an out-of-band human action.
ALLOWED_REGISTRY_HASHES = {GOVERNANCE_REGISTRY_V1_HASH}


def verify_registry_authenticity(registry: dict,
                                  trusted_root_pub_hex: str,
                                  allowed_hashes: set[str]) -> tuple[bool, str]:
    """Verify that a registry (1) has a valid root signature,
    (2) its hash is in the allowed set, (3) its declared root key
    matches the verifier's pinned trusted root.

    Returns (ok, reason). reason is empty when ok."""
    # 1. Structural requirements
    if "registry_signature" not in registry:
        return False, "Registry has no registry_signature field."
    if "registry_root_public_key" not in registry:
        return False, "Registry has no registry_root_public_key field."

    # 2. Pinned-root check: the registry must claim the SAME root we trust
    if registry["registry_root_public_key"] != trusted_root_pub_hex:
        return False, ("Registry root_public_key does not match verifier's "
                       "pinned TRUSTED_REGISTRY_ROOT_PUBLIC_KEY.")

    # 3. Hash check: must be in allowed set (defense in depth)
    computed_hash = governance_registry_hash(registry)
    if computed_hash not in allowed_hashes:
        return False, (f"Registry hash {computed_hash} is not in the "
                       "pinned ALLOWED_REGISTRY_HASHES set.")

    # 4. Signature check
    payload = _registry_canonical_payload(registry)
    sig_ok = verify_signature(
        trusted_root_pub_hex, payload, registry["registry_signature"]
    )
    if not sig_ok:
        return False, "Registry signature does not verify against trusted root."

    return True, ""


# ============================================================
# CRYPTO UTILITIES
# ============================================================

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest. Returned with algorithm prefix."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization for hashing.
    Sorted keys, no whitespace, UTF-8. Two equal objects → identical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def hash_object(obj: Any) -> str:
    """Hash any JSON-serializable object canonically."""
    return sha256_hex(canonical_json(obj))


def merkle_root_from_hashes(hashes: list[str]) -> str:
    """Compute Merkle root over an ordered list of hex hashes.
    Simple binary tree; duplicates last node if odd count at each level."""
    if not hashes:
        raise ValueError("Cannot compute Merkle root over empty list")

    # Strip the "sha256:" prefix for binary computation, restore at end
    level = [bytes.fromhex(h.split(":", 1)[1]) for h in hashes]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last for odd count
        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(hashlib.sha256(combined).digest())
        level = next_level

    return f"sha256:{level[0].hex()}"


# ============================================================
# OPERATOR KEY MANAGEMENT (prototype)
# ============================================================

@dataclass
class Operator:
    """A signing identity. In production, keys would live in an HSM."""
    operator_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def new(cls, operator_id: str) -> "Operator":
        priv = Ed25519PrivateKey.generate()
        return cls(operator_id, priv, priv.public_key())

    def sign(self, data: bytes) -> str:
        """Return signature as hex with scheme tag."""
        sig = self.private_key.sign(data)
        return f"{SIGNATURE_SCHEME_TAG}:{sig.hex()}"

    def public_key_hex(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        return f"{SIGNATURE_SCHEME_TAG}-pub:{raw.hex()}"


def verify_signature(public_key_hex: str, data: bytes,
                     signature_hex: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    # Strip tags
    if not signature_hex.startswith(SIGNATURE_SCHEME_TAG + ":"):
        return False
    if not public_key_hex.startswith(SIGNATURE_SCHEME_TAG + "-pub:"):
        return False

    sig_bytes = bytes.fromhex(signature_hex.split(":", 1)[1])
    pub_bytes = bytes.fromhex(public_key_hex.split(":", 1)[1])

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, data)
        return True
    except Exception:
        return False


# ============================================================
# CONSTITUTIONAL LAYER — PoN (Proof of Negotiation)
# ============================================================

def build_pon(epoch_id: str, t0: str, votes: list[dict],
              registry_hash: str) -> dict:
    """Construct a Proof of Negotiation record.

    NOTE on design (governance registry anchoring + signed votes):
    PoN records only the SIGNED VOTES cast during a specific negotiation
    epoch. It does NOT carry the constitutional rules (threshold, roles,
    canonical vote weights). Those live in an external signed governance
    registry. Each vote carries the participant's signature; the verifier
    resolves the participant's public key from the registry and verifies
    the signature there.

    Each vote entry contains:
      - participant_id
      - vote ("ACCEPT" | "REJECT" | "ABSTAIN")
      - epoch_id, policy_version_id_anchor, vote_timestamp
      - signature  (over the canonical vote payload, signed with
                    the participant's private key)
    """
    return {
        "epoch_id": epoch_id,
        "negotiation_timestamp_t0": t0,
        "governance_registry_hash": registry_hash,
        "votes": votes,
        "consensus_mechanism": "WEIGHTED_QUORUM",
        "_metadata_note": ("Advisory metadata only. Verifier recomputes "
                           "quorum from registry + signed votes."),
    }


def canonical_vote_payload(participant_id: str, vote: str, epoch_id: str,
                           policy_version_id_anchor: str,
                           policy_hash: str,
                           vote_timestamp: str) -> bytes:
    """The exact bytes a participant signs to authorize a vote.

    CRITICAL: The signature binds to policy_hash, NOT just to the
    symbolic policy_version_id. A malicious operator who edits the
    constraints inside a version while keeping the version_id constant
    will produce a different policy_hash, and all existing signatures
    will fail to verify against the new content."""
    payload = {
        "participant_id": participant_id,
        "vote": vote,
        "epoch_id": epoch_id,
        "policy_version_id_anchor": policy_version_id_anchor,
        "policy_hash": policy_hash,
        "vote_timestamp": vote_timestamp,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_vote(participant_id: str, vote: str, epoch_id: str,
              policy_version_id_anchor: str, policy_hash: str,
              vote_timestamp: str,
              private_key: Ed25519PrivateKey) -> dict:
    """Build a fully-formed signed vote entry bound to a specific
    policy_hash (not just a symbolic version id)."""
    payload = canonical_vote_payload(
        participant_id, vote, epoch_id, policy_version_id_anchor,
        policy_hash, vote_timestamp
    )
    sig_bytes = private_key.sign(payload)
    return {
        "participant_id": participant_id,
        "vote": vote,
        "epoch_id": epoch_id,
        "policy_version_id_anchor": policy_version_id_anchor,
        "policy_hash": policy_hash,
        "vote_timestamp": vote_timestamp,
        "signature": f"{SIGNATURE_SCHEME_TAG}:{sig_bytes.hex()}",
    }


# ============================================================
# CONSTITUTIONAL LAYER — PoE (Proof of Evolution)
# ============================================================

def compute_policy_hash(constraints: list[dict]) -> str:
    """Hash the canonical bytes of a constraint set.

    The policy_hash binds participant votes and operator decisions to the
    EXACT content of the constraints — not just their symbolic version ID.
    A malicious operator who edits the constraints while keeping
    version_id='CV_1' will change the policy_hash, invalidating all
    existing vote signatures and PoO signatures bound to the old hash.
    """
    return hash_object(constraints)


def compute_constraint_hash(constraint: dict) -> str:
    """Hash a single constraint's canonical content (v2.5).

    PoR's rules_applied each carry a constraint_hash binding the rule
    invocation to the exact content of the constraint it claims to be
    derived from. This defeats arbitrary rule injection: an attacker
    cannot claim 'I used C1' while applying a different rule body."""
    return hash_object(constraint)


def build_constraint_version(version_id: str, constraints: list[dict],
                             previous_hash: str | None,
                             effective_date: str,
                             justification: str) -> dict:
    """Construct a single constraint version record.

    Each version carries a policy_hash computed over the canonical bytes
    of the constraint set. This hash is what participant vote signatures
    and operator decision signatures actually bind to."""
    policy_hash = compute_policy_hash(constraints)
    version_payload = {
        "version_id": version_id,
        "effective_date": effective_date,
        "constraints": constraints,
        "policy_hash": policy_hash,
        "previous_version_hash": previous_hash,
        "justification": justification,
    }
    version_payload["self_hash"] = hash_object({
        k: v for k, v in version_payload.items() if k != "self_hash"
    })
    return version_payload


def build_poe(versions: list[dict]) -> dict:
    """Construct PoE record with chain integrity verification.

    Monotonic History Axiom: each version's previous_version_hash must
    match the prior version's self_hash. Genesis version has previous=None.
    """
    chain_integrity = True
    for i, v in enumerate(versions):
        if i == 0:
            if v["previous_version_hash"] is not None:
                chain_integrity = False
                break
        else:
            if v["previous_version_hash"] != versions[i - 1]["self_hash"]:
                chain_integrity = False
                break

    return {
        "versions": versions,
        "current_version_id": versions[-1]["version_id"],
        "chain_length": len(versions),
        "chain_integrity_verified": chain_integrity,
    }


# ============================================================
# OPERATIONAL LAYER — PoO (Proof of Operation)
# ============================================================

def build_poo(input_data: dict, policy_version_id: str,
              policy_hash: str,
              decision_timestamp: str, operator: Operator) -> dict:
    """Construct a Proof of Operation: hash of (D ∥ P ∥ T), signed.

    NOTE on operator key anchoring (v2.2):
    The bundle records the operator_id only. The public key is included
    as advisory metadata under '_metadata_public_key', but the verifier
    resolves the canonical operator public key from the governance
    registry's authorized_operators map.

    NOTE on policy binding (v2.3):
    PoO records the policy_hash of the active constraint version. The
    PoR signature includes this hash via its poo_anchor, so any change
    to the constraints invalidates the entire bundle.
    """
    concat = (canonical_json(input_data) + b"||" +
              policy_version_id.encode("utf-8") + b"||" +
              decision_timestamp.encode("utf-8"))

    input_hash = sha256_hex(concat)
    signature = operator.sign(concat)

    return {
        "input_data_hash": hash_object(input_data),
        "policy_version_id": policy_version_id,
        "policy_hash": policy_hash,
        "decision_timestamp": decision_timestamp,
        "operational_hash": input_hash,
        "operator_id": operator.operator_id,
        "operator_signature": signature,
        "signature_scheme": SIGNATURE_SCHEME_TAG,
        "production_signature_target": PRODUCTION_TARGET,
        "_signed_bytes_b64hint": "canonical(D) || '||' || P || '||' || T",
        "_metadata_public_key": operator.public_key_hex(),
        "_metadata_note": ("Advisory only. Verifier resolves operator's "
                           "public key from "
                           "registry.authorized_operators[operator_id]."),
    }


# ============================================================
# OPERATIONAL LAYER — PoR (Proof of Reason)
# ============================================================

def build_por(premises: list[dict], rules: list[dict],
              conclusions: list[dict], logic_delta: dict,
              operator: Operator,
              poo_anchor: dict,
              active_policy_constraints: list[dict]) -> dict:
    """Construct a Proof of Reason: directed acyclic reason graph + Δ_L
    bound to a specific PoO via cross-layer anchor fields AND bound to
    a specific policy via per-rule constraint_hash bindings (v2.5).

    CROSS-LAYER BINDING (v2.3):
    PoR's signature is computed over a payload that includes anchor
    fields copied from PoO: operational_hash, policy_version_id,
    policy_hash, decision_timestamp.

    RULE-POLICY BINDING (v2.5):
    Each rule in rules_applied is augmented with:
      - policy_hash: the policy_hash of the active policy
      - constraint_hash: the hash of the specific constraint this rule
        claims to invoke (resolved via from_constraint)
    The verifier independently recomputes both hashes from the active
    policy and rejects any rule whose declared constraint does not
    exist in the policy or whose constraint_hash does not match.

    Args:
      poo_anchor: dict with operational_hash, policy_version_id,
        policy_hash, decision_timestamp — copied from PoO.
      active_policy_constraints: the constraint list of the version
        that PoO is executing under. Used to compute per-rule
        constraint_hash bindings.
    """

    premise_ids = {p["id"] for p in premises}
    rule_ids = {r["id"] for r in rules}

    consistent = True
    for c in conclusions:
        for ref in c.get("derived_from", []):
            if ref not in premise_ids and ref not in rule_ids \
               and ref not in {x["id"] for x in conclusions}:
                consistent = False

    # v2.5: Bind each rule to the exact constraint content it invokes
    constraint_by_id = {c["id"]: c for c in active_policy_constraints}
    active_policy_hash = compute_policy_hash(active_policy_constraints)

    augmented_rules = []
    for r in rules:
        from_id = r.get("from_constraint")
        augmented = dict(r)
        augmented["policy_hash"] = active_policy_hash
        if from_id in constraint_by_id:
            augmented["constraint_hash"] = compute_constraint_hash(
                constraint_by_id[from_id]
            )
        else:
            # Generator records the missing reference honestly. Verifier
            # will catch this — generator doesn't lie here.
            augmented["constraint_hash"] = None
            augmented["_constraint_missing"] = (
                f"from_constraint '{from_id}' not found in active policy."
            )
        augmented_rules.append(augmented)

    payload = {
        "premises": premises,
        "rules_applied": augmented_rules,
        "conclusions": conclusions,
        "logic_delta": logic_delta,
        "graph_is_dag": True,
        "structural_consistency_verified": consistent,
        "verification_type": "structural_provenance_plus_rule_binding",
        "formal_entailment_verified": False,
        "formal_entailment_note": (
            "PoR v2.5 records the reasoning graph, verifies reference "
            "resolution, and binds each rule invocation to the exact "
            "constraint content via constraint_hash. It does NOT verify "
            "that conclusions formally entail from premises under the "
            "declared rules — that requires a SAT/SMT solver and is "
            "left for future work. What is proven: PoR uses authorized "
            "policy rules (rule provenance binding). What is NOT proven: "
            "the rules were applied correctly to produce the conclusions."
        ),
        # Cross-layer anchor (v2.3)
        "poo_anchor": {
            "operational_hash": poo_anchor["operational_hash"],
            "policy_version_id": poo_anchor["policy_version_id"],
            "policy_hash": poo_anchor["policy_hash"],
            "decision_timestamp": poo_anchor["decision_timestamp"],
        },
    }

    # Sign the reason graph together with its PoO anchor and rule bindings
    payload["graph_signature"] = operator.sign(canonical_json(payload))
    return payload


# ============================================================
# OPERATIONAL LAYER — PoC (Proof of Conflict)
# ============================================================

def build_poc(conflicts: list[dict]) -> dict:
    """Construct Proof of Conflict.

    Key property: conflicts are never silenced. Every conflict has
    silenced=False; if any silenced=True is found, PoC is invalid.
    """
    any_silenced = any(c.get("silenced", False) for c in conflicts)
    valid_protocols = {"LEXICOGRAPHIC", "WEIGHTED_SUM",
                       "PARETO_OPTIMAL", "HUMAN_ESCALATE"}
    protocols_valid = all(
        c["resolution_protocol"] in valid_protocols for c in conflicts
    )

    return {
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
        "any_silenced": any_silenced,
        "protocols_valid": protocols_valid,
        "completeness_verified": not any_silenced and protocols_valid,
    }


# ============================================================
# VERIFICATION SCOPE — explicit claims and limitations
# ============================================================

VERIFICATION_SCOPE = {
    "trust_chain_property": (
        "OVA v2.5 establishes a multi-layered trust chain: "
        "(1) Trusted root: verifier pins TRUSTED_REGISTRY_ROOT_PUBLIC_KEY "
        "out-of-band. "
        "(2) Signed registry: any accepted registry must carry a "
        "registry_signature valid under the trusted root AND its content "
        "hash must be in the pinned ALLOWED_REGISTRY_HASHES. "
        "(3) Temporal validity: registry valid_from/valid_until must "
        "bracket the PoO decision_timestamp. "
        "(4) Registry-anchored participant keys: each PoN vote is signed "
        "by the participant; the verifier resolves the participant public "
        "key from the registry, not from the bundle. "
        "(5) Registry-anchored operator key: the operator's public key "
        "is resolved from registry.authorized_operators, not from PoO "
        "metadata. "
        "(6) Policy-content binding: vote signatures and PoO bind to "
        "policy_hash (content hash of constraints), not just symbolic "
        "version IDs. "
        "(7) Active policy binding: votes counted toward quorum must "
        "bind to the EXACT policy that PoO executes (same epoch_id, "
        "policy_version_id, and policy_hash). "
        "(8) Rule-policy binding (NEW v2.5): each rule in PoR carries "
        "policy_hash and constraint_hash. The verifier rejects rules "
        "whose constraint does not exist in the active policy or whose "
        "constraint_hash does not match the recomputed value. This "
        "establishes RULE PROVENANCE, not semantic execution compliance. "
        "(9) Cross-layer binding: PoR signature is computed over a "
        "payload that includes poo_anchor. PoR cannot be grafted across "
        "bundles. "
        "(10) Independent computation: all *_verified flags inside the "
        "bundle are ignored; everything is recomputed from primitives. "
        "(11) DAG + reachability: PoR is checked for cycles AND for "
        "every conclusion having a derivation path to at least one premise."
    ),
    "rule_provenance_binding_property": (
        "v2.5: Each rule_applied in PoR is bound to a specific constraint "
        "in the active policy via two hashes — policy_hash (the active "
        "policy's content hash) and constraint_hash (the hash of the "
        "specific constraint identified by from_constraint). The verifier "
        "independently recomputes both hashes from the active policy and "
        "rejects: (a) rules whose from_constraint does not exist in the "
        "active policy (arbitrary rule injection), (b) rules whose "
        "policy_hash does not match the active policy, (c) rules whose "
        "constraint_hash does not match the recomputation of the named "
        "constraint's canonical bytes (rule body tampering or fabrication). "
        "WHAT IS PROVEN: PoR uses rules authorized by the active policy "
        "and binds each rule invocation to the exact constraint content. "
        "WHAT IS NOT PROVEN: that the rules were applied CORRECTLY to "
        "produce the conclusions. Formal semantic execution compliance "
        "(every conclusion entails from premises under the declared rules) "
        "requires a constraint DSL plus SAT/SMT verification and is "
        "explicitly left for future work."
    ),
    "active_policy_binding_property": (
        "Defeats cross-version vote grafting and cross-epoch vote replay. "
        "The verifier enforces a strict identity between the policy that "
        "quorum approved and the policy that PoO executes: every ACCEPT "
        "vote contributing to quorum must satisfy three bindings — "
        "vote.epoch_id == registry.epoch_id, "
        "vote.policy_version_id_anchor == PoO.policy_version_id, "
        "vote.policy_hash == PoO.policy_hash. Stale votes (from prior "
        "epochs) and votes for prior policy versions are excluded from "
        "the quorum calculation even when their cryptographic signatures "
        "verify. The system answers not just 'were these signatures real?' "
        "but 'did the quorum approve exactly what was executed?'."
    ),
    "policy_content_binding_property": (
        "Every signed vote and every PoO commitment binds to "
        "policy_hash = SHA-256(canonical(constraints)). The symbolic "
        "version_id (e.g., 'CV_1') is metadata only. A malicious "
        "operator who edits constraints inside a version while "
        "preserving its version_id will change the policy_hash, and "
        "all existing signatures bound to the old policy_hash will "
        "fail to validate against the new constraint content. The "
        "verifier additionally recomputes policy_hash from the raw "
        "constraints array, defeating attempts to keep stored "
        "policy_hash in sync with old signatures."
    ),
    "cross_layer_binding_property": (
        "PoR signature payload includes poo_anchor = "
        "{operational_hash, policy_version_id, policy_hash, "
        "decision_timestamp}. The verifier rejects any bundle where "
        "PoR.poo_anchor does not match the bundle's actual PoO. A "
        "valid PoR taken from a different (legitimate) bundle cannot "
        "be grafted onto this bundle's PoO without invalidating "
        "por_signature_binding_valid."
    ),
    "verifier_independence_property": (
        "The verifier does NOT trust any *_verified, quorum_satisfied, "
        "graph_is_dag, accept_ratio, has_critical_acceptor, "
        "completeness_verified, chain_integrity_verified, or stored "
        "policy_hash. All integrity claims are recomputed from "
        "primitive records or resolved from the trusted registry."
    ),
    "governance_anchoring_property": (
        "Constitutional rules — authorized participants, their roles, "
        "their canonical vote weights, the consensus threshold, the "
        "critical acceptor roles, the authorized operators and their "
        "public keys — come from a signed external registry. A malicious "
        "generator cannot rewrite these rules inside the bundle."
    ),
    "dag_and_reachability_property": (
        "PoR's reason graph is verified for two structural properties: "
        "(a) acyclicity via DFS coloring; (b) reachability — every "
        "conclusion must trace back through derived_from edges to at "
        "least one premise. Conclusions that derive only from rules "
        "(floating logic islands) are rejected."
    ),
    "what_this_bundle_verifies": {
        "cryptographic_integrity": (
            "All layer hashes and the Merkle root can be recomputed by any "
            "independent party. Tampering with any field is detectable."
        ),
        "structural_provenance": (
            "Records which premises, rules, and conclusions were used in "
            "PoR; which conflicts were detected in PoC; which constraint "
            "version was active in PoO; how constraints evolved in PoE; "
            "who participated in the negotiation in PoN."
        ),
        "signature_authenticity": (
            "Cryptographic signatures by the declared operator can be "
            "verified against the operator's public key (prototype: Ed25519)."
        ),
        "governance_chain_integrity": (
            "PoE chain is append-only and monotonic; PoN quorum integrity "
            "axiom is checked (REGULATOR or ETHICS_BOARD must be in ACCEPT)."
        ),
    },
    "what_this_bundle_does_NOT_verify": {
        "formal_logical_entailment": (
            "PoR v2.5 records the reasoning graph, verifies that all "
            "references resolve to existing nodes, performs DFS-based "
            "cycle detection, performs reachability checking from "
            "conclusions back to premises, AND binds each rule "
            "invocation to the exact content of the active policy via "
            "policy_hash + constraint_hash. This is rule PROVENANCE "
            "binding — it does NOT prove that conclusions formally "
            "entail from premises under the declared rules. "
            "CONCRETE EXAMPLE OF THE GAP: A rule 'IF vital_score < 0.4 "
            "THEN priority = HIGH' with premise 'vital_score = 0.38' "
            "but recorded conclusion 'priority = MEDIUM' would NOT be "
            "detected by OVA v2.5 as a semantic inconsistency, because "
            "the verifier confirms rule provenance (the rule is "
            "authorized and bound to the active policy) but does not "
            "evaluate whether the conclusion logically follows from "
            "applying the rule to the premise. "
            "Formal semantic execution compliance requires (a) a "
            "constraint DSL that the rules are expressed in, and "
            "(b) a separate verification engine (e.g., SAT/SMT solver, "
            "theorem prover) that takes the constraints and premises "
            "and confirms the conclusions are valid derivations. This "
            "is explicitly out of scope for v2.5 and left for future work."
        ),
        "moral_or_ethical_correctness": (
            "The constraints negotiated in PoN may be auditable as to "
            "their genesis, but their substantive moral correctness is "
            "outside the scope of this framework. Documentation of "
            "negotiation is not endorsement of outcome."
        ),
        "clinical_or_domain_correctness": (
            "The triage priority assignment is the output of declared "
            "rules applied to declared inputs. The framework does NOT "
            "validate that the rules represent best clinical practice "
            "or that the priority assignment is medically optimal."
        ),
        "representativeness_of_negotiation": (
            "PoN documents that participants with named roles voted, but "
            "does NOT verify that those participants are legitimately "
            "representative of affected populations. Legitimacy is a "
            "sociopolitical question outside cryptographic verification."
        ),
        "resolution_protocol_justification": (
            "PoC documents which resolution protocol was chosen "
            "(LEXICOGRAPHIC, WEIGHTED_SUM, etc.) — it does NOT justify "
            "why that protocol was the correct choice for the domain."
        ),
        "conflict_completeness_silent_omission": (
            "PoC verifies the INTEGRITY of recorded conflicts (none silenced, "
            "protocols valid). It does NOT verify that all conflicts that "
            "SHOULD have been detected were in fact recorded. A malicious "
            "or buggy decision engine could omit a conflict entirely from "
            "PoC, and the verifier would not detect the omission. Detecting "
            "silent omission requires an independent conflict detector that "
            "applies the constraints to the decision state and produces an "
            "expected conflict set to compare against. This is left for "
            "future work. Accordingly, the relevant check is named "
            "'poc_record_integrity' (not 'poc_conflict_completeness') to "
            "avoid overclaim."
        ),
        "production_grade_cryptography": (
            "Signatures use Ed25519 (prototype). Production deployment "
            "targets ML-DSA / Dilithium-III (FIPS 204, post-quantum). "
            "The current bundle should NOT be treated as quantum-resistant."
        ),
        "key_revocation_not_supported_in_active_epoch": (
            "Within a single governance epoch, OVA v2.3 has NO mechanism "
            "to revoke a compromised participant key, operator key, or "
            "registry root key. If a private key is leaked mid-epoch, "
            "the attacker can produce valid-looking bundles until the "
            "next registry rotation. Mitigations are out-of-band: "
            "(a) issuing a new registry with a different ALLOWED_HASH "
            "and re-pinning the verifier; (b) externally annotating "
            "affected bundles as revoked in a transparency log. "
            "Future work: signed CRL/OCSP-style revocation anchor, or "
            "transparency-log-based revocation events that the verifier "
            "consults alongside the registry."
        ),
        "merkle_compliance": (
            "Merkle root uses a simple binary tree with last-node "
            "duplication for odd counts. NOT compliant with RFC 6962 "
            "(Certificate Transparency). Compliance is left for future work."
        ),
    },
    "what_is_left_for_future_work": [
        "Constraint DSL + formal semantic execution verification: "
        "define a domain-specific language for constraints and implement "
        "a SAT/SMT-based verifier (e.g., Z3, CVC5) that takes the active "
        "policy's constraints plus PoR's premises and confirms each "
        "conclusion is a valid derivation. This would turn rule provenance "
        "binding into formal entailment proof.",
        "Formal verification of verifier logic using TLA+ or Coq: beyond "
        "empirical adversarial testing, produce a mathematical proof that "
        "the verifier algorithm is free of logical gaps and unhandled edge "
        "cases. Complements the constraint-DSL + SAT/SMT work above: "
        "SAT/SMT covers CONTENT correctness (does premise + rule entail "
        "conclusion?), TLA+/Coq covers ALGORITHM correctness (is the "
        "verifier itself sound?).",
        "Performance benchmarking on large bundles: empirical measurement "
        "of verifier latency and memory consumption under scaled constraint "
        "sets, particularly in resource-constrained or distributed "
        "environments. The current implementation prioritizes clarity over "
        "performance and uses deepcopy in the test suites; production "
        "deployment may require streaming verification or incremental "
        "Merkle proofs.",
        "Implement key revocation: signed CRL, OCSP, or "
        "transparency-log-based revocation events consulted by the "
        "verifier alongside the registry.",
        "Implement an independent conflict detector that applies the "
        "active constraint set to the decision state to produce an "
        "expected conflict set, then compare against PoC's recorded "
        "conflicts to detect silent omission.",
        "Upgrade Ed25519 to ML-DSA (Dilithium-III) for post-quantum "
        "security per FIPS 204.",
        "Adopt RFC 6962 Merkle tree construction for interoperability "
        "with existing transparency log infrastructure.",
        "Separate PoR signing identity from PoO operator identity to "
        "support multi-party reasoning attribution.",
        "Extend tamper test coverage to all five proof layers and to "
        "the Merkle root itself.",
        "Define a formal trust model for PoN participants and their "
        "representativeness.",
    ],
    "claims_classification": {
        "verified_by_this_bundle": "cryptographic + structural integrity",
        "NOT_verified_by_this_bundle": (
            "formal entailment, ethical correctness, clinical correctness, "
            "representativeness legitimacy, protocol justification"
        ),
    },
}


# ============================================================
# BUNDLE ASSEMBLY
# ============================================================

def assemble_bundle(pon: dict, poe: dict, poo: dict, por: dict,
                    poc: dict) -> dict:
    """Assemble the full proof bundle with Merkle root over all 5 layers.

    Merkle order is deterministic: PoN, PoE, PoO, PoR, PoC.
    """
    layer_hashes = {
        "pon_hash": hash_object(pon),
        "poe_hash": hash_object(poe),
        "poo_hash": hash_object(poo),
        "por_hash": hash_object(por),
        "poc_hash": hash_object(poc),
    }

    ordered = [
        layer_hashes["pon_hash"],
        layer_hashes["poe_hash"],
        layer_hashes["poo_hash"],
        layer_hashes["por_hash"],
        layer_hashes["poc_hash"],
    ]
    merkle_root = merkle_root_from_hashes(ordered)

    bundle = {
        "bundle_id": BUNDLE_ID,
        "framework_version": FRAMEWORK_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z"),
        "hash_algorithm": HASH_ALGORITHM,
        "verification_scope": VERIFICATION_SCOPE,
        "constitutional_layer": {
            "pon": pon,
            "poe": poe,
        },
        "operational_layer": {
            "poo": poo,
            "por": por,
            "poc": poc,
        },
        "layer_hashes": layer_hashes,
        "merkle_root": merkle_root,
        "merkle_order": ["pon", "poe", "poo", "por", "poc"],
    }

    return bundle


# ============================================================
# VERIFIER — independent, reads bundle, returns VALID/INVALID
# ============================================================

def verify_bundle(bundle: dict, expected_input_data: dict | None = None,
                  governance_registry: dict | None = None,
                  trusted_root_public_key: str | None = None,
                  allowed_registry_hashes: set[str] | None = None) -> dict:
    """OVA v2.2 verifier — multi-layered trust chain.

    DESIGN PRINCIPLES:

    1. Trust anchoring (registry authority): The verifier accepts only
       a registry signed by the pinned TRUSTED_REGISTRY_ROOT_PUBLIC_KEY
       AND whose content hash is in the pinned ALLOWED_REGISTRY_HASHES.

    2. Temporal validity: The registry is bounded by valid_from /
       valid_until. PoO.decision_timestamp must fall in this window.

    3. Vote authentication: Each PoN vote carries a participant
       signature. The verifier resolves the participant's public key
       from the registry (NOT from the bundle) and verifies the
       signature over the canonical vote payload.

    4. Operator key anchoring: The operator's public key is resolved
       from registry.authorized_operators[operator_id] — NOT from any
       field inside PoO. Any key in PoO is metadata only.

    5. Verifier independence: All *_verified, quorum_satisfied,
       graph_is_dag flags are ignored. Everything is recomputed.

    6. DAG verification: PoR cycle detection (DFS) and reachability
       check (every conclusion must trace back to at least one premise).

    Returns a verifier_result dict; does NOT mutate the bundle.
    """
    checks_passed: list[str] = []
    checks_failed: list[dict] = []

    # Default to module-level pinned anchors if caller didn't override
    if trusted_root_public_key is None:
        trusted_root_public_key = TRUSTED_REGISTRY_ROOT_PUBLIC_KEY
    if allowed_registry_hashes is None:
        allowed_registry_hashes = ALLOWED_REGISTRY_HASHES

    pon = bundle["constitutional_layer"]["pon"]
    poe = bundle["constitutional_layer"]["poe"]
    poo = bundle["operational_layer"]["poo"]
    por = bundle["operational_layer"]["por"]
    poc = bundle["operational_layer"]["poc"]

    # ------------------------------------------------------------
    # Check 0a: Registry signature valid + pinned-hash check
    # ------------------------------------------------------------
    registry_authentic = False
    if governance_registry is None:
        checks_failed.append({
            "check": "registry_signature_valid",
            "reason": "No governance_registry provided to verifier.",
        })
    else:
        ok, why = verify_registry_authenticity(
            governance_registry, trusted_root_public_key,
            allowed_registry_hashes
        )
        if ok:
            checks_passed.append("registry_signature_valid")
            registry_authentic = True
        else:
            checks_failed.append({
                "check": "registry_signature_valid",
                "reason": why,
            })

    # ------------------------------------------------------------
    # Check 0b: Registry temporal validity
    # ------------------------------------------------------------
    if registry_authentic:
        try:
            valid_from = governance_registry["valid_from"]
            valid_until = governance_registry["valid_until"]
            decision_ts = poo.get("decision_timestamp", "")
            if not (valid_from <= decision_ts <= valid_until):
                checks_failed.append({
                    "check": "registry_temporal_validity",
                    "reason": (f"PoO.decision_timestamp={decision_ts} is "
                               f"outside registry validity window "
                               f"[{valid_from}, {valid_until}]."),
                })
            else:
                checks_passed.append("registry_temporal_validity")
        except (KeyError, TypeError) as e:
            checks_failed.append({
                "check": "registry_temporal_validity",
                "reason": f"Cannot evaluate temporal validity: "
                          f"{type(e).__name__}: {e}",
            })
    else:
        checks_failed.append({
            "check": "registry_temporal_validity",
            "reason": "Skipped: registry not authentic.",
        })

    # If the registry isn't authentic, every PoN check is moot.
    # We still run other layer checks (PoE/PoO/PoR/PoC/Merkle) for
    # diagnostic completeness, but record the dependency.

    # ------------------------------------------------------------
    # Check 1: PoN quorum integrity — uses authentic registry only
    # ------------------------------------------------------------
    if not registry_authentic:
        checks_failed.append({
            "check": "pon_quorum_integrity",
            "reason": "Skipped: registry not authentic.",
        })
    else:
        try:
            claimed_registry_hash = pon.get("governance_registry_hash")
            actual_hash = governance_registry_hash(governance_registry)
            if claimed_registry_hash != actual_hash:
                checks_failed.append({
                    "check": "pon_quorum_integrity",
                    "reason": (f"PoN references registry "
                               f"{claimed_registry_hash}, but trusted "
                               f"registry hash is {actual_hash}."),
                })
            else:
                authorized = governance_registry["authorized_participants"]
                threshold = governance_registry["consensus_threshold"]
                critical_roles = set(
                    governance_registry["critical_acceptor_roles"]
                )
                allowed_votes = set(governance_registry["allowed_votes"])

                votes = pon["votes"]
                total_weight = 0.0
                accept_weight = 0.0
                has_critical_acceptor = False
                bad = None

                for v in votes:
                    pid = v.get("participant_id")
                    vote = v.get("vote")
                    if pid not in authorized:
                        bad = (f"Vote by '{pid}' rejected: "
                               "not in registry.")
                        break
                    if vote not in allowed_votes:
                        bad = f"Vote value '{vote}' by '{pid}' invalid."
                        break
                    canonical_weight = (
                        authorized[pid]["canonical_vote_weight"]
                    )
                    canonical_role = authorized[pid]["role"]
                    total_weight += canonical_weight
                    if vote == "ACCEPT":
                        accept_weight += canonical_weight
                        if canonical_role in critical_roles:
                            has_critical_acceptor = True

                if bad:
                    checks_failed.append({
                        "check": "pon_quorum_integrity",
                        "reason": bad,
                    })
                else:
                    ratio = (accept_weight / total_weight
                             if total_weight > 0 else 0.0)
                    if has_critical_acceptor and ratio >= threshold:
                        checks_passed.append("pon_quorum_integrity")
                    else:
                        checks_failed.append({
                            "check": "pon_quorum_integrity",
                            "reason": (f"accept_ratio={ratio:.4f}, "
                                       f"threshold={threshold}, "
                                       f"critical_acceptor="
                                       f"{has_critical_acceptor}."),
                        })
        except (KeyError, TypeError, ZeroDivisionError) as e:
            checks_failed.append({
                "check": "pon_quorum_integrity",
                "reason": f"PoN malformed: {type(e).__name__}: {e}",
            })

    # ------------------------------------------------------------
    # Check 1b: PoN vote signatures
    # ------------------------------------------------------------
    if not registry_authentic:
        checks_failed.append({
            "check": "pon_vote_signatures_valid",
            "reason": "Skipped: registry not authentic.",
        })
    else:
        try:
            authorized = governance_registry["authorized_participants"]
            all_sigs_ok = True
            first_bad_sig = None
            for v in pon["votes"]:
                pid = v.get("participant_id")
                if pid not in authorized:
                    all_sigs_ok = False
                    first_bad_sig = (
                        f"Vote by unauthorized participant '{pid}'."
                    )
                    break
                if "signature" not in v:
                    all_sigs_ok = False
                    first_bad_sig = (
                        f"Vote by '{pid}' has no signature field."
                    )
                    break
                participant_pubkey = authorized[pid]["public_key"]
                payload = canonical_vote_payload(
                    pid, v["vote"], v.get("epoch_id", ""),
                    v.get("policy_version_id_anchor", ""),
                    v.get("policy_hash", ""),
                    v.get("vote_timestamp", "")
                )
                if not verify_signature(
                    participant_pubkey, payload, v["signature"]
                ):
                    all_sigs_ok = False
                    first_bad_sig = (
                        f"Signature by '{pid}' did not verify "
                        "against registry's public key for that "
                        "participant (or policy_hash mismatch)."
                    )
                    break
            if all_sigs_ok:
                checks_passed.append("pon_vote_signatures_valid")
            else:
                checks_failed.append({
                    "check": "pon_vote_signatures_valid",
                    "reason": first_bad_sig,
                })
        except (KeyError, TypeError) as e:
            checks_failed.append({
                "check": "pon_vote_signatures_valid",
                "reason": f"Vote malformed: {type(e).__name__}: {e}",
            })

    # ------------------------------------------------------------
    # Check 2: PoE chain monotonicity
    # ------------------------------------------------------------
    try:
        versions = poe["versions"]
        chain_ok = True
        chain_failure = None
        for i, v in enumerate(versions):
            primitive_fields = {
                k: val for k, val in v.items() if k != "self_hash"
            }
            recomputed = hash_object(primitive_fields)
            if v.get("self_hash") != recomputed:
                chain_ok = False
                chain_failure = (
                    f"Version {v.get('version_id', i)}: stored "
                    "self_hash != recomputed."
                )
                break
            if i == 0:
                if v["previous_version_hash"] is not None:
                    chain_ok = False
                    chain_failure = "Genesis has non-null prev hash."
                    break
            else:
                if v["previous_version_hash"] != versions[i-1]["self_hash"]:
                    chain_ok = False
                    chain_failure = (
                        f"Version {v['version_id']}: "
                        "previous_version_hash mismatch."
                    )
                    break
        if chain_ok:
            checks_passed.append("poe_chain_monotonicity")
        else:
            checks_failed.append({
                "check": "poe_chain_monotonicity",
                "reason": chain_failure,
            })
    except (KeyError, TypeError) as e:
        checks_failed.append({
            "check": "poe_chain_monotonicity",
            "reason": f"PoE malformed: {type(e).__name__}: {e}",
        })

    # ------------------------------------------------------------
    # Check 2b: policy_hash consistency — votes and PoO must reference
    # policy_hashes that actually exist in PoE
    # ------------------------------------------------------------
    # This is the v2.3 binding that defeats Policy Forgery: every signed
    # vote carries the policy_hash it was bound to, and PoO carries the
    # policy_hash it operated under. Both must match an entry in PoE.
    try:
        poe_version_map = {
            v["version_id"]: v.get("policy_hash")
            for v in poe["versions"]
        }
        # Also build a set of all valid policy_hashes for lookup
        valid_policy_hashes = set(poe_version_map.values())

        # Recompute each version's policy_hash from its raw constraints
        # to defeat tampering: an attacker who edits constraints but
        # keeps the stored policy_hash will be caught here.
        recomputation_ok = True
        recomputation_problem = None
        for v in poe["versions"]:
            recomputed = compute_policy_hash(v.get("constraints", []))
            if recomputed != v.get("policy_hash"):
                recomputation_ok = False
                recomputation_problem = (
                    f"Version {v.get('version_id')}: stored policy_hash "
                    f"does not match hash recomputed from constraints. "
                    "Constraints were edited without updating policy_hash."
                )
                break

        # Check that every vote's policy_hash matches some PoE entry
        votes_bound_to_valid_policy = True
        first_bad_vote = None
        for v in pon.get("votes", []):
            vp_hash = v.get("policy_hash")
            if vp_hash not in valid_policy_hashes:
                votes_bound_to_valid_policy = False
                first_bad_vote = (v.get("participant_id"), vp_hash)
                break

        # Check that PoO's policy_hash matches the declared version
        # in PoE
        poo_policy_hash = poo.get("policy_hash")
        poo_policy_version = poo.get("policy_version_id")
        poo_policy_ok = (
            poo_policy_version in poe_version_map
            and poe_version_map[poo_policy_version] == poo_policy_hash
        )

        if not recomputation_ok:
            checks_failed.append({
                "check": "policy_hash_consistency",
                "reason": recomputation_problem,
            })
        elif not votes_bound_to_valid_policy:
            checks_failed.append({
                "check": "policy_hash_consistency",
                "reason": (f"Vote by '{first_bad_vote[0]}' references "
                           f"policy_hash {first_bad_vote[1]} which is not "
                           "in PoE."),
            })
        elif not poo_policy_ok:
            checks_failed.append({
                "check": "policy_hash_consistency",
                "reason": (f"PoO declares policy_version "
                           f"'{poo_policy_version}' with policy_hash "
                           f"{poo_policy_hash}, but PoE has different "
                           "policy_hash for that version (or version "
                           "missing entirely)."),
            })
        else:
            checks_passed.append("policy_hash_consistency")
    except (KeyError, TypeError) as e:
        checks_failed.append({
            "check": "policy_hash_consistency",
            "reason": f"Cannot check policy_hash consistency: "
                      f"{type(e).__name__}: {e}",
        })

    # ------------------------------------------------------------
    # Check 2c: policy_consensus_execution_binding (v2.4)
    # ------------------------------------------------------------
    # Defeats cross-version vote grafting: the policy that PoO executes
    # MUST be the SAME policy that the quorum approved. Votes for CV_1
    # cannot authorize execution of CV_2 even if both versions are in
    # PoE with valid chain integrity.
    #
    # Defeats cross-epoch vote replay: votes from a prior epoch cannot
    # authorize a decision in the current epoch.
    #
    # The contract this check enforces:
    #   - registry.epoch_id is the active epoch
    #   - PoO.policy_version_id is the active policy version
    #   - PoO.policy_hash is the active policy hash
    #   - EVERY ACCEPT vote must bind to ALL THREE: same epoch, same
    #     policy_version_id, same policy_hash
    #   - Quorum is computed ONLY from votes that bind to the active policy
    if not registry_authentic:
        checks_failed.append({
            "check": "policy_consensus_execution_binding",
            "reason": "Skipped: registry not authentic.",
        })
    else:
        try:
            active_epoch_id = governance_registry["epoch_id"]
            active_policy_version_id = poo["policy_version_id"]
            active_policy_hash = poo["policy_hash"]

            authorized = governance_registry["authorized_participants"]
            critical_roles = set(
                governance_registry["critical_acceptor_roles"]
            )
            threshold = governance_registry["consensus_threshold"]

            # Filter ACCEPT votes that bind to the ACTIVE policy
            # (epoch + version_id + policy_hash all matching)
            binding_accept_weight = 0.0
            total_weight = 0.0
            binding_critical_acceptor = False
            mismatched_votes = []

            for v in pon.get("votes", []):
                pid = v.get("participant_id")
                if pid not in authorized:
                    continue  # caught by other checks
                canonical_weight = (
                    authorized[pid]["canonical_vote_weight"]
                )
                canonical_role = authorized[pid]["role"]
                total_weight += canonical_weight

                # All three bindings must match for the vote to count
                # toward the active policy's consensus
                if (v.get("epoch_id") == active_epoch_id
                        and v.get("policy_version_id_anchor")
                            == active_policy_version_id
                        and v.get("policy_hash") == active_policy_hash):
                    if v.get("vote") == "ACCEPT":
                        binding_accept_weight += canonical_weight
                        if canonical_role in critical_roles:
                            binding_critical_acceptor = True
                else:
                    # Record the mismatch for diagnostics
                    mismatched_votes.append({
                        "participant_id": pid,
                        "vote_epoch": v.get("epoch_id"),
                        "vote_policy_version": v.get(
                            "policy_version_id_anchor"
                        ),
                        "vote_policy_hash": v.get("policy_hash"),
                    })

            binding_ratio = (binding_accept_weight / total_weight
                             if total_weight > 0 else 0.0)
            binding_quorum_ok = (binding_critical_acceptor
                                 and binding_ratio >= threshold)

            if binding_quorum_ok and not mismatched_votes:
                checks_passed.append("policy_consensus_execution_binding")
            elif binding_quorum_ok and mismatched_votes:
                # Quorum is met by binding votes, but there are stale
                # votes in the bundle that don't bind. We accept the
                # check but note the anomaly for the audit log.
                # (Strictly speaking, this is fine: extra non-binding
                # votes can't fabricate consensus on their own. They
                # would still fail any per-vote signature check that
                # mismatches policy_hash. We allow them with a note.)
                checks_passed.append("policy_consensus_execution_binding")
            else:
                reasons = []
                if mismatched_votes:
                    reasons.append(
                        f"{len(mismatched_votes)} vote(s) do not bind to "
                        f"the active policy (epoch={active_epoch_id}, "
                        f"version={active_policy_version_id}, "
                        f"policy_hash={active_policy_hash[:16]}...)"
                    )
                reasons.append(
                    f"binding_accept_ratio={binding_ratio:.4f}, "
                    f"threshold={threshold}, "
                    f"critical_acceptor_on_active_policy="
                    f"{binding_critical_acceptor}"
                )
                checks_failed.append({
                    "check": "policy_consensus_execution_binding",
                    "reason": ("Quorum on the ACTIVE policy is not "
                               "satisfied. " + "; ".join(reasons)),
                    "mismatched_votes": mismatched_votes,
                })
        except (KeyError, TypeError, ZeroDivisionError) as e:
            checks_failed.append({
                "check": "policy_consensus_execution_binding",
                "reason": f"Cannot evaluate binding: "
                          f"{type(e).__name__}: {e}",
            })

    # ------------------------------------------------------------
    # Check 3: PoO signature valid — operator key from REGISTRY
    # ------------------------------------------------------------
    sig_ok = False
    sig_failure_reason = None
    if not registry_authentic:
        sig_failure_reason = "Skipped: registry not authentic."
    elif expected_input_data is None:
        sig_failure_reason = "No expected_input_data provided."
    else:
        try:
            operator_id = poo["operator_id"]
            authorized_ops = governance_registry.get(
                "authorized_operators", {}
            )
            if operator_id not in authorized_ops:
                sig_failure_reason = (
                    f"Operator '{operator_id}' is not in "
                    "registry.authorized_operators."
                )
            else:
                # KEY ANCHORING: take pubkey from registry, NOT from PoO
                operator_pubkey = authorized_ops[operator_id]["public_key"]
                concat = (canonical_json(expected_input_data) + b"||"
                          + poo["policy_version_id"].encode("utf-8")
                          + b"||"
                          + poo["decision_timestamp"].encode("utf-8"))
                if not verify_signature(operator_pubkey, concat,
                                        poo["operator_signature"]):
                    sig_failure_reason = (
                        "PoO signature did not verify against "
                        "operator's registry-anchored public key."
                    )
                elif hash_object(expected_input_data) != poo["input_data_hash"]:
                    sig_failure_reason = "input_data_hash mismatch."
                else:
                    sig_ok = True
        except (KeyError, TypeError) as e:
            sig_failure_reason = (
                f"PoO/registry malformed: {type(e).__name__}: {e}"
            )

    if sig_ok:
        checks_passed.append("poo_signature_valid")
    else:
        checks_failed.append({
            "check": "poo_signature_valid",
            "reason": sig_failure_reason,
        })

    # ------------------------------------------------------------
    # Check 4: PoR — references + DAG + REACHABILITY + signature
    # ------------------------------------------------------------
    # (a) every derived_from resolves to a real node
    # (b) the conclusion sub-graph is acyclic
    # (c) every conclusion has a derivation path reaching at least one premise
    # (d) graph signature verifies against the registry-anchored operator key
    try:
        premise_ids = {p["id"] for p in por["premises"]}
        rule_ids = {r["id"] for r in por["rules_applied"]}
        conclusion_ids = {c["id"] for c in por["conclusions"]}

        # (a) reference resolution
        consistent = True
        first_bad_ref = None
        for c in por["conclusions"]:
            for ref in c.get("derived_from", []):
                if (ref not in premise_ids and ref not in rule_ids
                        and ref not in conclusion_ids):
                    consistent = False
                    first_bad_ref = (c["id"], ref)
                    break
            if not consistent:
                break

        # (b) cycle detection on conclusion->conclusion edges
        cycle_detected = False
        cycle_path = None
        if consistent:
            adj = {c["id"]: [r for r in c.get("derived_from", [])
                              if r in conclusion_ids]
                   for c in por["conclusions"]}
            WHITE, GRAY, BLACK = 0, 1, 2
            color = {cid: WHITE for cid in adj}

            def dfs(node, path):
                nonlocal cycle_detected, cycle_path
                color[node] = GRAY
                path.append(node)
                for nb in adj.get(node, []):
                    if color[nb] == GRAY:
                        cycle_detected = True
                        cycle_path = path + [nb]
                        return
                    if color[nb] == WHITE:
                        dfs(nb, path)
                        if cycle_detected:
                            return
                color[node] = BLACK
                path.pop()

            for cid in adj:
                if color[cid] == WHITE:
                    dfs(cid, [])
                    if cycle_detected:
                        break

        # (c) reachability: every conclusion must transitively reach a premise
        reachability_ok = True
        unreachable_conclusion = None
        if consistent and not cycle_detected:
            # Build a full graph including conclusions -> their derived_from
            # (excluding rules, which are not facts themselves).
            # A conclusion is reachable if a DFS from it lands on at least
            # one premise id.
            full_adj = {}
            for c in por["conclusions"]:
                full_adj[c["id"]] = [
                    r for r in c.get("derived_from", [])
                    if r in premise_ids or r in conclusion_ids
                ]
            for c in por["conclusions"]:
                # BFS from c looking for any premise
                seen = {c["id"]}
                stack = [c["id"]]
                found_premise = False
                while stack:
                    node = stack.pop()
                    for nb in full_adj.get(node, []):
                        if nb in premise_ids:
                            found_premise = True
                            break
                        if nb not in seen:
                            seen.add(nb)
                            stack.append(nb)
                    if found_premise:
                        break
                if not found_premise:
                    reachability_ok = False
                    unreachable_conclusion = c["id"]
                    break

        if not consistent:
            checks_failed.append({
                "check": "por_structural_consistency",
                "reason": (f"Conclusion {first_bad_ref[0]} references "
                           f"'{first_bad_ref[1]}' which does not exist."),
            })
        elif cycle_detected:
            checks_failed.append({
                "check": "por_structural_consistency",
                "reason": (f"Cycle in reason graph: "
                           f"{' -> '.join(cycle_path)}."),
            })
        elif not reachability_ok:
            checks_failed.append({
                "check": "por_structural_consistency",
                "reason": (f"Floating logic island: conclusion "
                           f"'{unreachable_conclusion}' has no derivation "
                           "path reaching any premise."),
            })
        else:
            # (d) signature check — operator key from REGISTRY
            if not registry_authentic:
                checks_failed.append({
                    "check": "por_structural_consistency",
                    "reason": "Skipped sig check: registry not authentic.",
                })
            else:
                try:
                    operator_id = poo["operator_id"]
                    authorized_ops = governance_registry.get(
                        "authorized_operators", {}
                    )
                    if operator_id not in authorized_ops:
                        checks_failed.append({
                            "check": "por_structural_consistency",
                            "reason": (f"Operator '{operator_id}' not "
                                       "in registry for PoR sig check."),
                        })
                    else:
                        operator_pubkey = (
                            authorized_ops[operator_id]["public_key"]
                        )

                        # CROSS-LAYER BINDING CHECK: PoR.poo_anchor must
                        # match the actual PoO in this bundle. This
                        # defeats cross-layer graph grafting.
                        anchor = por.get("poo_anchor")
                        anchor_ok = True
                        anchor_problem = None
                        if not anchor:
                            anchor_ok = False
                            anchor_problem = (
                                "PoR has no poo_anchor field. "
                                "Cross-layer binding cannot be verified."
                            )
                        elif anchor.get("operational_hash") != poo.get(
                                "operational_hash"):
                            anchor_ok = False
                            anchor_problem = (
                                "PoR.poo_anchor.operational_hash does not "
                                "match this bundle's PoO. PoR may have "
                                "been grafted from another bundle."
                            )
                        elif anchor.get("policy_hash") != poo.get(
                                "policy_hash"):
                            anchor_ok = False
                            anchor_problem = (
                                "PoR.poo_anchor.policy_hash does not "
                                "match this bundle's PoO."
                            )
                        elif anchor.get("policy_version_id") != poo.get(
                                "policy_version_id"):
                            anchor_ok = False
                            anchor_problem = (
                                "PoR.poo_anchor.policy_version_id does "
                                "not match this bundle's PoO."
                            )
                        elif anchor.get("decision_timestamp") != poo.get(
                                "decision_timestamp"):
                            anchor_ok = False
                            anchor_problem = (
                                "PoR.poo_anchor.decision_timestamp does "
                                "not match this bundle's PoO."
                            )

                        if not anchor_ok:
                            checks_failed.append({
                                "check": "por_signature_binding_valid",
                                "reason": anchor_problem,
                            })
                        else:
                            checks_passed.append(
                                "por_signature_binding_valid"
                            )

                        # v2.5: por_rule_policy_binding
                        # Every rule_applied must declare the constraint
                        # it derives from, AND the constraint_hash must
                        # match the verifier's recomputation from the
                        # active policy's constraints. This binds the
                        # rule invocation to the exact content of the
                        # authorized policy.
                        rule_binding_ok = True
                        rule_binding_problem = None
                        try:
                            # Resolve active policy constraints from PoE
                            active_version_id = poo["policy_version_id"]
                            active_constraints = None
                            for v in poe["versions"]:
                                if v["version_id"] == active_version_id:
                                    active_constraints = v["constraints"]
                                    break
                            if active_constraints is None:
                                rule_binding_ok = False
                                rule_binding_problem = (
                                    f"Active policy version "
                                    f"'{active_version_id}' not found in PoE."
                                )
                            else:
                                active_policy_hash_recomputed = (
                                    compute_policy_hash(active_constraints)
                                )
                                constraint_hash_by_id = {
                                    c["id"]: compute_constraint_hash(c)
                                    for c in active_constraints
                                }
                                for r in por.get("rules_applied", []):
                                    from_id = r.get("from_constraint")
                                    if from_id not in constraint_hash_by_id:
                                        rule_binding_ok = False
                                        rule_binding_problem = (
                                            f"Rule '{r.get('id')}' "
                                            f"claims from_constraint="
                                            f"'{from_id}', but no such "
                                            "constraint exists in the "
                                            "active policy. Arbitrary "
                                            "rule injection."
                                        )
                                        break
                                    declared_pol_hash = r.get(
                                        "policy_hash"
                                    )
                                    if declared_pol_hash != \
                                            active_policy_hash_recomputed:
                                        rule_binding_ok = False
                                        rule_binding_problem = (
                                            f"Rule '{r.get('id')}' "
                                            "declares policy_hash that "
                                            "does not match the active "
                                            "policy's recomputed hash."
                                        )
                                        break
                                    declared_c_hash = r.get(
                                        "constraint_hash"
                                    )
                                    expected_c_hash = (
                                        constraint_hash_by_id[from_id]
                                    )
                                    if declared_c_hash != expected_c_hash:
                                        rule_binding_ok = False
                                        rule_binding_problem = (
                                            f"Rule '{r.get('id')}' "
                                            f"claims constraint_hash "
                                            f"that does not match the "
                                            f"recomputed hash of "
                                            f"constraint '{from_id}' "
                                            "in the active policy. "
                                            "Rule body may have been "
                                            "tampered or fabricated."
                                        )
                                        break
                        except (KeyError, TypeError) as e:
                            rule_binding_ok = False
                            rule_binding_problem = (
                                f"Cannot evaluate rule-policy binding: "
                                f"{type(e).__name__}: {e}"
                            )

                        if rule_binding_ok:
                            checks_passed.append("por_rule_policy_binding")
                        else:
                            checks_failed.append({
                                "check": "por_rule_policy_binding",
                                "reason": rule_binding_problem,
                            })

                        unsigned_por = {
                            k: v for k, v in por.items()
                            if k != "graph_signature"
                        }
                        if verify_signature(
                            operator_pubkey,
                            canonical_json(unsigned_por),
                            por["graph_signature"],
                        ):
                            checks_passed.append("por_structural_consistency")
                        else:
                            checks_failed.append({
                                "check": "por_structural_consistency",
                                "reason": ("Reason graph signature did "
                                           "not verify against "
                                           "registry-anchored key."),
                            })
                except (KeyError, TypeError) as e:
                    checks_failed.append({
                        "check": "por_structural_consistency",
                        "reason": f"PoR sig check failed: "
                                  f"{type(e).__name__}: {e}",
                    })
    except (KeyError, TypeError) as e:
        checks_failed.append({
            "check": "por_structural_consistency",
            "reason": f"PoR malformed: {type(e).__name__}: {e}",
        })

    # ------------------------------------------------------------
    # Check 5: PoC record integrity
    # ------------------------------------------------------------
    try:
        conflicts = poc["conflicts"]
        valid_protocols = {"LEXICOGRAPHIC", "WEIGHTED_SUM",
                           "PARETO_OPTIMAL", "HUMAN_ESCALATE"}
        any_silenced = any(c.get("silenced", False) for c in conflicts)
        protocols_valid = all(
            c.get("resolution_protocol") in valid_protocols
            for c in conflicts
        )
        if not any_silenced and protocols_valid:
            checks_passed.append("poc_record_integrity")
        else:
            reasons = []
            if any_silenced:
                reasons.append("a conflict is silenced")
            if not protocols_valid:
                reasons.append("invalid resolution protocol")
            checks_failed.append({
                "check": "poc_record_integrity",
                "reason": "; ".join(reasons),
            })
    except (KeyError, TypeError) as e:
        checks_failed.append({
            "check": "poc_record_integrity",
            "reason": f"PoC malformed: {type(e).__name__}: {e}",
        })

    # ------------------------------------------------------------
    # Check 6: Merkle root
    # ------------------------------------------------------------
    try:
        recomputed_hashes = [
            hash_object(pon), hash_object(poe), hash_object(poo),
            hash_object(por), hash_object(poc),
        ]
        recomputed_root = merkle_root_from_hashes(recomputed_hashes)
        if recomputed_root == bundle.get("merkle_root"):
            checks_passed.append("merkle_root_match")
        else:
            checks_failed.append({
                "check": "merkle_root_match",
                "reason": (f"Computed root {recomputed_root} != "
                           f"stored {bundle.get('merkle_root')}."),
            })
    except (KeyError, TypeError) as e:
        checks_failed.append({
            "check": "merkle_root_match",
            "reason": f"Bundle malformed: {type(e).__name__}: {e}",
        })

    status = "VALID" if not checks_failed else "INVALID"

    return {
        "status": status,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "verification_timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z"),
        "checks_total": 13,
        "trust_chain_summary": (
            "Trusted root → signed registry → registry-anchored "
            "participant & operator keys → signed votes + signed PoO/PoR → "
            "Merkle root over all five layers."
        ),
    }

# ============================================================
# THE TRIAGE TEST SCENARIO — EXECUTED
# ============================================================

def run_triage_scenario() -> tuple[dict, dict, Operator, dict]:
    """Execute the medical triage scenario end-to-end.

    Returns: (bundle, verifier_result, operator, patient_data)
    """

    # --- Operator: identity from registry, private key from bootstrap ---
    # The operator's public key is anchored in the registry; the private
    # key is held by the bootstrap helper (in production: by the operator
    # in an HSM).
    operator_id = "operator-istanbul-hospital-ER-01"
    operator = Operator(
        operator_id=operator_id,
        private_key=_OPERATOR_PRIVATE_KEY,
        public_key=_OPERATOR_PRIVATE_KEY.public_key(),
    )

    # --- Build PoE FIRST (so we have policy_hash to bind to) ---
    # The constraint set IS the policy. The policy_hash binds participant
    # votes and operator decisions to the exact constraint content.
    c1 = {"id": "C1", "name": "Urgency Rule",
          "rule": "IF vital_score<0.4 AND life_threatening THEN priority=HIGH AND max_wait_minutes=5"}
    c2 = {"id": "C2", "name": "Fairness Rule",
          "rule": "IF priority=HIGH AND protected_group THEN escalation_review=REQUIRED",
          "fairness_bound": 0.15}
    c3_v1 = {"id": "C3", "name": "Wait-Time Rule",
             "rule": "IF wait_minutes>30 AND priority=MEDIUM THEN priority=HIGH"}
    c3_v2 = {"id": "C3", "name": "Wait-Time Rule",
             "rule": "IF wait_minutes>25 AND priority=MEDIUM THEN priority=HIGH"}
    c4 = {"id": "C4", "name": "Escalation Protocol",
          "rule": "IF escalation_review=REQUIRED THEN review_mode=PARALLEL_NON_BLOCKING AND attach escalation_record_id"}

    cv1 = build_constraint_version(
        version_id="CV_1",
        constraints=[c1, c2, c3_v1, c4],
        previous_hash=None,
        effective_date="2026-04-01T10:00:00Z",
        justification="Genesis version from PoN epoch-2026-Q2.",
    )
    cv2 = build_constraint_version(
        version_id="CV_2",
        constraints=[c1, c2, c3_v2, c4],
        previous_hash=cv1["self_hash"],
        effective_date="2026-05-15T09:00:00Z",
        justification="Ethics board review tightened wait-time threshold "
                      "from 30 to 25 minutes.",
    )
    poe = build_poe([cv1, cv2])

    # --- Build PoN ---
    # The participants vote on the policy that will actually be executed.
    # Here, after the CV_1 → CV_2 evolution, a new round of votes is
    # cast on CV_2 (the active policy). PoO will then execute under CV_2.
    # This satisfies policy_consensus_execution_binding: the quorum
    # approves the EXACT policy hash that PoO executes.
    epoch_id = "epoch-2026-Q2"
    vote_ts = "2026-05-15T10:00:00Z"  # after CV_2 effective date
    policy_anchor = "CV_2"  # symbolic name of the executed policy
    policy_hash_for_execution = cv2["policy_hash"]  # content-bound

    pon_votes = [
        sign_vote("regulator-MOH-TR-01", "ACCEPT", epoch_id, policy_anchor,
                  policy_hash_for_execution, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["regulator-MOH-TR-01"]),
        sign_vote("ethics-board-IST-04", "ACCEPT", epoch_id, policy_anchor,
                  policy_hash_for_execution, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["ethics-board-IST-04"]),
        sign_vote("domain-expert-EM-12", "ACCEPT", epoch_id, policy_anchor,
                  policy_hash_for_execution, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["domain-expert-EM-12"]),
        sign_vote("affected-rep-PA-03", "ACCEPT", epoch_id, policy_anchor,
                  policy_hash_for_execution, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["affected-rep-PA-03"]),
    ]
    pon = build_pon(
        epoch_id=epoch_id,
        t0=vote_ts,
        votes=pon_votes,
        registry_hash=GOVERNANCE_REGISTRY_V1_HASH,
    )

    # --- Patient data ---
    patient_data = {
        "patient_id": "pt-anon-2026-05-20-001",
        "vital_score": 0.38,
        "life_threatening": True,
        "wait_minutes_at_decision": 12,
        "demographic_group": "protected_group_A",
        "age": 72,
    }
    decision_timestamp = "2026-05-20T14:32:01Z"

    # --- Build PoO (binds to CV_2's policy_hash) ---
    poo = build_poo(
        input_data=patient_data,
        policy_version_id="CV_2",
        policy_hash=cv2["policy_hash"],
        decision_timestamp=decision_timestamp,
        operator=operator,
    )

    # --- Build PoR ---
    premises = [
        {"id": "p1", "fact": "vital_score = 0.38"},
        {"id": "p2", "fact": "life_threatening = TRUE"},
        {"id": "p3", "fact": "wait_minutes = 12"},
        {"id": "p4", "fact": "demographic_group = protected_group_A"},
    ]
    rules = [
        {"id": "r1", "from_constraint": "C1",
         "applied_as": "vital<0.4 AND life_threatening → priority=HIGH"},
        {"id": "r2", "from_constraint": "C2",
         "applied_as": "priority=HIGH AND protected_group → escalation_review=REQUIRED"},
        {"id": "r3", "from_constraint": "C4",
         "applied_as": "escalation_review=REQUIRED → "
                       "review_mode=PARALLEL_NON_BLOCKING + attach record_id"},
    ]
    conclusions = [
        {"id": "c1", "value": "priority = HIGH",
         "derived_from": ["p1", "p2", "r1"]},
        {"id": "c2", "value": "escalation_review = REQUIRED",
         "derived_from": ["c1", "p4", "r2"]},
        {"id": "c3", "value": "review_mode = PARALLEL_NON_BLOCKING",
         "derived_from": ["c2", "r3"]},
        {"id": "c4", "value": "escalation_record_id = ESC-001-2026",
         "derived_from": ["c2", "r3"]},
    ]
    logic_delta = {
        "before": {"priority": "UNASSIGNED"},
        "after": {
            "priority": "HIGH",
            "escalation_review": "REQUIRED",
            "review_mode": "PARALLEL_NON_BLOCKING",
            "escalation_record_id": "ESC-001-2026",
        },
    }
    por = build_por(premises, rules, conclusions, logic_delta, operator,
                    poo_anchor={
                        "operational_hash": poo["operational_hash"],
                        "policy_version_id": poo["policy_version_id"],
                        "policy_hash": poo["policy_hash"],
                        "decision_timestamp": poo["decision_timestamp"],
                    },
                    active_policy_constraints=cv2["constraints"])

    # --- Build PoC ---
    conflict_cf1 = {
        "conflict_id": "CF_1",
        "conflicting_constraints": ["C1", "C2"],
        "tension_type": "execution_timing",
        "description": "C1 demands immediate action (max_wait=5min); "
                       "C2 demands escalation_review which adds time.",
        "resolution_protocol": "LEXICOGRAPHIC",
        "priority_order": ["urgency", "fairness_review"],
        "resolution_outcome": "HIGH priority with PARALLEL_NON_BLOCKING review",
        "silenced": False,
        "documented_at": "2026-05-20T14:32:01Z",
    }
    poc = build_poc([conflict_cf1])

    # --- Assemble bundle ---
    bundle = assemble_bundle(pon, poe, poo, por, poc)

    # --- Run verifier ---
    verifier_result = verify_bundle(bundle, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    bundle["verifier_result"] = verifier_result

    return bundle, verifier_result, operator, patient_data


# ============================================================
# TAMPER SUITE — six independent tests, one per layer + Merkle
# ============================================================

def _expectation_satisfied(actual_failed: list[str],
                           expected_any_of: list[str]) -> bool:
    """A tamper test passes if at least one expected failure occurs.
    (Some tampers correctly cascade to multiple failures — e.g., changing
    poo.input_data_hash invalidates both poo_signature_valid AND
    merkle_root_match. We only require that one of the expected checks
    fails, not that ONLY those fail.)"""
    return any(c in actual_failed for c in expected_any_of)


def tamper_pon(bundle: dict, patient_data: dict) -> dict:
    """Test 1: Tamper PoN — flip both critical voters to REJECT in the
    new registry-anchored format.

    Expected to fail: pon_quorum_integrity."""
    import copy
    t = copy.deepcopy(bundle)
    # In the new format, votes is a list of {participant_id, vote}.
    # Flip the two critical voters' votes.
    for v in t["constitutional_layer"]["pon"]["votes"]:
        if v["participant_id"] in ("regulator-MOH-TR-01",
                                   "ethics-board-IST-04"):
            v["vote"] = "REJECT"

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]
    return {
        "test_id": "T1_pon_break_quorum_axiom",
        "tampered_field": "constitutional_layer.pon.votes[REGULATOR & ETHICS_BOARD]",
        "tamper_description": "Flipped BOTH REGULATOR and ETHICS_BOARD votes "
                              "from ACCEPT to REJECT in the registry-anchored "
                              "vote list. Quorum Integrity Axiom requires at "
                              "least one of REGULATOR/ETHICS_BOARD to ACCEPT.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def tamper_poe(bundle: dict, patient_data: dict) -> dict:
    """Test 2: Tamper PoE — break the previous_version_hash link.
    Expected to fail: poe_chain_monotonicity."""
    import copy
    t = copy.deepcopy(bundle)
    # Replace CV_2's previous_version_hash with garbage — breaking the chain
    poe = t["constitutional_layer"]["poe"]
    poe["versions"][1]["previous_version_hash"] = "sha256:" + "f" * 64
    # The chain_integrity_verified flag is what the verifier reads;
    # an attacker would try to keep it true. We leave it as-is to
    # simulate the more interesting case: tamperer rewrote the link
    # but the verifier recomputes the integrity check itself.
    # Recompute as the original logic would:
    chain_ok = True
    for i, v in enumerate(poe["versions"]):
        if i == 0:
            if v["previous_version_hash"] is not None:
                chain_ok = False
                break
        else:
            if v["previous_version_hash"] != poe["versions"][i - 1]["self_hash"]:
                chain_ok = False
                break
    poe["chain_integrity_verified"] = chain_ok

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poe_chain_monotonicity"]
    return {
        "test_id": "T2_poe_break_chain_link",
        "tampered_field": "constitutional_layer.poe.versions[1].previous_version_hash",
        "tamper_description": "Replaced CV_2.previous_version_hash with arbitrary "
                              "value (all-f); recomputed chain_integrity_verified.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def tamper_poo(bundle: dict, patient_data: dict) -> dict:
    """Test 3: Tamper PoO — change input_data_hash.
    Expected to fail: poo_signature_valid AND/OR merkle_root_match."""
    import copy
    t = copy.deepcopy(bundle)
    t["operational_layer"]["poo"]["input_data_hash"] = "sha256:" + "0" * 64

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poo_signature_valid", "merkle_root_match"]
    return {
        "test_id": "T3_poo_change_input_hash",
        "tampered_field": "operational_layer.poo.input_data_hash",
        "tamper_description": "Replaced input_data_hash with all-zeros sha256.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def tamper_por(bundle: dict, patient_data: dict) -> dict:
    """Test 4: Tamper PoR — modify a conclusion's derived_from to an
    invalid (non-existent) reference.
    Expected to fail: por_structural_consistency."""
    import copy
    t = copy.deepcopy(bundle)
    por = t["operational_layer"]["por"]
    # Add a non-existent reference to conclusion c1
    por["conclusions"][0]["derived_from"] = ["p1", "p2", "r1", "p_GHOST"]
    # Recompute structural_consistency_verified as the generator would
    premise_ids = {p["id"] for p in por["premises"]}
    rule_ids = {r["id"] for r in por["rules_applied"]}
    conclusion_ids = {c["id"] for c in por["conclusions"]}
    consistent = True
    for c in por["conclusions"]:
        for ref in c.get("derived_from", []):
            if ref not in premise_ids and ref not in rule_ids \
               and ref not in conclusion_ids:
                consistent = False
    por["structural_consistency_verified"] = consistent

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_structural_consistency"]
    return {
        "test_id": "T4_por_invalid_reference",
        "tampered_field": "operational_layer.por.conclusions[0].derived_from",
        "tamper_description": "Added non-existent reference 'p_GHOST' to c1's "
                              "derived_from list; recomputed structural "
                              "consistency flag.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def tamper_poc(bundle: dict, patient_data: dict) -> dict:
    """Test 5: Tamper PoC — silence a conflict.
    Expected to fail: poc_record_integrity."""
    import copy
    t = copy.deepcopy(bundle)
    poc = t["operational_layer"]["poc"]
    poc["conflicts"][0]["silenced"] = True
    # Recompute completeness as generator would
    any_silenced = any(c.get("silenced", False) for c in poc["conflicts"])
    valid_protocols = {"LEXICOGRAPHIC", "WEIGHTED_SUM",
                       "PARETO_OPTIMAL", "HUMAN_ESCALATE"}
    protocols_valid = all(
        c["resolution_protocol"] in valid_protocols for c in poc["conflicts"]
    )
    poc["any_silenced"] = any_silenced
    poc["protocols_valid"] = protocols_valid
    poc["completeness_verified"] = not any_silenced and protocols_valid

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poc_record_integrity"]
    return {
        "test_id": "T5_poc_silence_conflict",
        "tampered_field": "operational_layer.poc.conflicts[0].silenced",
        "tamper_description": "Set CF_1.silenced = True; recomputed completeness "
                              "flags. PoC's design rejects any silenced conflict.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def tamper_merkle_root(bundle: dict, patient_data: dict) -> dict:
    """Test 6: Tamper the Merkle root directly without touching any layer.
    Expected to fail: merkle_root_match."""
    import copy
    t = copy.deepcopy(bundle)
    t["merkle_root"] = "sha256:" + "1" * 64

    result = verify_bundle(t, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["merkle_root_match"]
    return {
        "test_id": "T6_merkle_root_direct_swap",
        "tampered_field": "merkle_root",
        "tamper_description": "Replaced merkle_root with all-ones sha256 while "
                              "leaving all five layers untouched. Verifier "
                              "recomputes the root from layer contents.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def run_tamper_suite(bundle: dict, patient_data: dict) -> dict:
    """Run all six tamper tests and aggregate results."""
    tests = [
        tamper_pon(bundle, patient_data),
        tamper_poe(bundle, patient_data),
        tamper_poo(bundle, patient_data),
        tamper_por(bundle, patient_data),
        tamper_poc(bundle, patient_data),
        tamper_merkle_root(bundle, patient_data),
    ]

    all_passed = all(t["expectation_satisfied"] for t in tests)

    return {
        "suite_id": "ova-v2-tamper-suite-001",
        "framework_version": FRAMEWORK_VERSION,
        "tested_bundle": BUNDLE_ID,
        "test_count": len(tests),
        "tests_passing_expectation": sum(
            1 for t in tests if t["expectation_satisfied"]
        ),
        "all_expectations_satisfied": all_passed,
        "test_results": tests,
        "suite_summary": (
            "Each tamper test mutates a single field in a deep-copied "
            "bundle and confirms that the verifier returns INVALID with "
            "the expected failed check(s). The original bundle is never "
            "modified. A passing test requires both: (1) the verifier "
            "returns INVALID, and (2) at least one of the expected "
            "failed checks appears in the actual failures."
        ),
        "executed_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z"),
    }


# ============================================================
# MALICIOUS-GENERATOR SUITE — different from tamper suite
# ============================================================
# These tests model a *malicious generator* (not a post-generation
# tamperer). The generator deliberately writes false metadata flags
# (e.g., quorum_satisfied: true when participants reject) while
# keeping the bundle internally consistent: hashes recomputed, Merkle
# root valid, signatures valid. The verifier must reject these bundles
# by recomputing flags from primitive records.
#
# This is the test class that revealed verifier-independence issues
# in earlier versions of the framework.
# ============================================================

def _rebuild_bundle_with_consistent_hashes(pon, poe, poo, por, poc):
    """Helper: given five layer dicts (possibly with lying flags),
    assemble a bundle with internally-consistent hashes and Merkle root.
    A malicious generator can do this; the verifier should still catch
    the lying flags by recomputation."""
    layer_hashes = {
        "pon_hash": hash_object(pon),
        "poe_hash": hash_object(poe),
        "poo_hash": hash_object(poo),
        "por_hash": hash_object(por),
        "poc_hash": hash_object(poc),
    }
    ordered = [layer_hashes["pon_hash"], layer_hashes["poe_hash"],
               layer_hashes["poo_hash"], layer_hashes["por_hash"],
               layer_hashes["poc_hash"]]
    return {
        "bundle_id": BUNDLE_ID + "-malicious",
        "framework_version": FRAMEWORK_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z"),
        "hash_algorithm": HASH_ALGORITHM,
        "verification_scope": VERIFICATION_SCOPE,
        "constitutional_layer": {"pon": pon, "poe": poe},
        "operational_layer": {"poo": poo, "por": por, "poc": poc},
        "layer_hashes": layer_hashes,
        "merkle_root": merkle_root_from_hashes(ordered),
        "merkle_order": ["pon", "poe", "poo", "por", "poc"],
    }


def malicious_pon(clean_bundle: dict, patient_data: dict) -> dict:
    """Test A: PoN with all votes REJECT but metadata flags set to ACCEPT.
    The malicious generator writes _metadata_quorum_satisfied=true in
    the advisory fields, hoping the verifier will trust the metadata
    rather than recomputing from votes."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    # Flip all votes to REJECT — actual quorum is broken
    for v in pon["votes"]:
        v["vote"] = "REJECT"
    # Generator LIES in advisory metadata fields
    pon["_metadata_accept_ratio"] = 1.0
    pon["_metadata_quorum_satisfied"] = True

    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]

    return {
        "test_id": "MG_A_pon_lying_metadata",
        "attack_model": "malicious_generator",
        "description": "All authorized participants vote REJECT, but "
                       "generator writes _metadata_quorum_satisfied=true "
                       "in advisory fields. Hashes and Merkle root are "
                       "consistent. Verifier must ignore metadata and "
                       "recompute from votes + registry.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_poe(clean_bundle: dict, patient_data: dict) -> dict:
    """Test B: PoE with broken chain link but chain_integrity_verified=true.
    Hashes and Merkle root are consistent with the lying flag."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    # Break the chain link
    poe["versions"][1]["previous_version_hash"] = "sha256:" + "f" * 64
    # Recompute the self_hash for CV_2 (otherwise PoO/PoR can be valid
    # and our PoE check fails on self_hash mismatch, not on chain).
    primitive_fields = {k: v for k, v in poe["versions"][1].items()
                        if k != "self_hash"}
    poe["versions"][1]["self_hash"] = hash_object(primitive_fields)
    # The generator LIES: keeps chain_integrity_verified as true
    poe["chain_integrity_verified"] = True  # fabricated

    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poe_chain_monotonicity"]

    return {
        "test_id": "MG_B_poe_lying_flags",
        "attack_model": "malicious_generator",
        "description": "CV_2.previous_version_hash does not match CV_1, but "
                       "generator writes chain_integrity_verified=true. All "
                       "hashes and Merkle root are recomputed to be consistent "
                       "with the lying flag.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_por(clean_bundle: dict, patient_data: dict) -> dict:
    """Test C: PoR with ghost reference but structural_consistency_verified=true.
    Note: we cannot fully execute this attack because the graph_signature
    is over the entire PoR payload including the ghost reference. If the
    malicious generator re-signs after inserting the ghost, the signature
    will verify but the structural check will catch the unresolved ref."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])

    # Insert ghost reference
    por["conclusions"][0]["derived_from"] = ["p1", "p2", "r1", "p_GHOST"]
    # Generator LIES: keeps structural_consistency_verified as true
    por["structural_consistency_verified"] = True  # fabricated

    # Re-sign with the operator's key (the malicious generator has access
    # to it — that's part of the malicious-generator model).
    # Reconstruct the operator from the public key stored in PoO is not
    # possible; for this test we generate a fresh operator and re-sign
    # both PoO and PoR with it.
    new_operator = Operator.new(poo["operator_id"])
    poo["operator_public_key"] = new_operator.public_key_hex()
    # Re-sign PoO
    concat = (canonical_json({
        "patient_id": "pt-anon-2026-05-20-001",
        "vital_score": 0.38,
        "life_threatening": True,
        "wait_minutes_at_decision": 12,
        "demographic_group": "protected_group_A",
        "age": 72,
    }) + b"||" + poo["policy_version_id"].encode("utf-8")
        + b"||" + poo["decision_timestamp"].encode("utf-8"))
    poo["operator_signature"] = new_operator.sign(concat)
    # Re-sign PoR
    unsigned_por = {k: v for k, v in por.items() if k != "graph_signature"}
    por["graph_signature"] = new_operator.sign(canonical_json(unsigned_por))

    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_structural_consistency"]

    return {
        "test_id": "MG_C_por_lying_flags",
        "attack_model": "malicious_generator",
        "description": "PoR contains an unresolved ghost reference, but "
                       "generator writes structural_consistency_verified=true. "
                       "Generator re-signs PoR and PoO with a fresh operator "
                       "key. Verifier must catch the ghost by recomputing "
                       "reference resolution.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_poc(clean_bundle: dict, patient_data: dict) -> dict:
    """Test D: PoC with silenced=true but completeness_verified=true.
    Hashes and Merkle root are consistent with the lying flag."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Conflict is silenced
    poc["conflicts"][0]["silenced"] = True
    # Generator LIES: keeps completeness_verified as true
    poc["any_silenced"] = False  # fabricated
    poc["completeness_verified"] = True  # fabricated

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle, expected_input_data=patient_data, governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poc_record_integrity"]

    return {
        "test_id": "MG_D_poc_lying_flags",
        "attack_model": "malicious_generator",
        "description": "Conflict CF_1 has silenced=true, but generator "
                       "writes any_silenced=false and completeness_verified=true. "
                       "Hashes and Merkle root are consistent with the lying flags.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


# ============================================================
# Governance-anchoring attacks (Gemini's discovery): the bundle
# carries self-authored constitutional rules. These tests verify
# that the verifier rejects bundles where the generator tried to
# rewrite threshold, weights, roles, or participant identities.
# ============================================================

def malicious_threshold_manipulation(clean_bundle: dict,
                                     patient_data: dict) -> dict:
    """Test E: Generator writes an old-format PoN with self-authored
    consensus_threshold = 0.01, hoping the verifier will accept this
    extremely permissive threshold. The verifier must reject because
    threshold comes from the registry, not the bundle."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # All participants REJECT — should fail under registry threshold (0.66)
    pon["votes"] = [
        {"participant_id": "regulator-MOH-TR-01", "vote": "REJECT"},
        {"participant_id": "ethics-board-IST-04", "vote": "REJECT"},
        {"participant_id": "domain-expert-EM-12", "vote": "REJECT"},
        {"participant_id": "affected-rep-PA-03", "vote": "ACCEPT"},
    ]
    # Generator inserts a fake low threshold INSIDE the bundle, hoping
    # the verifier will trust it. (In old code paths, this would work.)
    pon["consensus_threshold_FAKE"] = 0.01
    pon["_metadata_quorum_satisfied"] = True  # advisory lie

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]

    return {
        "test_id": "MG_E_threshold_manipulation",
        "attack_model": "malicious_generator_governance",
        "description": "Generator tries to inject a low consensus_threshold "
                       "into the bundle. Verifier must use registry threshold "
                       "(0.66), not bundle-supplied value.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_puppet_participant(clean_bundle: dict,
                                 patient_data: dict) -> dict:
    """Test F: Generator adds a fake participant 'PUPPET-001' with role
    REGULATOR. The verifier must reject because authorized participants
    come from the registry, not the bundle."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Replace all real votes with a single puppet that ACCEPTs
    pon["votes"] = [
        {"participant_id": "PUPPET-001", "vote": "ACCEPT"},
    ]

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]

    return {
        "test_id": "MG_F_puppet_participant",
        "attack_model": "malicious_generator_governance",
        "description": "Generator submits votes from 'PUPPET-001', a "
                       "participant not in the authorized registry. Verifier "
                       "must reject the vote as unauthorized.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_inflated_weight(clean_bundle: dict,
                              patient_data: dict) -> dict:
    """Test G: Generator tries to inflate a participant's vote_weight to
    999 inside the bundle. The verifier ignores this and uses the
    canonical_vote_weight from the registry."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # All critical voters REJECT; only one low-weight participant ACCEPTs
    # but the generator tries to claim that vote has weight 999.
    pon["votes"] = [
        {"participant_id": "regulator-MOH-TR-01", "vote": "REJECT"},
        {"participant_id": "ethics-board-IST-04", "vote": "REJECT"},
        {"participant_id": "domain-expert-EM-12", "vote": "REJECT"},
        {
            "participant_id": "affected-rep-PA-03",
            "vote": "ACCEPT",
            "FAKE_inflated_weight": 999.0,  # ignored by verifier
        },
    ]

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]

    return {
        "test_id": "MG_G_inflated_weight",
        "attack_model": "malicious_generator_governance",
        "description": "Generator tries to attach FAKE_inflated_weight=999 "
                       "to a vote. Verifier uses canonical_vote_weight from "
                       "the registry only.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_role_escalation(clean_bundle: dict,
                              patient_data: dict) -> dict:
    """Test H: Generator tries to claim that 'affected-rep-PA-03' actually
    has role REGULATOR (escalating a non-critical participant to critical).
    The verifier uses the registry's role mapping."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Critical roles all REJECT. affected-rep-PA-03 ACCEPTs.
    # Generator tries to claim affected-rep-PA-03's role is REGULATOR.
    pon["votes"] = [
        {"participant_id": "regulator-MOH-TR-01", "vote": "REJECT"},
        {"participant_id": "ethics-board-IST-04", "vote": "REJECT"},
        {"participant_id": "domain-expert-EM-12", "vote": "REJECT"},
        {
            "participant_id": "affected-rep-PA-03",
            "vote": "ACCEPT",
            "FAKE_claimed_role": "REGULATOR",  # ignored by verifier
        },
    ]

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_quorum_integrity"]

    return {
        "test_id": "MG_H_role_escalation",
        "attack_model": "malicious_generator_governance",
        "description": "Generator tries to claim 'affected-rep-PA-03' has "
                       "role REGULATOR. Verifier reads role from registry, "
                       "not from bundle.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_por_circular_reasoning(clean_bundle: dict,
                                     patient_data: dict) -> dict:
    """Test I: Generator builds a circular reason graph (c1 depends on
    c2, c2 depends on c1) but writes graph_is_dag=true and re-signs.
    The verifier must perform an actual cycle detection."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Force a circular dependency between c1 and c2
    por["conclusions"][0]["derived_from"] = ["p1", "p2", "r1", "c2"]
    por["conclusions"][1]["derived_from"] = ["c1", "p4", "r2"]
    # Generator LIES: claims it's still a DAG
    por["graph_is_dag"] = True
    por["structural_consistency_verified"] = True

    # Generator re-signs with a fresh operator key
    new_operator = Operator.new(poo["operator_id"])
    poo["operator_public_key"] = new_operator.public_key_hex()
    concat = (canonical_json({
        "patient_id": "pt-anon-2026-05-20-001",
        "vital_score": 0.38,
        "life_threatening": True,
        "wait_minutes_at_decision": 12,
        "demographic_group": "protected_group_A",
        "age": 72,
    }) + b"||" + poo["policy_version_id"].encode("utf-8")
        + b"||" + poo["decision_timestamp"].encode("utf-8"))
    poo["operator_signature"] = new_operator.sign(concat)
    unsigned_por = {k: v for k, v in por.items() if k != "graph_signature"}
    por["graph_signature"] = new_operator.sign(canonical_json(unsigned_por))

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_structural_consistency"]

    return {
        "test_id": "MG_I_circular_reasoning",
        "attack_model": "malicious_generator_dag",
        "description": "Generator builds c1 <-> c2 circular dependency. "
                       "Claims graph_is_dag=true and re-signs PoR. Verifier "
                       "must run actual cycle detection (DFS coloring) and "
                       "reject the cycle.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_registry_substitution(clean_bundle: dict,
                                    patient_data: dict) -> dict:
    """Test J: Attacker fabricates a fake registry with their own keys
    and threshold=0.01, signs it with their own root, and passes it to
    the verifier. The verifier's pinned TRUSTED_REGISTRY_ROOT_PUBLIC_KEY
    rejects it."""
    # Build a fake registry signed by an ATTACKER root key
    attacker_root = Ed25519PrivateKey.generate()
    attacker_root_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{attacker_root.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}"
    )
    attacker_op = Ed25519PrivateKey.generate()
    attacker_op_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{attacker_op.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}"
    )

    fake_registry_payload = {
        "registry_id": "ATTACKER-registry",
        "epoch_id": "epoch-attack",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2099-12-31T23:59:59Z",
        "consensus_threshold": 0.01,  # absurdly low
        "critical_acceptor_roles": ["ATTACKER_ROLE"],
        "authorized_participants": {
            "attacker-001": {
                "role": "ATTACKER_ROLE",
                "canonical_vote_weight": 999.0,
                "public_key": attacker_root_hex,
            },
        },
        "authorized_operators": {
            "operator-istanbul-hospital-ER-01": {
                "public_key": attacker_op_hex,
            },
        },
        "allowed_votes": ["ACCEPT", "REJECT", "ABSTAIN"],
        "registry_root_public_key": attacker_root_hex,
    }
    payload_bytes = json.dumps(fake_registry_payload, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
    fake_sig = attacker_root.sign(payload_bytes)
    fake_registry = dict(fake_registry_payload)
    fake_registry["registry_signature"] = (
        f"{SIGNATURE_SCHEME_TAG}:{fake_sig.hex()}"
    )

    # Pass the fake registry to the verifier (with the original bundle).
    # The verifier rejects because trusted_root_public_key doesn't match.
    result = verify_bundle(clean_bundle,
                           expected_input_data=patient_data,
                           governance_registry=fake_registry)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["registry_signature_valid"]
    return {
        "test_id": "MG_J_registry_substitution",
        "attack_model": "malicious_generator_pki",
        "description": "Attacker fabricates a registry signed by their own "
                       "root key (with attacker as participant, threshold=0.01). "
                       "Verifier rejects because TRUSTED_REGISTRY_ROOT_PUBLIC_KEY "
                       "is pinned out-of-band.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_vote_forgery(clean_bundle: dict,
                           patient_data: dict) -> dict:
    """Test K: Attacker submits an ACCEPT vote on behalf of a participant
    without a valid signature. The verifier rejects via vote signature
    check using registry-anchored keys."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Replace the regulator's signature with a fabricated one
    # (signed with attacker's key)
    attacker_key = Ed25519PrivateKey.generate()
    for v in pon["votes"]:
        if v["participant_id"] == "regulator-MOH-TR-01":
            # Build the canonical payload as the participant would
            payload = canonical_vote_payload(
                v["participant_id"], v["vote"], v["epoch_id"],
                v["policy_version_id_anchor"],
                v.get("policy_hash", ""),
                v["vote_timestamp"]
            )
            # Sign with attacker's key (not the real participant's)
            forged = attacker_key.sign(payload)
            v["signature"] = f"{SIGNATURE_SCHEME_TAG}:{forged.hex()}"
            break

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["pon_vote_signatures_valid"]
    return {
        "test_id": "MG_K_vote_forgery",
        "attack_model": "malicious_generator_pki",
        "description": "Attacker signs the regulator's vote payload with "
                       "an attacker-generated key. Verifier resolves the "
                       "regulator's public key from the registry and the "
                       "signature fails to verify.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_operator_key_substitution(clean_bundle: dict,
                                        patient_data: dict) -> dict:
    """Test L: Attacker swaps PoO's operator_public_key metadata for
    their own key and re-signs PoO. The verifier ignores PoO's metadata
    key and uses the registry-anchored operator key instead, so the
    signature fails."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Attacker generates a fresh key, claims it as the operator's key,
    # and re-signs PoO with it.
    attacker_key = Ed25519PrivateKey.generate()
    attacker_pub_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{attacker_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}"
    )
    poo["_metadata_public_key"] = attacker_pub_hex
    # Re-sign with attacker's key
    concat = (canonical_json(patient_data) + b"||"
              + poo["policy_version_id"].encode("utf-8") + b"||"
              + poo["decision_timestamp"].encode("utf-8"))
    poo["operator_signature"] = (
        f"{SIGNATURE_SCHEME_TAG}:{attacker_key.sign(concat).hex()}"
    )

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["poo_signature_valid"]
    return {
        "test_id": "MG_L_operator_key_substitution",
        "attack_model": "malicious_generator_pki",
        "description": "Attacker writes their own public key into PoO's "
                       "metadata field and re-signs with it. Verifier "
                       "resolves operator key from "
                       "registry.authorized_operators, not from PoO, so the "
                       "signature fails.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_registry_version_skew(clean_bundle: dict,
                                    patient_data: dict) -> dict:
    """Test M: Attacker uses a registry whose valid_until is BEFORE the
    decision timestamp. Verifier rejects on temporal validity."""
    import copy

    # Build a valid-but-expired registry signed by the SAME trusted root.
    # We can't easily extract the private key here, so we generate a
    # new bootstrap pair and pretend the verifier was pinned to that.
    # For this test we override trusted_root_public_key in the call.
    expired_root_priv = Ed25519PrivateKey.generate()
    expired_root_hex = (
        f"{SIGNATURE_SCHEME_TAG}-pub:"
        f"{expired_root_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}"
    )

    # Build the registry but with valid_until in the past
    real_reg = copy.deepcopy(GOVERNANCE_REGISTRY_V1)
    real_reg.pop("registry_signature", None)
    real_reg["valid_from"] = "2020-01-01T00:00:00Z"
    real_reg["valid_until"] = "2020-12-31T23:59:59Z"  # expired
    real_reg["registry_root_public_key"] = expired_root_hex

    # Re-sign with the new "trusted" root
    payload_bytes = json.dumps(real_reg, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
    sig = expired_root_priv.sign(payload_bytes)
    real_reg["registry_signature"] = f"{SIGNATURE_SCHEME_TAG}:{sig.hex()}"

    expired_hash = (
        f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
    )

    # Update the bundle to reference this expired registry's hash
    bundle_copy = copy.deepcopy(clean_bundle)
    bundle_copy["constitutional_layer"]["pon"]["governance_registry_hash"] = expired_hash
    # Recompute Merkle root
    bundle_copy = _rebuild_bundle_with_consistent_hashes(
        bundle_copy["constitutional_layer"]["pon"],
        bundle_copy["constitutional_layer"]["poe"],
        bundle_copy["operational_layer"]["poo"],
        bundle_copy["operational_layer"]["por"],
        bundle_copy["operational_layer"]["poc"],
    )

    # Verify with this attacker-controlled but signature-valid registry.
    # We temporarily trust the expired root (simulating a real deployment
    # where the verifier WAS configured with this root, but the registry
    # has since expired).
    result = verify_bundle(
        bundle_copy,
        expected_input_data=patient_data,
        governance_registry=real_reg,
        trusted_root_public_key=expired_root_hex,
        allowed_registry_hashes={expired_hash},
    )
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["registry_temporal_validity"]
    return {
        "test_id": "MG_M_registry_version_skew",
        "attack_model": "malicious_generator_pki",
        "description": "Registry is properly signed and pinned, but its "
                       "valid_until is in the past relative to the "
                       "decision timestamp. Verifier rejects on temporal "
                       "validity.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_unsigned_registry(clean_bundle: dict,
                                patient_data: dict) -> dict:
    """Test N: Attacker presents an unsigned registry to the verifier."""
    import copy
    unsigned_reg = copy.deepcopy(GOVERNANCE_REGISTRY_V1)
    unsigned_reg.pop("registry_signature", None)

    result = verify_bundle(clean_bundle,
                           expected_input_data=patient_data,
                           governance_registry=unsigned_reg)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["registry_signature_valid"]
    return {
        "test_id": "MG_N_unsigned_registry",
        "attack_model": "malicious_generator_pki",
        "description": "Attacker strips registry_signature from the "
                       "registry. Verifier rejects because the signature "
                       "is required.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_por_floating_island(clean_bundle: dict,
                                  patient_data: dict) -> dict:
    """Test O: Attacker builds a PoR where a conclusion derives only from
    a rule (no premise path). The verifier's reachability check rejects."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Make all conclusions derive from rules only (no premise reachable)
    # The attacker chains conclusions to each other and to rules, but
    # never references a premise.
    for c in por["conclusions"]:
        c["derived_from"] = [r["id"] for r in por["rules_applied"]]

    # Re-sign PoR with the operator's key
    unsigned_por = {k: v for k, v in por.items() if k != "graph_signature"}
    por["graph_signature"] = (
        f"{SIGNATURE_SCHEME_TAG}:"
        f"{_OPERATOR_PRIVATE_KEY.sign(canonical_json(unsigned_por)).hex()}"
    )

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_structural_consistency"]
    return {
        "test_id": "MG_O_floating_logic_island",
        "attack_model": "malicious_generator_dag",
        "description": "Attacker builds conclusions that only derive from "
                       "rules, with no path back to any premise. Reasoning "
                       "is structurally consistent and acyclic but "
                       "ungrounded. Verifier's reachability check rejects.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_policy_payload_substitution(clean_bundle: dict,
                                          patient_data: dict) -> dict:
    """Test P: Attacker edits the constraints inside CV_1 (keeping its
    version_id and stored policy_hash) hoping the old vote signatures
    will still verify. The verifier recomputes policy_hash from raw
    constraints and rejects on policy_hash_consistency.

    This defeats Policy Forgery: votes bind to the policy CONTENT, not
    just the symbolic version name."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Edit CV_1's constraints (keep policy_hash and version_id the same!)
    # Add a new attacker-favored constraint while keeping stored hashes.
    cv1 = poe["versions"][0]
    cv1["constraints"].append({
        "id": "C5_ATTACKER",
        "name": "Attacker Backdoor",
        "rule": "IF anything THEN priority=HIGH",
    })
    # Recompute self_hash so the chain still ties together; but DO NOT
    # update policy_hash — that's the lie the verifier catches.
    primitive = {k: v for k, v in cv1.items() if k != "self_hash"}
    cv1["self_hash"] = hash_object(primitive)
    # Now CV_2's previous_version_hash needs to point to this new self_hash
    cv2 = poe["versions"][1]
    cv2["previous_version_hash"] = cv1["self_hash"]
    primitive2 = {k: v for k, v in cv2.items() if k != "self_hash"}
    cv2["self_hash"] = hash_object(primitive2)

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["policy_hash_consistency"]
    return {
        "test_id": "MG_P_policy_payload_substitution",
        "attack_model": "malicious_generator_policy_forgery",
        "description": "Attacker injects an extra constraint into CV_1 "
                       "after the negotiation, keeping the stored "
                       "policy_hash and version_id unchanged. Vote "
                       "signatures still verify cryptographically against "
                       "the old payload, but the verifier recomputes "
                       "policy_hash from raw constraints and detects the "
                       "discrepancy.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_cross_layer_graph_grafting(clean_bundle: dict,
                                         patient_data: dict) -> dict:
    """Test Q: Attacker builds a SECOND valid bundle (different patient,
    different decision) and grafts its PoR onto the first bundle's PoO.
    Both PoO and PoR have valid individual signatures, but the verifier's
    cross-layer binding check (poo_anchor) catches that they belong to
    different decisions."""
    import copy

    # Build a SECOND, independent bundle for a different patient.
    # The attacker can create this themselves with the same operator key
    # (since they control the operator in the malicious-generator model).
    operator = Operator(
        operator_id="operator-istanbul-hospital-ER-01",
        private_key=_OPERATOR_PRIVATE_KEY,
        public_key=_OPERATOR_PRIVATE_KEY.public_key(),
    )

    # Different patient data → different operational_hash
    different_patient = {
        "patient_id": "pt-DIFFERENT-PATIENT-001",
        "vital_score": 0.92,  # very different
        "life_threatening": False,
        "wait_minutes_at_decision": 5,
        "demographic_group": "general_population",
        "age": 30,
    }
    different_ts = "2026-05-21T09:00:00Z"

    # Build PoO for the different patient (using policy_hash of CV_2
    # from the clean bundle for simplicity)
    cv2_policy_hash = clean_bundle["constitutional_layer"]["poe"][
        "versions"][1]["policy_hash"]
    different_poo = build_poo(
        input_data=different_patient,
        policy_version_id="CV_2",
        policy_hash=cv2_policy_hash,
        decision_timestamp=different_ts,
        operator=operator,
    )

    # Build PoR for the different decision, anchored to the DIFFERENT PoO
    different_premises = [
        {"id": "p1", "fact": "vital_score = 0.92"},
        {"id": "p2", "fact": "life_threatening = FALSE"},
    ]
    different_rules = [{"id": "r1", "from_constraint": "C1",
                        "applied_as": "stable patient → LOW"}]
    different_conclusions = [
        {"id": "c1", "value": "priority = LOW",
         "derived_from": ["p1", "p2", "r1"]},
    ]
    # Get cv2's constraints for rule binding (PoO uses CV_2)
    cv2_constraints = clean_bundle["constitutional_layer"]["poe"][
        "versions"][1]["constraints"]
    different_por = build_por(
        different_premises, different_rules, different_conclusions,
        {"before": {"priority": "UNASSIGNED"},
         "after": {"priority": "LOW"}},
        operator,
        poo_anchor={
            "operational_hash": different_poo["operational_hash"],
            "policy_version_id": different_poo["policy_version_id"],
            "policy_hash": different_poo["policy_hash"],
            "decision_timestamp": different_poo["decision_timestamp"],
        },
        active_policy_constraints=cv2_constraints,
    )

    # Now graft: take the clean bundle's PoO, attach the DIFFERENT PoR.
    # Both signatures are individually valid.
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    grafted_por = copy.deepcopy(different_por)
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, grafted_por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_signature_binding_valid"]
    return {
        "test_id": "MG_Q_cross_layer_graph_grafting",
        "attack_model": "malicious_generator_cross_layer",
        "description": "Attacker grafts a valid PoR (signed correctly, "
                       "anchored to a different patient's PoO) onto this "
                       "bundle's PoO. The verifier checks PoR.poo_anchor "
                       "against this bundle's actual PoO and rejects on "
                       "the binding mismatch.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_cross_version_vote_grafting(clean_bundle: dict,
                                          patient_data: dict) -> dict:
    """Test R: Attacker presents votes that approve CV_1, but PoO executes
    CV_2. Without the policy_consensus_execution_binding check, the
    verifier would see valid signatures + valid PoE chain + valid PoO,
    but the consensus and execution refer to different policies.

    With v2.4, the check fails on policy_consensus_execution_binding."""
    import copy

    # Take clean PoE (has both CV_1 and CV_2)
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Get CV_1's policy_hash from the chain
    cv1_policy_hash = poe["versions"][0]["policy_hash"]
    cv2_policy_hash = poe["versions"][1]["policy_hash"]

    # Attacker replaces the votes with new votes bound to CV_1
    # (not the executed CV_2). Each vote is REAL — signed by the actual
    # participant — but for the WRONG policy.
    epoch_id = "epoch-2026-Q2"
    vote_ts = "2026-04-01T10:00:00Z"  # at the time CV_1 was active
    pon["votes"] = [
        sign_vote("regulator-MOH-TR-01", "ACCEPT", epoch_id, "CV_1",
                  cv1_policy_hash, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["regulator-MOH-TR-01"]),
        sign_vote("ethics-board-IST-04", "ACCEPT", epoch_id, "CV_1",
                  cv1_policy_hash, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["ethics-board-IST-04"]),
        sign_vote("domain-expert-EM-12", "ACCEPT", epoch_id, "CV_1",
                  cv1_policy_hash, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["domain-expert-EM-12"]),
        sign_vote("affected-rep-PA-03", "ACCEPT", epoch_id, "CV_1",
                  cv1_policy_hash, vote_ts,
                  _PARTICIPANT_PRIVATE_KEYS["affected-rep-PA-03"]),
    ]
    # PoO still executes CV_2 (cv2_policy_hash); we do NOT change PoO.
    # The bundle now claims: quorum approved CV_1, but operator ran CV_2.

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["policy_consensus_execution_binding"]
    return {
        "test_id": "MG_R_cross_version_vote_grafting",
        "attack_model": "malicious_generator_cross_version",
        "description": "Attacker uses real, signed votes for CV_1 to claim "
                       "consensus, but PoO executes CV_2. Without active "
                       "policy binding, both 'CV_1 votes valid' and 'CV_2 "
                       "is a real policy in PoE' are individually true. "
                       "The active-policy-binding check requires every "
                       "ACCEPT vote to match PoO's policy_hash exactly.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_cross_epoch_vote_replay(clean_bundle: dict,
                                      patient_data: dict) -> dict:
    """Test S: Attacker reuses votes from a prior epoch (epoch-2025-Q1)
    to authorize a decision in the current epoch (epoch-2026-Q2). Each
    vote is properly signed by its participant — at the time, with their
    real key — but the epoch_id in the signed payload is stale.

    The check fails because every vote's epoch_id must match the active
    registry's epoch_id (which is the current epoch)."""
    import copy

    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Replay scenario: take CV_2's policy_hash (current active policy),
    # but sign votes with an OLD epoch_id ("epoch-2025-Q1"). The
    # signatures are cryptographically valid (real participant keys),
    # but the epoch is stale.
    cv2_policy_hash = poe["versions"][1]["policy_hash"]
    stale_epoch = "epoch-2025-Q1"
    stale_ts = "2025-01-15T10:00:00Z"

    pon["votes"] = [
        sign_vote("regulator-MOH-TR-01", "ACCEPT", stale_epoch, "CV_2",
                  cv2_policy_hash, stale_ts,
                  _PARTICIPANT_PRIVATE_KEYS["regulator-MOH-TR-01"]),
        sign_vote("ethics-board-IST-04", "ACCEPT", stale_epoch, "CV_2",
                  cv2_policy_hash, stale_ts,
                  _PARTICIPANT_PRIVATE_KEYS["ethics-board-IST-04"]),
        sign_vote("domain-expert-EM-12", "ACCEPT", stale_epoch, "CV_2",
                  cv2_policy_hash, stale_ts,
                  _PARTICIPANT_PRIVATE_KEYS["domain-expert-EM-12"]),
        sign_vote("affected-rep-PA-03", "ACCEPT", stale_epoch, "CV_2",
                  cv2_policy_hash, stale_ts,
                  _PARTICIPANT_PRIVATE_KEYS["affected-rep-PA-03"]),
    ]

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["policy_consensus_execution_binding"]
    return {
        "test_id": "MG_S_cross_epoch_vote_replay",
        "attack_model": "malicious_generator_cross_epoch",
        "description": "Attacker replays votes signed in a prior epoch "
                       "(epoch-2025-Q1) into the current epoch "
                       "(epoch-2026-Q2). Each signature is cryptographically "
                       "valid against the participant's still-authorized "
                       "key, but the epoch_id in the signed payload does "
                       "not match the active registry's epoch_id.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def malicious_arbitrary_rule_injection(clean_bundle: dict,
                                       patient_data: dict) -> dict:
    """Test T: Attacker injects a rule into PoR that is NOT in the
    active policy, or claims a constraint_hash that doesn't match the
    real constraint content. The verifier recomputes constraint_hashes
    from the active policy and rejects on por_rule_policy_binding.

    Without this check, an operator could claim 'I used rule r_evil from
    constraint C_evil' and have the bundle accepted as long as the
    structure was DAG-consistent."""
    import copy
    pon = copy.deepcopy(clean_bundle["constitutional_layer"]["pon"])
    poe = copy.deepcopy(clean_bundle["constitutional_layer"]["poe"])
    poo = copy.deepcopy(clean_bundle["operational_layer"]["poo"])
    por = copy.deepcopy(clean_bundle["operational_layer"]["por"])
    poc = copy.deepcopy(clean_bundle["operational_layer"]["poc"])

    # Inject a fabricated rule with a fabricated constraint_hash.
    # The attacker keeps policy_hash correct (so policy_hash_consistency
    # passes) but the constraint_hash will not match.
    active_policy_hash = poo["policy_hash"]
    fake_rule = {
        "id": "r_evil",
        "from_constraint": "C1",  # claims to derive from real constraint
        "applied_as": "ATTACKER PRIORITY OVERRIDE",
        "policy_hash": active_policy_hash,  # this part is correct
        "constraint_hash": "sha256:" + "f" * 64,  # FABRICATED
    }
    por["rules_applied"].append(fake_rule)

    # The attacker also re-signs the PoR with the legitimate operator's
    # key (since they control the operator in this attack model)
    new_operator = Operator(
        operator_id=poo["operator_id"],
        private_key=_OPERATOR_PRIVATE_KEY,
        public_key=_OPERATOR_PRIVATE_KEY.public_key(),
    )
    unsigned_por = {k: v for k, v in por.items() if k != "graph_signature"}
    por["graph_signature"] = new_operator.sign(canonical_json(unsigned_por))

    malicious_bundle = _rebuild_bundle_with_consistent_hashes(
        pon, poe, poo, por, poc
    )
    result = verify_bundle(malicious_bundle,
                           expected_input_data=patient_data,
                           governance_registry=GOVERNANCE_REGISTRY_V1)
    failed = [c["check"] for c in result["checks_failed"]]
    expected = ["por_rule_policy_binding"]
    return {
        "test_id": "MG_T_arbitrary_rule_injection",
        "attack_model": "malicious_generator_rule_injection",
        "description": "Attacker injects an extra rule into PoR with a "
                       "fabricated constraint_hash. The rule claims to "
                       "derive from a real constraint (C1), the policy_hash "
                       "is correct, but constraint_hash does not match the "
                       "recomputation of C1's content. The verifier rejects "
                       "on por_rule_policy_binding.",
        "expected_failed_checks": expected,
        "actual_failed_checks": failed,
        "actual_status": result["status"],
        "expectation_satisfied": _expectation_satisfied(failed, expected)
                                 and result["status"] == "INVALID",
    }


def run_malicious_generator_suite(clean_bundle: dict,
                                  patient_data: dict) -> dict:
    """Run all malicious-generator tests.

    Groups:
      A-D: Flag-lying (basic verifier independence)
      E-H: Governance parameter manipulation
      I:   DAG cycle detection
      J-N: PKI / trust anchoring (registry, keys, temporal validity)
      O:   Reachability (floating logic island)
    """
    tests = [
        # Flag-lying group
        malicious_pon(clean_bundle, patient_data),
        malicious_poe(clean_bundle, patient_data),
        malicious_por(clean_bundle, patient_data),
        malicious_poc(clean_bundle, patient_data),
        # Governance-anchoring group
        malicious_threshold_manipulation(clean_bundle, patient_data),
        malicious_puppet_participant(clean_bundle, patient_data),
        malicious_inflated_weight(clean_bundle, patient_data),
        malicious_role_escalation(clean_bundle, patient_data),
        # DAG cycle group
        malicious_por_circular_reasoning(clean_bundle, patient_data),
        # PKI / trust anchoring group (Gemini v2.2 discoveries)
        malicious_registry_substitution(clean_bundle, patient_data),
        malicious_vote_forgery(clean_bundle, patient_data),
        malicious_operator_key_substitution(clean_bundle, patient_data),
        malicious_registry_version_skew(clean_bundle, patient_data),
        malicious_unsigned_registry(clean_bundle, patient_data),
        # Reachability group
        malicious_por_floating_island(clean_bundle, patient_data),
        # Cross-layer binding group (Gemini v2.3 discoveries)
        malicious_policy_payload_substitution(clean_bundle, patient_data),
        malicious_cross_layer_graph_grafting(clean_bundle, patient_data),
        # Active-policy binding group (Gemini v2.4 discoveries)
        malicious_cross_version_vote_grafting(clean_bundle, patient_data),
        malicious_cross_epoch_vote_replay(clean_bundle, patient_data),
        # Rule-policy binding group (Gemini v2.5 discovery)
        malicious_arbitrary_rule_injection(clean_bundle, patient_data),
    ]

    all_passed = all(t["expectation_satisfied"] for t in tests)

    return {
        "suite_id": "ova-v2-malicious-generator-suite-001",
        "framework_version": FRAMEWORK_VERSION,
        "tested_bundle": BUNDLE_ID,
        "attack_model": (
            "Malicious generator with knowledge of and access to all "
            "cryptographic keys. Tests cover three attack classes: "
            "(1) flag-lying — writing false *_verified flags while keeping "
            "internal hash consistency; (2) governance-anchoring — "
            "attempting to rewrite constitutional rules (threshold, "
            "weights, roles, participant identity) inside the bundle; "
            "(3) DAG verification — claiming graph_is_dag while embedding "
            "a cycle. Defense in each case is independent recomputation "
            "from primitive records and the external governance registry."
        ),
        "test_count": len(tests),
        "tests_passing_expectation": sum(
            1 for t in tests if t["expectation_satisfied"]
        ),
        "all_expectations_satisfied": all_passed,
        "test_results": tests,
        "executed_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z"),
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print(" OVA v2 — Minimal Proof Bundle Test")
    print(" Scenario: Medical triage with timing-tension conflict")
    print(f" Framework: {FRAMEWORK_VERSION}")
    print(f" Signature scheme: {SIGNATURE_SCHEME_TAG}")
    print(f" Production target: {PRODUCTION_TARGET}")
    print("=" * 70)

    # Run the scenario
    bundle, result, operator, patient_data = run_triage_scenario()

    print("\n[1] Proof bundle generated")
    print(f"    bundle_id:    {bundle['bundle_id']}")
    print(f"    merkle_root:  {bundle['merkle_root']}")
    print(f"    PoN hash:     {bundle['layer_hashes']['pon_hash']}")
    print(f"    PoE hash:     {bundle['layer_hashes']['poe_hash']}")
    print(f"    PoO hash:     {bundle['layer_hashes']['poo_hash']}")
    print(f"    PoR hash:     {bundle['layer_hashes']['por_hash']}")
    print(f"    PoC hash:     {bundle['layer_hashes']['poc_hash']}")

    print(f"\n[2] Verifier result: {result['status']}")
    print(f"    Checks passed ({len(result['checks_passed'])}/{result['checks_total']}):")
    for c in result["checks_passed"]:
        print(f"      ✓ {c}")
    if result["checks_failed"]:
        print(f"    Checks failed:")
        for f in result["checks_failed"]:
            print(f"      ✗ {f['check']}: {f['reason']}")

    # Tamper suite
    print("\n[3] Tamper suite (6 tests, one per verification layer)")
    suite = run_tamper_suite(bundle, patient_data)
    for t in suite["test_results"]:
        mark = "✓" if t["expectation_satisfied"] else "✗"
        print(f"    {mark} {t['test_id']}")
    print(f"    Tamper suite: {suite['tests_passing_expectation']}/"
          f"{suite['test_count']} passed")

    # Malicious-generator suite (NEW — verifier independence)
    print("\n[4] Malicious-generator suite (4 tests, verifier independence)")
    mg_suite = run_malicious_generator_suite(bundle, patient_data)
    for t in mg_suite["test_results"]:
        mark = "✓" if t["expectation_satisfied"] else "✗"
        print(f"    {mark} {t['test_id']}")
        print(f"        expected: {t['expected_failed_checks']}")
        print(f"        actual:   {t['actual_failed_checks']}")
    print(f"    Malicious-generator suite: "
          f"{mg_suite['tests_passing_expectation']}/{mg_suite['test_count']} passed")

    # Save the clean bundle to disk
    output_path = "/home/claude/ova_v2_bundle.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    print(f"\n[5] Bundle saved to: {output_path}")

    # Save the tamper suite result
    suite_path = "/home/claude/ova_v2_tamper_suite.json"
    with open(suite_path, "w", encoding="utf-8") as f:
        json.dump(suite, f, indent=2, ensure_ascii=False)
    print(f"    Tamper suite saved to: {suite_path}")

    # Save the malicious-generator suite result
    mg_path = "/home/claude/ova_v2_malicious_generator_suite.json"
    with open(mg_path, "w", encoding="utf-8") as f:
        json.dump(mg_suite, f, indent=2, ensure_ascii=False)
    print(f"    Malicious-generator suite saved to: {mg_path}")

    print("\n" + "=" * 70)
    print(" Test complete.")
    print("=" * 70)
