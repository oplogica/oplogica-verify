# OpLogica v2 — Foundation Document

**Purpose:** Establish exactly what v2 is, how it responds to v1's rejection, and what we claim (and don't claim).

**Status:** Internal reference. Not for publication. Pre-requisite for any Diagram, paper, or LinkedIn content.

**Date:** 20 May 2026

---

## 1. v1 Snapshot — What Was Submitted and Rejected

### Proof Model (3 mechanisms)
| Proof | Function |
|---|---|
| PoO — Proof of Operation | Cryptographic integrity of computational processes |
| PoR — Proof of Reason | Formal logical justification of decisions |
| PoI — Proof of Intent | A priori declaration of ethical constraints |

### Architectural Layers (5 layers)
| Layer | Role |
|---|---|
| L4 — Verification Interface | REST APIs + offline validation |
| L3 — Logic Kernel of Trust | Reason Graphs + Δ-Logic Engine |
| L2 — Witness Consensus | Distributed timestamp federation |
| L1 — Post-Quantum Authenticity | Dilithium-III signatures + Kyber KEX |
| L0 — Canonical Event Lineage | Deterministic serialization + SHA3-256 |

**Submission:** AI and Ethics (Springer Nature), December 2025
**Decision:** Rejected (single reviewer report)

### Rejection Cause — Verbatim from Reviewer 1
> "If a key aspect of the framework cannot be technically specified, this moves closer, in a practical sense, to a highly developed thought experiment than something to effectively build on for eventual deployment."

**The reviewer accepted:** the core logic, the formalization attempt, the timeliness.

**The reviewer rejected:** PoI specifically — on grounds of practical viability of normative constraint specification.

---

## 2. v2 Snapshot — Current Architecture

### Proof Model (5 mechanisms)

**Conceptual shift:** v2 does not eliminate PoI. It *decomposes* PoI into a **governance proof stack** — recognizing that "intent" cannot be expressed as a single declaration at T₀, but only through an ongoing, auditable governance process.

| Proof | Function | Status vs v1 |
|---|---|---|
| PoO — Proof of Operation | Cryptographic integrity | **Retained from v1** |
| PoR — Proof of Reason | Logical justification | **Retained from v1** |
| PoN — Proof of Negotiation | Multi-stakeholder constraint genesis | **Decomposed from PoI** |
| PoC — Proof of Conflict | Formal documentation of disagreements | **Decomposed from PoI** |
| PoE — Proof of Evolution | Append-only versioning of constraints | **Decomposed from PoI** |

**Why decomposition (not replacement):** PoI's underlying intuition — that ethical commitments must precede and constrain operational decisions — remains valid. What changes is the *representation*: from a single static declaration to a three-layer governance process (genesis → conflict → evolution). The intent is no longer a fixed artifact; it is a verifiable trajectory.

### Governance Separation (architectural innovation)
| Class | Layers | Frequency |
|---|---|---|
| **Constitutional** governance | PoN + PoE | Per governance epoch |
| **Operational** governance | PoO + PoR + PoC | Per decision |

**Key insight:** The split between constitutional and operational governance is the technical realization of "governance-in-the-loop". v1 had no such separation; v2 makes it formal.

---

## 3. Reviewer Response Matrix

This is the core defensibility artifact. For each Reviewer 1 objection, we document the responding layer, the operational answer, the required evidence, and — critically — the **remaining risk** that the system does NOT address.

### Objection 1 — Specification of Normative Constraints
**Reviewer's words:** *"prioritization rules for life-threatening conditions, maximum acceptable wait times by severity, fairness bounds across demographic groups, and escalation protocols for edge cases ... is a very non-trivial task, one that may be practically close to impossible outside of broader guidelines."*

| Field | Content |
|---|---|
| **Responding layer** | PoN — Proof of Negotiation |
| **Operational response** | v2 does not require constraints to be *correct*. It requires them to have a documented *genesis* via multi-stakeholder negotiation. The framework provides infrastructure for the negotiation process, not the philosophical answer. |
| **Required evidence in bundle** | Negotiation participants (with roles); quorum verification (must include REGULATOR or ETHICS_BOARD); negotiation timestamp T₀; cryptographic signature of consensus output. |
| **Remaining risk** | PoN documents *that* negotiation occurred and *who* participated, but cannot guarantee that participants are *legitimate representatives* of affected populations, nor that the consensus reflects substantive moral agreement rather than political compromise. The legitimacy of the quorum itself remains a sociopolitical question outside the framework. |

---

### Objection 2 — Standardization is an Unresolved Field
**Reviewer's words:** *"standardization of medical triage ... is a site of significant ongoing work and critique (cf. Timmermans & Berg 1997 ... Ferrara 2025)"*

| Field | Content |
|---|---|
| **Responding layer** | PoC — Proof of Conflict |
| **Operational response** | v2 acknowledges that disagreement is the normal state, not the failure state. Conflicts are documented as first-class artifacts. The system does not pretend to resolve genuine ethical disputes; it makes them auditable. |
| **Required evidence in bundle** | Set of documented conflicts {CF_k}; resolution protocol applied (LEXICOGRAPHIC, WEIGHTED_SUM, PARETO_OPTIMAL, or HUMAN_ESCALATE); cryptographic seal on conflict documentation. |
| **Remaining risk** | PoC ensures conflicts are *recorded*, but the choice of resolution protocol itself encodes normative assumptions. A LEXICOGRAPHIC ordering implicitly prioritizes one value over another; WEIGHTED_SUM presupposes commensurability. The framework documents *which* protocol was used; it does not justify *why* that protocol was the right one for the domain. |

---

### Objection 3 — Constraints are Not Static
**Reviewer's implicit concern:** Real-world normative consensus shifts over time. A framework that locks in PoI at T₀ is brittle.

| Field | Content |
|---|---|
| **Responding layer** | PoE — Proof of Evolution |
| **Operational response** | v2 treats constraint sets as versioned objects with append-only history. Any change to constraints creates a new version with cryptographic chain-of-custody. |
| **Required evidence in bundle** | Ordered set of constraint versions {CV_v}; append-only hash chain H_E (Monotonic History Axiom); timeline T_E of version transitions; chain integrity verifier output. |
| **Remaining risk** | PoE preserves *that* constraints evolved and *when*, but cannot detect whether evolution was driven by genuine moral learning or by political capture. An append-only chain that records "constraint X was loosened on date Y" is auditable, but does not surface whether the loosening was legitimate or coerced. Detecting capture requires external sociopolitical analysis, not cryptographic verification. |

---

### Objection 4 — Deployment Viability vs Thought Experiment
**Reviewer's words:** *"this moves closer, in a practical sense, to a highly developed thought experiment"*

| Field | Content |
|---|---|
| **Responding layer** | PoN + PoC + PoE working together |
| **Operational response** | v2's three new layers convert each unspecifiable normative question into a *procedural* question that is fully specifiable. The unspecifiable→procedural conversion is the answer to the viability objection. |
| **Required evidence in bundle** | Combined Merkle root over PoN + PoC + PoE; verifier_result with all integrity checks passed. |
| **Remaining risk** | The *procedural specifiability* of governance does not by itself produce *deployment readiness*. v2 makes the governance machinery auditable, but real deployment still requires: legal recognition of the proof artifacts, regulatory acceptance of the verification protocol, and trained auditors capable of interpreting the bundles. The framework is technically complete; the institutional ecosystem around it is not yet built. |

**Conversion table (unspecifiable → procedural):**

| Unspecifiable normative question | Procedurally specifiable equivalent |
|---|---|
| "What are the right constraints?" | "Who negotiated them, when, with what quorum?" (PoN) |
| "How do we handle disagreement?" | "Is the disagreement documented and how was it resolved?" (PoC) |
| "What if values change?" | "Is there an auditable version history?" (PoE) |

---

## 4. What We Do NOT Claim

This section exists to prevent overreach — the same failure mode that hurt the UCS paper.

**We do NOT claim:**

1. ❌ That OpLogica resolves ethical disputes
2. ❌ That documented constraints are morally correct by virtue of documentation
3. ❌ That multi-stakeholder negotiation produces objectively right outcomes
4. ❌ That PoN/PoC/PoE eliminate the need for ethical deliberation
5. ❌ That the framework replaces human judgment in normative matters

**We DO claim:**

1. ✓ That the **genesis** of constraints is cryptographically documented
2. ✓ That **disagreements** are recorded as first-class artifacts, never silenced
3. ✓ That **temporal evolution** of constraints is append-only and auditable
4. ✓ That the entire bundle is **verifiable by third parties** without re-running the system
5. ✓ That this constitutes a meaningful operational improvement over post-hoc XAI explanations

**The honest framing:** OpLogica v2 does not solve the philosophical problem Reviewer 1 raised. It converts the philosophical problem into an auditable procedural problem. This is a category shift, not a resolution.

---

## 5. Minimum Viable Proof Bundle

A real proof bundle must serialize the following structure. This is the JSON schema v2 must produce:

```json
{
  "bundle_id": "ova-bundle-2026-05-20-001",
  "framework_version": "OpLogica v2.0",
  "timestamp_utc": "2026-05-20T14:32:01Z",

  "constitutional_layer": {
    "pon_record_hash": "sha3-256:a7f2c8...",
    "pon_metadata": {
      "epoch_id": "epoch-2026-Q2",
      "quorum_satisfied": true,
      "participants": ["REGULATOR", "ETHICS_BOARD", "DOMAIN_EXPERT"],
      "consensus_mechanism": "WEIGHTED_QUORUM",
      "negotiation_timestamp_t0": "2026-04-01T00:00:00Z"
    },
    "poe_chain_hash": "sha3-256:b9e1d4...",
    "poe_metadata": {
      "current_version": "CV_3",
      "previous_version_link": "sha3-256:c8a3f1...",
      "chain_integrity_verified": true
    }
  },

  "operational_layer": {
    "poo_record_hash": "sha3-256:d4e7b2...",
    "poo_metadata": {
      "input_hash": "sha3-256:e5f6a8...",
      "policy_version": "CV_3",
      "operator_signature_dilithium3": "sig:..."
    },
    "por_record_hash": "sha3-256:f8a1c3...",
    "por_metadata": {
      "reason_graph_nodes": 7,
      "logic_delta_signed": true
    },
    "poc_record_hash": "sha3-256:a2b4d6...",
    "poc_metadata": {
      "conflicts_documented": 2,
      "resolution_protocol": "LEXICOGRAPHIC",
      "conflicts_silenced": 0
    }
  },

  "merkle_root": "sha3-256:9f8e7d6c5b4a...",

  "verifier_result": {
    "status": "VALID",
    "checks_passed": [
      "pon_quorum_integrity",
      "poe_chain_monotonicity",
      "poo_cryptographic_signatures",
      "por_logical_consistency",
      "poc_conflict_completeness",
      "merkle_root_match"
    ],
    "checks_failed": [],
    "verification_timestamp": "2026-05-20T14:32:02Z"
  }
}
```

**Defensibility property:** A third-party auditor receiving **this JSON bundle plus the referenced public verification material** (public keys for signature verification, policy schemas for PoR validation, and the constraint version index for PoE chain validation) can verify the entire decision pathway without access to the deployed system or to any private state. This is the operational answer to Reviewer 1's "viability" concern.

**Important boundary:** The bundle is *self-verifying* only with respect to its cryptographic and structural integrity. It does NOT self-verify the *substantive correctness* of the constraints negotiated in PoN, the resolution protocols chosen in PoC, or the moral legitimacy of evolutionary changes in PoE. Those remain questions for human auditors and the surrounding institutional ecosystem.

---

## 6. Pre-Defensibility Questions (Self-Test)

Before any external publication or LinkedIn Diagram, the system must answer these questions cleanly:

| Question | Answering layer | Status |
|---|---|---|
| Q1: Who defined the constraints? | PoN.participants | ⏳ Implementation test required |
| Q2: How was agreement reached? | PoN.consensus_mechanism | ⏳ Implementation test required |
| Q3: What happens on disagreement? | PoC.{conflicts, resolution_protocol} | ⏳ Implementation test required |
| Q4: How do constraints evolve? | PoE.chain | ⏳ Implementation test required |
| Q5: Is the entire bundle auditable by an external party? | merkle_root + verifier | ⏳ Implementation test required |
| Q6: Does the system claim to resolve ethics? | NO — explicit in framing | ✓ Resolved in §4 |
| Q7: What was wrong with v1, and how does v2 differ? | Section 1 vs Section 2 | ✓ Resolved in this doc |

---

## 7. Next Steps (in order)

1. **Now (this session):** This document. ✓
2. **Next session (server):** Implement minimal proof bundle generator. Test against the JSON schema in §5.
3. **Following session:** Run the system end-to-end on a single test case. Produce a real bundle.
4. **Only then:** Build LinkedIn Diagram that reflects the actual v2 implementation.
5. **Parallel:** Share this document with GPT and Gemini for independent critique before Diagram.

---

**End of Foundation Document**
