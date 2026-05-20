# Medical Triage Test Scenario — OVA v2 Minimal Test

**Purpose:** Single end-to-end scenario to validate that OVA v2 generates a complete, verifiable proof bundle with all five proof layers, Merkle root, and verifier result.

**Scope:** Proof of concept only. Not a performance test. Not a deployment test.

**Date:** 20 May 2026
**Test ID:** `ova-test-2026-05-20-001`

---

## 1. Clinical Context

**Setting:** Hospital emergency department triage decision support system.

**Decision type:** Patient priority classification (HIGH / MEDIUM / LOW).

**Single patient encounter:** One patient arrives. System must produce one triage decision with full audit trail.

---

## 2. Constitutional Layer (PoN + PoE)

### 2.1 PoN — Negotiated Constraint Set

A multi-stakeholder governance epoch was convened on **2026-04-01** to define the hospital's triage policy. Participants and their roles:

| Participant ID | Role | Vote Weight |
|---|---|---|
| `regulator-MOH-TR-01` | REGULATOR (Turkish Ministry of Health) | 1.0 |
| `ethics-board-IST-04` | ETHICS_BOARD (Istanbul Hospital Ethics Committee) | 1.0 |
| `domain-expert-EM-12` | DOMAIN_EXPERT (Emergency Medicine Specialist) | 0.8 |
| `affected-rep-PA-03` | AFFECTED_PARTY_REP (Patient Advocacy Group) | 0.6 |

**Quorum requirement (Quorum Integrity Axiom):**
At least one of {REGULATOR, ETHICS_BOARD} must vote ACCEPT for PoN to be valid.

**Consensus mechanism:** `WEIGHTED_QUORUM` (sum of ACCEPT vote weights / sum of all vote weights ≥ 0.66)

### 2.2 The Three Constraints (Negotiated)

The participants negotiated and signed three formal constraints:

**Constraint C1 — Urgency Rule**
```
IF (vital_score < 0.4 AND life_threatening = TRUE)
THEN priority = HIGH AND max_wait_minutes = 5
```
Source: WHO emergency triage guidelines, adapted by domain expert.

**Constraint C2 — Fairness Rule**
```
IF (priority = HIGH AND patient.demographic_group ∈ {protected_groups})
THEN escalation_review = REQUIRED
ENSURING: |HIGH_rate(group_A) - HIGH_rate(group_B)| ≤ 0.15
```
Source: Ethics board proposal to prevent demographic bias in HIGH assignment.

**Constraint C3 — Wait-Time Rule**
```
IF (wait_minutes > 30 AND current_priority = MEDIUM)
THEN priority = HIGH (upgraded)
```
Source: Patient advocacy proposal to prevent neglect of waiting patients.

**Constraint C4 — Escalation Protocol**
```
IF escalation_review = REQUIRED
THEN review_mode = PARALLEL_NON_BLOCKING
AND escalation_record_id MUST be attached to the proof bundle.
```
Source: Ethics board procedural rule for edge cases — directly addresses Reviewer 1's "escalation protocols for edge cases" concern.

**Negotiation outcome:**
- Total ACCEPT weight: 3.4 / 3.4 = 100%
- Quorum satisfied: YES (both REGULATOR and ETHICS_BOARD voted ACCEPT)
- Timestamp T₀: `2026-04-01T10:00:00Z`

### 2.3 PoE — Constraint Evolution Chain

Two versions exist (testing the chain mechanism):

**Version CV_1** (initial — 2026-04-01)
- Constraints: {C1, C2, C3} as defined above
- Hash: computed from canonical serialization
- Previous version: NULL (genesis)

**Version CV_2** (current — 2026-05-15)
- Constraints: {C1, C2, C3'} where C3' modified `wait_minutes > 30` to `wait_minutes > 25` after ethics board review
- Previous version hash: link to CV_1
- Justification: documented in PoE.metadata (ethics board review note)
- Append-only property: CV_1 is preserved, not overwritten

**Monotonic History Axiom:** `H_E[CV_2].previous_hash = H_E[CV_1].hash` — verifier checks this link.

---

## 3. Operational Layer (PoO + PoR + PoC)

### 3.1 The Test Patient

**Patient ID:** `pt-anon-2026-05-20-001` (synthetic, anonymized)

**Clinical inputs (D):**
```json
{
  "vital_score": 0.38,
  "life_threatening": true,
  "wait_minutes_at_decision": 12,
  "demographic_group": "protected_group_A",
  "age": 72
}
```

**Decision timestamp T:** `2026-05-20T14:32:01Z` (well after T₀)

**Active policy version:** CV_2 (current)

### 3.2 PoO — Proof of Operation

Captures:
- Cryptographic hash: `SHA-256(D ∥ policy_version ∥ T)`
- Operator signature: Ed25519 signature over the hash (prototype scheme)
- **Prototype tag:** `"signature_scheme": "Ed25519-prototype-2026"` with explicit note that production target is ML-DSA (Dilithium-III, FIPS 204)

### 3.3 PoR — Proof of Reason

Reason Graph for this decision:

```
Premises (observed):
  p1: vital_score = 0.38
  p2: life_threatening = TRUE
  p3: wait_minutes = 12
  p4: demographic_group = protected_group_A

Rules applied (from CV_2):
  r1: C1 — IF vital<0.4 ∧ life_threatening THEN priority=HIGH
  r2: C2 — IF priority=HIGH ∧ protected_group THEN escalation_review=REQUIRED
  r3: C4 — IF escalation_review=REQUIRED THEN review_mode=PARALLEL_NON_BLOCKING ∧ attach escalation_record_id

Conclusions:
  c1: priority = HIGH                        (derived from p1, p2 via r1)
  c2: escalation_review = REQUIRED           (derived from c1, p4 via r2)
  c3: review_mode = PARALLEL_NON_BLOCKING    (derived from c2 via r3)
  c4: escalation_record_id = ESC-001-2026    (attached per r3)
```

**Logic delta ΔL:** State changed from `{priority: UNASSIGNED}` to `{priority: HIGH, escalation_review: REQUIRED, review_mode: PARALLEL_NON_BLOCKING, escalation_record_id: ESC-001-2026}`.

### 3.4 PoC — Proof of Conflict

**Conflict CF_1 detected:**

C1 (Urgency Rule) and C2 (Fairness Rule) both apply to this case and produce **compatible but tension-bearing requirements**:

- C1 says: priority = HIGH, max_wait = 5 minutes
- C2 says: HIGH for protected group → escalation_review REQUIRED, which adds processing time

**This is the conflict we want to test:** urgency demands immediate action; fairness demands review process. Both are satisfied by setting HIGH + scheduling parallel escalation review, but the conflict is *documented*, not silenced.

**Resolution protocol:** `LEXICOGRAPHIC` — urgency (life-threatening) is documented as taking strict priority over review delay, with the review proceeding in parallel rather than blocking.

**Why LEXICOGRAPHIC?** The hospital's negotiated policy (in PoN metadata) specified that life-threatening cases bypass blocking review steps. This choice is itself documented, not assumed.

**Conflict record:**
```json
{
  "conflict_id": "CF_1",
  "conflicting_constraints": ["C1", "C2"],
  "tension_type": "execution_timing",
  "resolution_protocol": "LEXICOGRAPHIC",
  "priority_order": ["urgency", "fairness_review"],
  "silenced": false,
  "documented_at": "2026-05-20T14:32:01Z"
}
```

**Key property:** Even though the system resolved the conflict and acted, the conflict itself is preserved as a first-class artifact in the bundle.

---

## 4. The Final Decision

**Output:**
- `priority: HIGH`
- `escalation_review: REQUIRED (parallel, non-blocking)`
- `max_wait_target_minutes: 5`

**Full proof bundle generated:** YES (this is what the generator must produce)

---

## 5. Expected Verifier Checks

The verifier must perform **six checks** and all must pass for `status: VALID`:

| # | Check | Layer | What it verifies |
|---|---|---|---|
| 1 | `pon_quorum_integrity` | PoN | REGULATOR or ETHICS_BOARD in ACCEPT votes; weight threshold met |
| 2 | `poe_chain_monotonicity` | PoE | CV_2.previous_hash matches CV_1.hash; no version deleted |
| 3 | `poo_signature_valid` | PoO | Ed25519 signature verifies against operator public key |
| 4 | `por_logic_consistency` | PoR | Conclusions follow from premises via declared rules in CV_2 |
| 5 | `poc_conflict_completeness` | PoC | Detected conflict is documented; not silenced; resolution protocol valid |
| 6 | `merkle_root_match` | All | Computed Merkle root over all proof hashes equals stored root |

**If any check fails:** `status: INVALID` with specific `checks_failed` list.

---

## 6. What This Test Does NOT Cover

(Per the foundation document's Section 4 — "What We Do NOT Claim")

This test will produce a valid proof bundle. It will **not**:

1. Prove that C1, C2, C3 are morally correct triage rules
2. Prove that the LEXICOGRAPHIC protocol is the right way to resolve urgency/fairness tension
3. Prove that the negotiation participants are *legitimately* representative
4. Prove that the priority assignment is clinically optimal
5. Test scalability, latency, or any performance metric

It will **only** prove: *given a properly negotiated and evolved constraint set, the framework can produce a cryptographically verifiable record of a decision and any conflicts encountered.*

This is the operational answer to Reviewer 1's "thought experiment" critique.

---

## 7. Success Criteria for This Test

The test passes if:

✓ The generator produces a JSON bundle conforming to the schema in `oplogica_v2_foundation.md` §5
✓ The bundle includes all 5 proof layers (PoO, PoR, PoN, PoC, PoE)
✓ The bundle includes a Merkle root computed over all layer hashes
✓ The independent verifier reads the bundle and returns `status: VALID`
✓ Tampering with any single field in the bundle causes the verifier to return `status: INVALID`
✓ All prototype components (Ed25519) are explicitly tagged as prototype

---

**End of Scenario Specification**
