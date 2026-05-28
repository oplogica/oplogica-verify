# Limitations

This is a demonstration over a Python reference implementation. The list below
states the boundaries explicitly; they are findings, not footnotes.

## Explicit non-claims

A verifying ("VALID") bundle does **not** establish any of the following:

- **Decision correctness.** The verifier says nothing about whether the recorded
  decision was right.
- **Model fairness.** It makes no statement about bias or fairness of any model.
- **Legal or regulatory compliance.** It is not a compliance determination and
  is not a legal opinion.
- **Clinical or medical correctness.** The triage scenario is synthetic; this is
  not clinical advice and not a medical device.
- **Production readiness.** It is a demo and is not intended for critical
  deployment.

## Scope boundaries of specific checks

- **Conflict records (`poc_record_integrity`).** Confirms that *recorded*
  conflicts remain visible and intact (none silenced, recognized resolution
  protocols). It does **not** establish that every conflict which should have
  been detected was recorded. Completeness of conflict capture is out of scope.
- **Reasoning (`por_structural_consistency`, `por_signature_binding_valid`,
  `por_rule_policy_binding`).** Confirm that the recorded reasoning graph is well
  formed, authenticated, bound to the operation, and that its rules map to the
  active policy's constraints. They do **not** establish that the reasoning is
  sound, that its conclusions are true, or that it constitutes a formal
  entailment.
- **Input binding (`poo_signature_valid`).** Confirms the operation signature
  and that the supplied raw input hashes to the recorded input hash. It does
  **not** establish that the input data was true. The raw input is not embedded
  in the bundle (only its hash); the verifier requires the input to be supplied
  separately. If the input is withheld, this check is reported as **failed**
  with an explicit reason ("No expected_input_data provided.") — it never
  silently passes.

## Cryptographic constraints

- **Signatures** are Ed25519, tagged `Ed25519-prototype-2026`. They are **not**
  post-quantum. The production target ML-DSA (Dilithium-III, FIPS 204) is
  declared in the code but not implemented.
- **Merkle tree** is a simple binary tree (last node duplicated on odd count).
  It does **not** implement the RFC 6962 (Certificate Transparency)
  construction.
- **Keys** are demo keys, not HSM-backed and not production PKI. No resistance to
  key compromise is claimed.

## Implementation constraints

- Python reference implementation only. **Go/Rust SDKs do not exist.**
- The engine returns a hardcoded `checks_total = 13`; on some failing inputs two
  reasoning-nested checks short-circuit and never emit. The demo's
  reconciliation layer surfaces those as `not_run` (named, with reasons) so the
  reported counts always sum to 13. See `docs/ARCHITECTURE.md`.

## Wording discipline

The project avoids absolute-coverage percentage phrasing. Test status is stated
concretely (for example, "all included tests currently pass"). See the README
"Scope discipline" section.
