# Threat Model

Tamper detection is only meaningful relative to a stated adversary. This demo
makes a narrow, explicit claim: **post-generation tampering within the capture
boundary is detectable by recomputation under the demo trust root.**

## The demo assumes the attacker MAY

- Modify bundle JSON after generation.
- Replace the policy hash.
- Edit reasoning text after signing.
- Delete or alter conflict records.
- Reorder or rewrite timestamps.
- Swap policy-version references.
- Attempt to reuse a valid signature from another bundle.
- Present a fabricated or unsigned governance registry.
- Graft votes that approved one policy version onto execution of another, or
  replay votes from a different epoch.

The verifier is designed to detect these by recomputing hashes, the Merkle
root, and signature validity from primitives, resolving participant and operator
keys from a registry that must itself be signed by the pinned trust root and
whose content hash must be in a pinned allow-list.

## The demo does NOT claim to stop

- False input data entered **before** bundle generation (garbage in).
- A malicious institution approving a bad policy through legitimate channels.
- A model producing a factually or clinically wrong output.
- Private-key compromise.
- Collusion among authorized signers who jointly meet quorum.
- Runtime attacks outside the evidence-capture boundary.

## Trust root

The trust root is a **demo anchor**, generated for the demo run, with its public
part supplied to the verifier independently of any bundle (see
`trust_root.json`). The verifier never recovers the trust root from the registry
it is inspecting. Keys are demo keys only: not HSM-backed, not production PKI,
with no claim of resistance to key compromise.

## Why this framing matters

Without an explicit adversary statement, "tamper detection" would imply "we
prevent tampering" in general, which is an overclaim. The honest claim is
narrow and recomputation-based, and it is bounded by the assumptions above.
