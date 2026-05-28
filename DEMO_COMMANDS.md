# OVA Demo — Commands

A runnable, deliberately honest demo of the OVA evidence-integrity verifier.
It does not build an API or dashboard, and it deploys nothing.

> **Synthetic medical triage scenario.** Not clinical advice. Not a medical
> device. Not validated for clinical use. Data is illustrative and fabricated
> for demo purposes. Demo keys only — not HSM-backed, not production PKI.

## Prerequisites

- Python 3.10+
- One dependency: `cryptography`

```bash
pip install cryptography
```

## Run the full demo (one command)

From the repository root:

```bash
python3 ova_demo/run_demo.py --out ./exports
```

This will:

1. generate a clean bundle, governance registry, trust root, and input data,
2. generate all 6 tampered bundles,
3. write `exports/tamper_manifest.json`,
4. write `exports/evidence_integrity_report.md`,

then print a summary: the reconciled clean-bundle status, the 6 tamper cases,
the report path, and reproduction commands.

## Verify the clean bundle

```bash
python3 ova_demo/verify_bundle.py exports/clean_bundle.json \
  --registry exports/registry.json \
  --trust-root exports/trust_root.json \
  --input-data exports/input_data.json
```

Expected: reconciled status **VALID**, 13 passed / 0 failed / 0 not run,
**exit code 0**.

## Verify the T4 tampered bundle

T4 adds a non-existent reference to a reasoning conclusion. It is the most
instructive case: one mutation causes two checks to **fail** and two more to be
reported as **not run** (surfaced explicitly, never silently dropped).

```bash
python3 ova_demo/verify_bundle.py exports/tampered_T4_por.json \
  --registry exports/registry.json \
  --trust-root exports/trust_root.json \
  --input-data exports/input_data.json
```

Expected: reconciled status **INVALID**, 9 passed / 2 failed / 2 not run,
**exit code 1**. The two failed checks are `por_structural_consistency` (the
dangling reference) and `merkle_root_match` (cascading). The two not-run checks
are `por_signature_binding_valid` and `por_rule_policy_binding`, which the
engine short-circuits past — the reconciliation layer reports them by name with
a reason instead of letting them disappear.

## Exit codes (verify_bundle.py)

| Code | Meaning |
|-----:|---------|
| 0    | reconciled VALID |
| 1    | reconciled INVALID (failed and/or not-run and/or unexpected checks) |
| 2    | usage / file-not-found / JSON-parse / structural error |

## What the result means — and does not mean

```
13/13 integrity checks passed.
Meaning: the evidence bundle is internally consistent and tamper-evident under
the demo trust root.
Not meaning: the AI decision is medically correct, unbiased, or legally
compliant.
```

More fully:

- **What a VALID result shows.** The recorded evidence bundle was not silently
  altered after generation; the governing policy version, the executed
  operation, and the recorded reasoning bind together; signatures verify under
  the demo trust root; and the recomputed Merkle root matches the stored one.
- **What it does not show.** It does not show that the decision was correct,
  that any model behaves fairly, that any institution meets a legal obligation,
  or that this system is fit for real-world critical use. The conflict check
  confirms that *recorded* conflicts stay visible and intact — not that every
  conflict that should have been detected was recorded. The reasoning checks
  confirm the recorded reasoning graph is well formed, authenticated, and bound
  to the policy and operation — not that the reasoning is sound, true, or a
  formal entailment.
- **Threat model.** Tamper-evidence is relative to an adversary who modifies
  the bundle *after* generation. It does not address false input entered before
  generation, a bad policy approved through legitimate channels, key
  compromise, or collusion among authorized signers.

## Tests

```bash
python3 tests/test_reconcile.py
python3 tests/test_cli.py
python3 tests/test_check_explanations.py
python3 tests/test_tamper_examples.py
python3 tests/test_report_generator.py
python3 tests/test_run_demo.py
```
