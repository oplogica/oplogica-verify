# Architecture

This document describes the components and the data flow. For scope and
non-claims see `LIMITATIONS.md`; for the adversary model see `THREAT_MODEL.md`.

## Components

### `ova_engine/` — the verification engine (read-only authority)

`ova_v2.py` is the vendored engine. It generates a five-layer proof bundle and
verifies it by recomputing integrity claims from primitive records. The demo
treats this file as authoritative and does not modify it. `__init__.py`
re-exports the pieces the demo needs: `verify_bundle`, `run_triage_scenario`,
`GOVERNANCE_REGISTRY_V1`, `GOVERNANCE_REGISTRY_V1_HASH`,
`TRUSTED_REGISTRY_ROOT_PUBLIC_KEY`, `ALLOWED_REGISTRY_HASHES`.

The five proof layers:

| Layer | Meaning |
|-------|---------|
| PoN (Proof of Negotiation) | how the governing consensus was reached (quorum, signed votes) |
| PoE (Proof of Evolution) | the append-only policy-version chain |
| PoO (Proof of Operation) | what the system did, bound to the active policy hash |
| PoR (Proof of Reason) | recorded reasoning, linked to policy constraints |
| PoC (Proof of Conflict) | conflicts recorded rather than silently dropped |

These are bound by a Merkle root over the five layer hashes.

### The 13 checks

The verifier emits these check names (canonical order):

```
registry_signature_valid            registry_temporal_validity
pon_quorum_integrity                pon_vote_signatures_valid
poe_chain_monotonicity             policy_hash_consistency
policy_consensus_execution_binding poo_signature_valid
por_signature_binding_valid        por_rule_policy_binding
por_structural_consistency         poc_record_integrity
merkle_root_match
```

### `ova_demo/` — packaging layer

- **`checks.py`** — `ALL_CHECKS` (the canonical 13) and `reconcile()`. The
  engine hardcodes `checks_total = 13`, but on some failing inputs two
  reasoning-nested checks short-circuit and never emit. `reconcile()` partitions
  the canonical 13 into `passed` / `failed` / `not_run` (each named, with a
  reason) so the three buckets always sum to 13. It computes the total from
  `len(ALL_CHECKS)`, never from the engine's literal.
- **`generate_bundle.py`** — runs the engine scenario and writes
  `clean_bundle.json`, `registry.json`, `trust_root.json`, and `input_data.json`
  to an output directory. The trust root is written to its **own** file so the
  verifier can pin to it independently of the registry under inspection.
- **`verify_bundle.py`** — the standalone offline CLI. Loads bundle, registry,
  and trust root from disk; calls the engine verifier with explicit,
  independently supplied trust material; routes through `reconcile()`; prints a
  legible report with the mandatory meaning/not-meaning block. Exit codes:
  0 (VALID), 1 (INVALID), 2 (usage/file/JSON error).
- **`tamper_examples.py`** — applies the six canonical one-field mutations to a
  fresh clean bundle, writes the real tampered bundle files, verifies and
  reconciles each, and emits `tamper_manifest.json` with explanations attached.
- **`check_explanations.py`** — an auditor-readable registry: for each check, a
  `meaning`, `fields_checked`, `failure_means`, and `does_not_mean`.
- **`report_generator.py`** — renders the human-readable
  `evidence_integrity_report.md` from the manifest plus a re-verified clean
  bundle.
- **`run_demo.py`** — the one-command orchestrator over the above.

### `api/` — thin HTTP wrapper

`server.py` exposes `GET /health` and `POST /verify` over the same
`verify -> reconcile` path. The request body carries `bundle`, `registry`,
`trust_root`, and optional `input_data`. The response contains only reconciled
fields plus the meaning/not-meaning block and a scope warning. The raw engine
result is never surfaced. The app also mounts `ui/` at `/ui` as static files
(guarded: a no-op if the directory is absent).

### `ui/` — local dashboard

Static `index.html` + `app.js` + `style.css`. No build, no framework, no
storage. It calls `/health` and `/verify` same-origin. It can load the demo
inputs from `../exports/`, apply the T4 mutation client-side, and render the
reconciled result, always with the meaning/not-meaning block.

### `tests/` — one file per component

Every test runs the real engine; nothing is mocked. The suites cover
reconciliation, the CLI, explanations, tamper generation, the report, the
one-command pipeline, the API, and the dashboard.

## Data flow

```
run_demo.py
   └─ tamper_examples.build()
         └─ generate_bundle.generate()      → clean_bundle / registry /
         │                                     trust_root / input_data
         ├─ apply 6 one-field mutations      → tampered_T1..T6.json
         ├─ engine.verify_bundle(...)        (explicit, independent trust root)
         ├─ reconcile(...)                   → passed / failed / not_run (=13)
         ├─ attach check_explanations        → per-check meaning/does-not-mean
         └─ write tamper_manifest.json
   └─ report_generator.build_report()        → evidence_integrity_report.md

verify_bundle.py / api /verify / ui          → same engine.verify_bundle ->
                                               reconcile path
```

## Trust-root independence

The engine bootstraps a fresh random trust anchor per process, and the registry
payload embeds its own root public key. A verifier could therefore recover the
trust root from the registry it is checking — but that would let a fabricated
registry supply its own trust root and defeat pinning. To avoid this, the
generator writes the trust root to a separate `trust_root.json`, and every
verification path pins to that file (or to the trust material in the request
body), never to a root recovered from the registry under inspection.
