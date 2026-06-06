# Repository, Hosted Demo, and Future Product

This document records the boundary between three distinct things so that readers
do not over-read the scope of this repository. It introduces no new claims.

---

## 1. This repository: the runnable local demo

The `oplogica-verify` repository contains a runnable, self-contained
implementation of the OVA evidence-integrity demo. It includes:

- the verification engine (`ova_v2.py`, vendored under `ova_engine/`),
- the demo packaging layer (`ova_demo/`: bundle generation, offline verify CLI,
  tamper examples, reconciliation, report generation, and a one-command runner),
- local web code: a thin HTTP API (`api/server.py`) and a static dashboard
  (`ui/`) that run on your own machine,
- the test suite (`tests/`),
- example and exported JSON artifacts, plus documentation (`docs/`) and
  `LICENSE` / `NOTICE`.

You can run all of it locally from the command line, including the local
dashboard and API. What it verifies is deliberately scoped: deterministic,
tamper-evident integrity of evidence bundles around recorded AI decision
artifacts (rule provenance, governance binding, signature authenticity, and
Merkle integrity). It does not establish decision correctness, fairness,
clinical validity, legal or regulatory sufficiency, or formal semantic
entailment. The explicit non-claims are listed in the README and in the
per-bundle `verification_scope`.

## 2. The hosted public demo

The interactive demo at `oplogica.com/ova-demo` is a separately operated
deployment of this demo. It is hosted and maintained independently of any
repository checkout, so its availability, configuration, deployment
environment, and exact hosted state may differ from what is in this repository
at any given commit. Treat the hosted site as a convenience for trying the demo,
not as a description of the code in your checkout.

## 3. Future production product

A production product is not represented by this repository or by the hosted
demo. Both are a proof-of-concept demonstration. A production deployment would
require work beyond what is demonstrated here (see the README's future-work
notes). Claims of production readiness, compliance certification, or regulatory
acceptance are not made here and should not be inferred.

---

## Summary

| Thing | Where it lives | In this repository? |
|---|---|---|
| Runnable local demo (engine, demo layer, local API/dashboard, tests, artifacts, docs) | this repository | Yes |
| Hosted public demo (`oplogica.com/ova-demo`) | separately operated deployment | No (built from this demo, run and maintained separately) |
| Future production product | not yet built | No |
