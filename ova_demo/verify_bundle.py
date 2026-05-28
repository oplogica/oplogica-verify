#!/usr/bin/env python3
"""Standalone OFFLINE verifier CLI for OVA demo bundles.

This is the centerpiece of the demo: a skeptical auditor can run it on their
own machine, against a downloaded bundle, with no network access and without
trusting any Oplogica service. It loads the bundle, the governance registry,
and an INDEPENDENT trust-root file from disk, calls the vendored engine
verifier, routes the result through the reconciliation adapter, and prints a
legible report.

Offline guarantee
-----------------
This CLI makes no network calls. The vendored engine makes none either (it
uses only local hashing and Ed25519 signature math from the `cryptography`
library). The trust root is pinned from a file you supply, not fetched.

Trust-root independence
-----------------------
The trusted root public key and the allowed registry-hash set are loaded from
--trust-root, a file shipped to the verifier OUT OF BAND from the bundle. The
CLI deliberately does NOT recover the trust root from the registry under
inspection — doing so would let a fabricated registry supply its own trust
root and defeat pinning entirely (brief §5C).

Exit codes
----------
  0  reconciled status VALID
  1  reconciled status INVALID (failed and/or not_run and/or unexpected checks)
  2  usage / file-not-found / JSON-parse / structural error

Scope (printed on every run, never omitted)
--------------------------------------------
A VALID result means the evidence bundle is internally consistent and
tamper-evident under the demo trust root. It does NOT mean the AI decision is
medically correct, unbiased, or legally compliant. This CLI does not assert
regulatory compliance, clinical correctness, model fairness, or
production-grade readiness, and never reports a bare percentage.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo.checks import ALL_CHECKS, reconcile


EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


# The mandatory meaning / not-meaning block. This text is fixed and must
# accompany any rendering of the check results. The CLI prints it on EVERY
# run, pass or fail.
MEANING_BLOCK = (
    "{n_passed}/{n_total} integrity checks passed.\n"
    "Meaning: the evidence bundle is internally consistent and "
    "tamper-evident under the demo trust root.\n"
    "Not meaning: the AI decision is medically correct, unbiased, or "
    "legally compliant."
)

SYNTHETIC_BANNER = (
    "Synthetic medical triage scenario. Not clinical advice. Not a medical "
    "device.\nNot validated for clinical use. Data is illustrative and "
    "fabricated for demo purposes."
)

DEMO_KEYS_NOTE = (
    "Demo keys only. Not HSM-backed, not production PKI. No claim of "
    "resistance to key compromise. Ed25519-prototype-2026; production target "
    "ML-DSA (Dilithium-III, FIPS 204) is declared but not implemented."
)


class CliError(Exception):
    """Raised for usage / file / JSON / structural errors -> exit code 2."""


def _load_json(path: str, label: str) -> object:
    if not os.path.isfile(path):
        raise CliError(f"{label} file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise CliError(f"{label} is not valid JSON ({path}): {e}")
    except OSError as e:
        raise CliError(f"Cannot read {label} ({path}): {e}")


def _extract_trust_material(trust_root_obj: object) -> tuple[str, set[str]]:
    if not isinstance(trust_root_obj, dict):
        raise CliError("trust-root file must be a JSON object.")
    root_key = trust_root_obj.get("trusted_root_public_key")
    allowed = trust_root_obj.get("allowed_registry_hashes")
    if not isinstance(root_key, str) or not root_key:
        raise CliError(
            "trust-root file missing string 'trusted_root_public_key'."
        )
    if not isinstance(allowed, list) or not all(
        isinstance(h, str) for h in allowed
    ):
        raise CliError(
            "trust-root file missing list 'allowed_registry_hashes' of "
            "strings."
        )
    return root_key, set(allowed)


def run(bundle_path: str, registry_path: str, trust_root_path: str,
        input_data_path: str | None) -> dict:
    """Load inputs, verify, reconcile. Returns the reconciled dict.

    Raises CliError for usage/file/JSON/structural problems (exit code 2).
    """
    bundle = _load_json(bundle_path, "bundle")
    registry = _load_json(registry_path, "registry")
    trust_root_obj = _load_json(trust_root_path, "trust-root")

    if not isinstance(bundle, dict):
        raise CliError("bundle file must be a JSON object.")
    if not isinstance(registry, dict):
        raise CliError("registry file must be a JSON object.")

    trusted_root_key, allowed_hashes = _extract_trust_material(trust_root_obj)

    expected_input_data = None
    if input_data_path is not None:
        expected_input_data = _load_json(input_data_path, "input-data")

    # Call the vendored engine verifier with EXPLICIT, independently-supplied
    # trust material. We never let the engine fall back to its module-level
    # pins here, and we never recover the trust root from `registry`.
    try:
        raw = engine.verify_bundle(
            bundle,
            expected_input_data=expected_input_data,
            governance_registry=registry,
            trusted_root_public_key=trusted_root_key,
            allowed_registry_hashes=allowed_hashes,
        )
    except Exception as e:  # structural problems in the bundle, etc.
        raise CliError(
            f"Verifier could not process the bundle: {type(e).__name__}: {e}"
        )

    return reconcile(raw)


def _print_report(rec: dict, input_data_provided: bool) -> None:
    line = "=" * 70
    print(line)
    print(" OVA Offline Verifier — Evidence Integrity (demo)")
    print(line)
    print(SYNTHETIC_BANNER)
    print()
    print(DEMO_KEYS_NOTE)
    print()
    print(f"Reconciled status: {rec['status']}")
    print(
        f"Checks: {rec['checks_passed_count']} passed, "
        f"{rec['checks_failed_count']} failed, "
        f"{rec['checks_not_run_count']} not run "
        f"(of {rec['checks_total']} total)"
    )
    print()

    if rec["passed"]:
        print(f"PASSED ({rec['checks_passed_count']}):")
        for name in rec["passed"]:
            print(f"  [pass] {name}")
        print()

    if rec["failed"]:
        print(f"FAILED ({rec['checks_failed_count']}):")
        for entry in rec["failed"]:
            print(f"  [FAIL] {entry['check']}")
            print(f"         reason: {entry.get('reason', '(none)')}")
        print()

    if rec["not_run"]:
        print(f"NOT RUN ({rec['checks_not_run_count']}):")
        for entry in rec["not_run"]:
            print(f"  [skip] {entry['check']}")
            print(f"         reason: {entry.get('reason', '(none)')}")
        print()

    if rec["unexpected"]:
        print(f"UNEXPECTED CHECK NAMES (not in canonical 13): "
              f"{rec['unexpected']}")
        print("  These were emitted by the engine but are not registered in "
              "ALL_CHECKS. Treated as a reason to withhold a VALID result.")
        print()

    if not input_data_provided:
        print("Note: no --input-data was supplied, so any check that binds to "
              "the raw decision input (e.g. poo_signature_valid) cannot be "
              "evaluated and is reported above as FAILED with the reason 'No "
              "expected_input_data provided.' This is expected when the "
              "sensitive input is withheld; such a failure is not by itself a "
              "tampering signal. Supply --input-data to evaluate that check.")
        print()

    # The mandatory meaning / not-meaning block — printed on every run.
    print(line)
    print(MEANING_BLOCK.format(
        n_passed=rec["checks_passed_count"],
        n_total=rec["checks_total"],
    ))
    print(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline OVA bundle verifier (demo). Verifies a proof bundle "
            "against an independently-supplied trust root and prints a "
            "reconciled Evidence Integrity result. Does not assert "
            "compliance, clinical correctness, model fairness, or "
            "production-grade readiness."
        )
    )
    parser.add_argument("bundle", help="Path to the bundle JSON.")
    parser.add_argument(
        "--registry", required=True,
        help="Path to the governance registry JSON.",
    )
    parser.add_argument(
        "--trust-root", required=True,
        help="Path to the independent trust-root JSON "
             "(trusted_root_public_key + allowed_registry_hashes).",
    )
    parser.add_argument(
        "--input-data", default=None,
        help="Optional path to the raw decision input JSON. Required for "
             "checks that bind to the input (e.g. poo_signature_valid). "
             "If omitted, those checks are reported as NOT RUN.",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        # argparse already printed usage; normalize to our usage exit code.
        return EXIT_USAGE

    try:
        rec = run(
            args.bundle, args.registry, args.trust_root, args.input_data
        )
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    _print_report(rec, input_data_provided=args.input_data is not None)

    return EXIT_VALID if rec["status"] == "VALID" else EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
