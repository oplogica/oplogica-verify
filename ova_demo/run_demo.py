"""Run the full OVA demo pipeline in one command.

Pipeline (all over the already-tested honest core path):
  1. generate clean bundle / registry / trust_root / input_data
  2. generate all 6 tampered bundles
  3. generate tamper_manifest.json
  4. generate evidence_integrity_report.md

This orchestrator adds NO verification logic of its own. It sequences the
existing, tested modules and prints a concise summary. The clean-bundle status
shown in the summary is taken from a reconciled result, never a raw engine
count. It does not build an API or dashboard and does not deploy anything.

Scope reminder: a verifying bundle demonstrates evidence integrity and binding
under the demo trust root. It does not establish clinical correctness, model
behaviour, legal obligations, or production readiness. Demo keys only.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import contextlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo import generate_bundle
from ova_demo import tamper_examples
from ova_demo import report_generator
from ova_demo.checks import reconcile


EXIT_OK = 0
EXIT_ERROR = 1


class DemoError(Exception):
    """Controlled pipeline failure -> non-zero exit."""


def _reconciled_clean_status(out_dir: str, manifest: dict) -> dict:
    """Verify the clean bundle through the offline path and reconcile, so the
    summary reflects a reconciled result rather than a raw engine count."""
    clean = manifest["clean_inputs"]

    def _load(rel: str):
        path = os.path.join(_ROOT, rel)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    bundle = _load(clean["bundle"])
    registry = _load(clean["registry"])
    trust_root = _load(clean["trust_root"])
    input_data = _load(clean["input_data"])

    raw = engine.verify_bundle(
        bundle,
        expected_input_data=input_data,
        governance_registry=registry,
        trusted_root_public_key=trust_root["trusted_root_public_key"],
        allowed_registry_hashes=set(trust_root["allowed_registry_hashes"]),
    )
    return reconcile(raw)


def run(out_dir: str) -> dict:
    """Execute the full pipeline. Returns a result dict with paths + summary.

    Raises DemoError on any controlled failure.
    """
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        raise DemoError(f"Cannot create output directory '{out_dir}': {e}")

    # 1-3: clean artifacts + tampered bundles + manifest. tamper_examples.build
    # internally calls generate_bundle.generate, so this single call produces
    # the clean inputs AND the 6 tampered bundles AND the manifest.
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            manifest = tamper_examples.build(out_dir)
    except Exception as e:
        raise DemoError(
            f"Failed during bundle/tamper generation: {type(e).__name__}: {e}"
        )

    manifest_path = os.path.join(out_dir, "tamper_manifest.json")
    if not os.path.isfile(manifest_path):
        raise DemoError("Manifest was not written.")

    # 4: report.
    report_path = os.path.join(out_dir, "evidence_integrity_report.md")
    try:
        report_generator.build_report(manifest_path, report_path)
    except Exception as e:
        raise DemoError(
            f"Failed during report generation: {type(e).__name__}: {e}"
        )
    if not os.path.isfile(report_path):
        raise DemoError("Report was not written.")

    # Reconciled clean status for the summary.
    try:
        clean_rec = _reconciled_clean_status(out_dir, manifest)
    except Exception as e:
        raise DemoError(
            f"Failed to verify clean bundle: {type(e).__name__}: {e}"
        )

    # Reproduction commands.
    clean = manifest["clean_inputs"]
    clean_cmd = (
        "python3 ova_demo/verify_bundle.py "
        f"{clean['bundle']} --registry {clean['registry']} "
        f"--trust-root {clean['trust_root']} --input-data {clean['input_data']}"
    )
    t4 = next(
        (c for c in manifest["cases"]
         if c["test_id"] == "T4_por_invalid_reference"),
        manifest["cases"][0],
    )
    t4_cmd = (
        "python3 ova_demo/verify_bundle.py "
        f"{t4['tampered_bundle_path']} --registry {clean['registry']} "
        f"--trust-root {clean['trust_root']} --input-data {clean['input_data']}"
    )

    return {
        "out_dir": out_dir,
        "manifest_path": os.path.relpath(manifest_path, _ROOT),
        "report_path": os.path.relpath(report_path, _ROOT),
        "clean_status": clean_rec["status"],
        "clean_passed": clean_rec["checks_passed_count"],
        "clean_failed": clean_rec["checks_failed_count"],
        "clean_not_run": clean_rec["checks_not_run_count"],
        "clean_total": clean_rec["checks_total"],
        "tamper_cases": [
            {
                "test_id": c["test_id"],
                "status": c["reconciled_status"],
                "passed": c["passed_count"],
                "failed": c["failed_count"],
                "not_run": c["not_run_count"],
            }
            for c in manifest["cases"]
        ],
        "clean_cmd": clean_cmd,
        "t4_cmd": t4_cmd,
    }


def _print_summary(result: dict) -> None:
    line = "=" * 70
    print(line)
    print(" OVA demo pipeline — complete")
    print(line)
    print(
        f"Clean bundle: {result['clean_status']} "
        f"({result['clean_passed']} passed, {result['clean_failed']} failed, "
        f"{result['clean_not_run']} not run, of {result['clean_total']} total)"
    )
    print()
    print(f"Tamper cases generated: {len(result['tamper_cases'])}")
    for c in result["tamper_cases"]:
        print(
            f"  {c['test_id']:28s} -> {c['status']:7s} "
            f"({c['passed']} passed, {c['failed']} failed, "
            f"{c['not_run']} not run)"
        )
    print()
    print(f"Manifest: {result['manifest_path']}")
    print(f"Report:   {result['report_path']}")
    print()
    print("Reproduce — verify the clean bundle (expect VALID, exit 0):")
    print(f"  {result['clean_cmd']}")
    print()
    print("Reproduce — verify the T4 tampered bundle (expect INVALID, exit 1):")
    print(f"  {result['t4_cmd']}")
    print()
    print(line)
    print(
        f" {result['clean_passed']}/{result['clean_total']} integrity checks "
        "passed on the clean bundle."
    )
    print(" Meaning: the evidence bundle is internally consistent and "
          "tamper-evident under the demo trust root.")
    print(" Not meaning: the AI decision is medically correct, unbiased, or "
          "legally compliant.")
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the full OVA demo pipeline (no API, no deploy)."
    )
    parser.add_argument(
        "--out", default=os.path.join(_ROOT, "exports"),
        help="Output directory (default: ./exports)",
    )
    args = parser.parse_args()

    try:
        result = run(args.out)
    except DemoError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    _print_summary(result)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
