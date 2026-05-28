"""Generate the human-readable Evidence Integrity Report (Markdown).

Consumes the reconciled tamper manifest (exports/tamper_manifest.json) plus the
clean inputs it references, re-verifies the clean bundle through the offline
verify -> reconcile path, and writes exports/evidence_integrity_report.md.

Every count rendered in this report comes from a reconciled result (passed /
failed / not_run summing to the canonical 13). The engine's raw, hardcoded
checks_total is never rendered directly.

Scope: this report concerns evidence integrity and binding under the demo trust
root. It is not a Compliance Report and makes no statement about clinical
correctness, model behaviour, legal obligations, or production readiness.
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
from ova_demo.checks import reconcile


REPORT_TITLE = "OVA Evidence Integrity Report"

SYNTHETIC_BANNER = (
    "**Synthetic medical triage scenario.** Not clinical advice. Not a medical "
    "device. Not validated for clinical use. Data is illustrative and "
    "fabricated for demo purposes."
)

# The fixed meaning / not-meaning block. Rendered verbatim wherever a check
# fraction appears. The numerator is filled in per result; the denominator is
# the reconciled total.
def _meaning_block(n_passed: int, n_total: int) -> str:
    return (
        f"> {n_passed}/{n_total} integrity checks passed.\n"
        f">\n"
        f"> Meaning: the evidence bundle is internally consistent and "
        f"tamper-evident under the demo trust root.\n"
        f">\n"
        f"> Not meaning: the AI decision is medically correct, unbiased, or "
        f"legally compliant."
    )


DEMO_KEY_NOTE = (
    "These are **demo keys only**. Not HSM-backed, not production PKI, and no "
    "claim of resistance to key compromise is made. Signatures use "
    "Ed25519-prototype-2026; the production target ML-DSA (Dilithium-III, "
    "FIPS 204) is declared but not implemented. The trust root is a demo "
    "anchor generated for this run; its public part is shipped to the verifier "
    "independently of any bundle, and the verifier never recovers the trust "
    "root from the registry it is inspecting."
)

SCOPE_STATEMENT = (
    "This report concerns **evidence integrity and binding only**: whether the "
    "recorded artifacts are authentic, internally consistent, and untampered "
    "under the demo trust root, and whether the governing policy, the executed "
    "operation, and the recorded reasoning bind together. A verifying bundle "
    "shows that the record was not silently altered after generation. It does "
    "not show that the decision was correct, that any model behaves fairly, "
    "that any institution meets a legal obligation, or that this system is fit "
    "for real-world critical use."
)


def _load_json(path: str) -> object:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _verify_clean(manifest: dict) -> dict:
    """Re-verify the clean bundle through the offline path and reconcile."""
    clean = manifest["clean_inputs"]
    bundle = _load_json(os.path.join(_ROOT, clean["bundle"]))
    registry = _load_json(os.path.join(_ROOT, clean["registry"]))
    trust_root = _load_json(os.path.join(_ROOT, clean["trust_root"]))
    input_data = _load_json(os.path.join(_ROOT, clean["input_data"]))

    raw = engine.verify_bundle(
        bundle,
        expected_input_data=input_data,
        governance_registry=registry,
        trusted_root_public_key=trust_root["trusted_root_public_key"],
        allowed_registry_hashes=set(trust_root["allowed_registry_hashes"]),
    )
    return reconcile(raw)


def _render_check_list(items: list[dict], kind: str) -> list[str]:
    """Render failed or not_run check entries with reasons."""
    lines: list[str] = []
    if not items:
        lines.append(f"_No {kind} checks._")
        return lines
    for item in items:
        lines.append(f"- **{item['check']}**")
        reason = item.get("reason", "").strip()
        if reason:
            lines.append(f"  - reason: {reason}")
    return lines


def _render_explanations(expl_list: list[dict]) -> list[str]:
    lines: list[str] = []
    for e in expl_list:
        lines.append(f"- **{e['check']}**")
        if "meaning" in e:
            lines.append(f"  - meaning: {e['meaning']}")
            lines.append(f"  - failure means: {e['failure_means']}")
            lines.append(f"  - does not mean: {e['does_not_mean']}")
            fields = ", ".join(f"`{x}`" for x in e.get("fields_checked", []))
            if fields:
                lines.append(f"  - fields checked: {fields}")
        elif "note" in e:
            lines.append(f"  - note: {e['note']}")
    return lines


def _repro_commands(manifest: dict) -> tuple[str, str]:
    """Return (clean_cmd, tampered_cmd) reproduction command strings."""
    clean = manifest["clean_inputs"]
    clean_cmd = (
        "python3 ova_demo/verify_bundle.py "
        f"{clean['bundle']} "
        f"--registry {clean['registry']} "
        f"--trust-root {clean['trust_root']} "
        f"--input-data {clean['input_data']}"
    )
    # Use T4 as the tampered reproduction example (it shows failed + not_run).
    t4 = next(
        (c for c in manifest["cases"]
         if c["test_id"] == "T4_por_invalid_reference"),
        manifest["cases"][0],
    )
    tampered_cmd = (
        "python3 ova_demo/verify_bundle.py "
        f"{t4['tampered_bundle_path']} "
        f"--registry {clean['registry']} "
        f"--trust-root {clean['trust_root']} "
        f"--input-data {clean['input_data']}"
    )
    return clean_cmd, tampered_cmd


def build_report(manifest_path: str, out_path: str) -> str:
    manifest = _load_json(manifest_path)
    clean_rec = _verify_clean(manifest)

    L: list[str] = []
    a = L.append

    # --- Title + banners ---
    a(f"# {REPORT_TITLE}")
    a("")
    a(SYNTHETIC_BANNER)
    a("")
    a("## Scope")
    a("")
    a(SCOPE_STATEMENT)
    a("")
    a("## Demo keys and trust root")
    a("")
    a(DEMO_KEY_NOTE)
    a("")

    # --- Clean bundle summary ---
    a("## Clean bundle verification")
    a("")
    a(
        f"The clean bundle reconciles to **{clean_rec['status']}**: "
        f"{clean_rec['checks_passed_count']} passed, "
        f"{clean_rec['checks_failed_count']} failed, "
        f"{clean_rec['checks_not_run_count']} not run "
        f"(of {clean_rec['checks_total']} total)."
    )
    a("")
    a(_meaning_block(
        clean_rec["checks_passed_count"], clean_rec["checks_total"]
    ))
    a("")
    a("Checks passed on the clean bundle:")
    a("")
    for name in clean_rec["passed"]:
        a(f"- `{name}`")
    a("")

    # --- Tamper summary table ---
    a("## Tamper case summary")
    a("")
    a("Each tampered bundle below is a real file produced by applying one "
      "narrow mutation to the clean bundle, then re-verified offline. All "
      "counts are reconciled (passed + failed + not run = "
      f"{clean_rec['checks_total']}).")
    a("")
    a("| Test ID | Layer attacked | Status | Passed | Failed | Not run |")
    a("|---------|----------------|--------|-------:|-------:|--------:|")
    for c in manifest["cases"]:
        a(
            f"| {c['test_id']} | {c['layer_attacked']} | "
            f"{c['reconciled_status']} | {c['passed_count']} | "
            f"{c['failed_count']} | {c['not_run_count']} |"
        )
    a("")

    # --- Detailed sections ---
    a("## Tamper case details")
    a("")
    for c in manifest["cases"]:
        a(f"### {c['test_id']}")
        a("")
        a(f"- **Layer attacked:** {c['layer_attacked']}")
        a(f"- **Mutation:** {c['mutation_description']}")
        a(f"- **Tampered bundle:** `{c['tampered_bundle_path']}`")
        a(
            f"- **Reconciled status:** {c['reconciled_status']} "
            f"({c['passed_count']} passed, {c['failed_count']} failed, "
            f"{c['not_run_count']} not run, of {c['checks_total']} total)"
        )
        a("")
        a("**Failed checks:**")
        a("")
        L.extend(_render_check_list(c["failed_checks"], "failed"))
        a("")
        a("**Not-run checks:**")
        a("")
        L.extend(_render_check_list(c["not_run_checks"], "not-run"))
        a("")
        a("**Explanations (failed):**")
        a("")
        L.extend(_render_explanations(c["explanations"]["failed"]))
        a("")
        a("**Explanations (not run):**")
        a("")
        L.extend(_render_explanations(c["explanations"]["not_run"]))
        a("")

    # --- Reproduction ---
    clean_cmd, tampered_cmd = _repro_commands(manifest)
    a("## Reproduce these results")
    a("")
    a("Verify the clean bundle (expect reconciled VALID, exit code 0):")
    a("")
    a("```bash")
    a(clean_cmd)
    a("```")
    a("")
    a("Verify a tampered bundle (expect reconciled INVALID, exit code 1):")
    a("")
    a("```bash")
    a(tampered_cmd)
    a("```")
    a("")

    # --- Limitations ---
    a("## Limitations")
    a("")
    a("- This is a demo over a Python reference implementation. It is not "
      "described as fit for real-world critical deployment.")
    a("- The conflict check confirms that **recorded** conflicts remain "
      "visible and intact. It does **not** establish that every conflict "
      "which should have been detected was recorded; completeness of conflict "
      "capture is out of scope.")
    a("- The reasoning checks confirm that the recorded reasoning graph is "
      "well formed, authenticated, and bound to the operation and policy. "
      "They do **not** establish that the reasoning is sound, that its "
      "conclusions are true, or that it constitutes a formal entailment.")
    a("- Tamper-evidence is relative to a stated adversary who modifies the "
      "bundle **after** generation. It does not address false input entered "
      "before generation, a bad policy approved through legitimate channels, "
      "key compromise, or collusion among authorized signers.")
    a("- The Merkle tree is a simple binary tree and does not implement the "
      "RFC 6962 (Certificate Transparency) construction.")
    a("- Signatures are Ed25519-prototype-2026 and are not post-quantum; the "
      "production target ML-DSA (Dilithium-III, FIPS 204) is declared but not "
      "implemented.")
    a("")

    report = "\n".join(L) + "\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Evidence Integrity Report (Markdown)."
    )
    parser.add_argument(
        "--manifest",
        default=os.path.join(_ROOT, "exports", "tamper_manifest.json"),
        help="Path to tamper_manifest.json",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(_ROOT, "exports", "evidence_integrity_report.md"),
        help="Output Markdown path",
    )
    args = parser.parse_args()
    if not os.path.isfile(args.manifest):
        print(
            f"error: manifest not found: {args.manifest}\n"
            "Run: python3 ova_demo/tamper_examples.py --out ./exports",
            file=sys.stderr,
        )
        return 2
    path = build_report(args.manifest, args.out)
    print(f"Wrote report: {os.path.relpath(path, _ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
