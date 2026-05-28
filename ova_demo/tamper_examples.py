"""Generate real tampered bundle files for the 6 canonical tamper cases.

For each case we:
  1. start from a freshly generated clean bundle,
  2. apply ONE narrow mutation (mirroring the engine's own tamper_* mutations,
     ova_v2.py lines ~2071-2259, but applied here so we keep the real mutated
     bundle as a file),
  3. write the tampered bundle JSON to disk,
  4. run the offline verifier (engine.verify_bundle with explicit, independently
     supplied trust material — never recovered from the registry under
     inspection),
  5. pass the raw verifier output through reconcile(),
  6. attach explanation snippets from check_explanations for every failed and
     not_run check,
  7. record everything in a machine-readable manifest.

We do NOT use the engine's tamper_* wrapper return values as the artifact: those
wrappers verify internally and return a report, not the mutated bundle. The demo
needs actual mutated bundle files plus the real reconciled result, so we
reproduce the mutations directly.

Scope: a tampered bundle verifying as INVALID demonstrates post-generation
tamper-evidence under the demo trust root. It says nothing about clinical
correctness, model behaviour, legal obligations, or production readiness.
These are DEMO keys only; not HSM-backed, not production PKI.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo import generate_bundle
from ova_demo.checks import reconcile
from ova_demo.check_explanations import get_explanation


# ----------------------------------------------------------------------
# The 6 canonical tamper mutations. Each takes a deep-copied clean bundle
# and applies exactly one narrow change. Mirrors the engine's tamper_*
# field mutations (kept minimal on purpose: the point is the engine's
# detection, not elaborate forgery).
# ----------------------------------------------------------------------

def _mutate_T1(b: dict) -> None:
    # Flip both critical voters (REGULATOR + ETHICS_BOARD) to REJECT.
    for v in b["constitutional_layer"]["pon"]["votes"]:
        if v["participant_id"] in (
            "regulator-MOH-TR-01", "ethics-board-IST-04"
        ):
            v["vote"] = "REJECT"


def _mutate_T2(b: dict) -> None:
    # Break the previous_version_hash link in the policy-evolution chain.
    b["constitutional_layer"]["poe"]["versions"][1][
        "previous_version_hash"
    ] = "sha256:" + "f" * 64


def _mutate_T3(b: dict) -> None:
    # Replace the operation's recorded input_data_hash with zeros.
    b["operational_layer"]["poo"]["input_data_hash"] = "sha256:" + "0" * 64


def _mutate_T4(b: dict) -> None:
    # Add a non-existent reference to a conclusion's derivation list.
    b["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
        "p1", "p2", "r1", "p_GHOST"
    ]


def _mutate_T5(b: dict) -> None:
    # Silence a recorded conflict.
    b["operational_layer"]["poc"]["conflicts"][0]["silenced"] = True


def _mutate_T6(b: dict) -> None:
    # Swap the stored Merkle root directly, leaving the five layers intact.
    b["merkle_root"] = "sha256:" + "1" * 64


_TAMPER_CASES: list[dict[str, object]] = [
    {
        "test_id": "T1_pon_break_quorum_axiom",
        "layer_attacked": "PoN (negotiation quorum)",
        "mutation_description": (
            "Flipped both critical-acceptor votes (REGULATOR and "
            "ETHICS_BOARD) from ACCEPT to REJECT."
        ),
        "mutate": _mutate_T1,
        "filename": "tampered_T1_pon.json",
    },
    {
        "test_id": "T2_poe_break_chain_link",
        "layer_attacked": "PoE (policy-evolution chain)",
        "mutation_description": (
            "Replaced the second version's previous_version_hash with an "
            "arbitrary value, breaking the chain link."
        ),
        "mutate": _mutate_T2,
        "filename": "tampered_T2_poe.json",
    },
    {
        "test_id": "T3_poo_change_input_hash",
        "layer_attacked": "PoO (operation record)",
        "mutation_description": (
            "Replaced the operation's input_data_hash with an all-zero hash."
        ),
        "mutate": _mutate_T3,
        "filename": "tampered_T3_poo.json",
    },
    {
        "test_id": "T4_por_invalid_reference",
        "layer_attacked": "PoR (reasoning graph)",
        "mutation_description": (
            "Added a non-existent reference ('p_GHOST') to a conclusion's "
            "derived_from list."
        ),
        "mutate": _mutate_T4,
        "filename": "tampered_T4_por.json",
    },
    {
        "test_id": "T5_poc_silence_conflict",
        "layer_attacked": "PoC (conflict record)",
        "mutation_description": (
            "Marked a recorded conflict as silenced."
        ),
        "mutate": _mutate_T5,
        "filename": "tampered_T5_poc.json",
    },
    {
        "test_id": "T6_merkle_root_direct_swap",
        "layer_attacked": "Merkle root",
        "mutation_description": (
            "Replaced the stored Merkle root with an all-ones hash while "
            "leaving all five proof layers untouched."
        ),
        "mutate": _mutate_T6,
        "filename": "tampered_T6_merkle.json",
    },
]


def _explanation_snippet(check_name: str) -> dict[str, object]:
    """Return a compact explanation snippet for a check, or a clearly-marked
    fallback if the check is not in the canonical registry (should not happen
    for engine-emitted checks, but we never silently omit)."""
    try:
        e = get_explanation(check_name)
    except KeyError:
        return {
            "check": check_name,
            "note": (
                "No canonical explanation registered for this check name. "
                "It is reported verbatim and not interpreted."
            ),
        }
    return {
        "check": check_name,
        "meaning": e["meaning"],
        "failure_means": e["failure_means"],
        "does_not_mean": e["does_not_mean"],
        "fields_checked": e["fields_checked"],
    }


def build(out_dir: str) -> dict:
    """Generate clean artifacts, produce all 6 tampered bundles, verify and
    reconcile each, and write a manifest. Returns the manifest dict."""
    # 1. Fresh clean artifacts (bundle, registry, trust_root, input_data),
    #    all mutually consistent and produced in this process.
    paths = generate_bundle.generate(out_dir)
    with open(paths["bundle"], "r", encoding="utf-8") as f:
        clean_bundle = json.load(f)
    with open(paths["registry"], "r", encoding="utf-8") as f:
        registry = json.load(f)
    with open(paths["trust_root"], "r", encoding="utf-8") as f:
        trust_root = json.load(f)
    with open(paths["input_data"], "r", encoding="utf-8") as f:
        input_data = json.load(f)

    trusted_root_key = trust_root["trusted_root_public_key"]
    allowed_hashes = set(trust_root["allowed_registry_hashes"])

    entries = []
    for case in _TAMPER_CASES:
        tampered = copy.deepcopy(clean_bundle)
        case["mutate"](tampered)  # type: ignore[operator]

        tampered_path = os.path.join(out_dir, str(case["filename"]))
        with open(tampered_path, "w", encoding="utf-8") as f:
            json.dump(tampered, f, indent=2, ensure_ascii=False)

        # Real offline verification with explicit, independent trust material.
        raw = engine.verify_bundle(
            tampered,
            expected_input_data=input_data,
            governance_registry=registry,
            trusted_root_public_key=trusted_root_key,
            allowed_registry_hashes=allowed_hashes,
        )
        rec = reconcile(raw)

        failed_checks = [
            {"check": f["check"], "reason": f.get("reason", "")}
            for f in rec["failed"]
        ]
        not_run_checks = [
            {"check": n["check"], "reason": n.get("reason", "")}
            for n in rec["not_run"]
        ]

        explanations = {
            "failed": [
                _explanation_snippet(f["check"]) for f in rec["failed"]
            ],
            "not_run": [
                _explanation_snippet(n["check"]) for n in rec["not_run"]
            ],
        }

        entries.append({
            "test_id": case["test_id"],
            "layer_attacked": case["layer_attacked"],
            "mutation_description": case["mutation_description"],
            "tampered_bundle_path": os.path.relpath(tampered_path, _ROOT),
            "reconciled_status": rec["status"],
            "passed_count": rec["checks_passed_count"],
            "failed_count": rec["checks_failed_count"],
            "not_run_count": rec["checks_not_run_count"],
            "checks_total": rec["checks_total"],
            "failed_checks": failed_checks,
            "not_run_checks": not_run_checks,
            "explanations": explanations,
        })

    manifest = {
        "manifest_id": "ova_tamper_manifest",
        "scope_note": (
            "Each tampered bundle below verifies as INVALID, demonstrating "
            "post-generation tamper-evidence under the demo trust root. This "
            "demonstrates evidence integrity only. It does not address whether "
            "any decision was correct, whether a model behaves fairly, whether "
            "any institution meets a legal obligation, or whether this is fit "
            "for real-world critical deployment."
        ),
        "key_note": (
            "Demo keys only. Not HSM-backed, not production PKI. No claim of "
            "resistance to key compromise. Ed25519-prototype-2026; production "
            "target ML-DSA (Dilithium-III, FIPS 204) is declared but not "
            "implemented."
        ),
        "clean_inputs": {
            "bundle": os.path.relpath(paths["bundle"], _ROOT),
            "registry": os.path.relpath(paths["registry"], _ROOT),
            "trust_root": os.path.relpath(paths["trust_root"], _ROOT),
            "input_data": os.path.relpath(paths["input_data"], _ROOT),
        },
        "cases": entries,
    }

    manifest_path = os.path.join(out_dir, "tamper_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    manifest["_manifest_path"] = os.path.relpath(manifest_path, _ROOT)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate real tampered bundles + reconciled manifest."
    )
    parser.add_argument(
        "--out", default=os.path.join(_ROOT, "exports"),
        help="Output directory (default: ./exports)",
    )
    args = parser.parse_args()
    manifest = build(args.out)
    print("Generated tamper artifacts:")
    for case in manifest["cases"]:
        print(
            f"  {case['test_id']:28s} -> {case['reconciled_status']:7s} "
            f"({case['passed_count']} passed, {case['failed_count']} failed, "
            f"{case['not_run_count']} not run) -> "
            f"{case['tampered_bundle_path']}"
        )
    print(f"\nManifest: {manifest['_manifest_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
