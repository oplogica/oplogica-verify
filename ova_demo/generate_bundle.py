"""Generate on-disk demo artifacts from the vendored engine.

Writes three files to an output directory:

  * clean_bundle.json   — a healthy 5-layer proof bundle (engine output)
  * registry.json       — the signed governance registry the bundle refers to
  * trust_root.json     — the INDEPENDENT trust anchor the verifier pins to:
                          { "trusted_root_public_key": ...,
                            "allowed_registry_hashes": [ ... ] }

Why a separate trust_root.json
------------------------------
The engine bootstraps a fresh random trust anchor on every import, and the
registry payload happens to embed its own root public key. A naive verifier
could recover the trust root *from the very registry it is checking* — but
then an attacker who fabricates a registry also supplies its own trust root,
which defeats the whole point of pinning (brief §5C: "where did the trust
root come from?").

So we serialize the trust anchor to its own file at generation time. The
verifier (verify_bundle.py) pins to THIS file, independently of whatever
registry it is later handed. That is the honest model: the trust root is a
demo anchor, generated once for the demo, and shipped to the verifier
out-of-band from the bundle.

These are DEMO keys only. Not HSM-backed. Not production PKI. This does not
claim resistance to key compromise. The purpose is to demonstrate binding and
post-hoc tamper detection, not production-grade key management.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine


def generate(out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)

    # Run the engine scenario (suppress its console chatter).
    with contextlib.redirect_stdout(io.StringIO()):
        bundle, _result, _operator, patient = engine.run_triage_scenario()

    registry = engine.GOVERNANCE_REGISTRY_V1

    # The independent trust anchor, captured at generation time.
    trust_root = {
        "_comment": (
            "DEMO trust anchor only. Not HSM-backed, not production PKI, "
            "no claim of resistance to key compromise. Generated for this "
            "demo run and shipped to the verifier independently of any "
            "bundle. The verifier pins to this file, NOT to a root recovered "
            "from the registry under inspection."
        ),
        "signature_scheme": "Ed25519-prototype-2026",
        "production_target": "ML-DSA (Dilithium-III, FIPS 204) — not implemented",
        "trusted_root_public_key": engine.TRUSTED_REGISTRY_ROOT_PUBLIC_KEY,
        "allowed_registry_hashes": sorted(engine.ALLOWED_REGISTRY_HASHES),
    }

    paths = {
        "bundle": os.path.join(out_dir, "clean_bundle.json"),
        "registry": os.path.join(out_dir, "registry.json"),
        "trust_root": os.path.join(out_dir, "trust_root.json"),
        "input_data": os.path.join(out_dir, "input_data.json"),
    }

    with open(paths["bundle"], "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    with open(paths["registry"], "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)
    with open(paths["trust_root"], "w", encoding="utf-8") as f:
        json.dump(trust_root, f, indent=2, ensure_ascii=False)
    # The raw decision input is NOT embedded in the bundle (it is sensitive,
    # only its hash is bound). The verifier needs it to check
    # poo_signature_valid. We write it as a separate SYNTHETIC file. In a real
    # deployment this would be supplied through a controlled channel.
    with open(paths["input_data"], "w", encoding="utf-8") as f:
        json.dump(patient, f, indent=2, ensure_ascii=False)

    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate demo bundle, registry, and trust-root files."
    )
    parser.add_argument(
        "--out", default=os.path.join(_ROOT, "exports"),
        help="Output directory (default: ./exports)",
    )
    args = parser.parse_args()
    paths = generate(args.out)
    print("Generated demo artifacts:")
    for label, path in paths.items():
        print(f"  {label:10s} -> {path}")
    print()
    print("Note: trust_root.json holds DEMO keys only. Not production PKI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
