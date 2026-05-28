"""Thin re-export wrapper around the vendored ova_v2.py engine.

We do NOT modify ova_v2.py. Everything in this package treats the engine as a
read-only authority. If the engine ever needs to change, that is a separate
decision recorded in the brief; the demo layer must never silently diverge.
"""

from .ova_v2 import (  # noqa: F401
    verify_bundle,
    run_triage_scenario,
    GOVERNANCE_REGISTRY_V1,
    GOVERNANCE_REGISTRY_V1_HASH,
    TRUSTED_REGISTRY_ROOT_PUBLIC_KEY,
    ALLOWED_REGISTRY_HASHES,
)
