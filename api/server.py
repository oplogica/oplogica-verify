"""Thin FastAPI wrapper over the OVA verify -> reconcile path.

This is a face over the SAME core the CLI uses: ``engine.verify_bundle(...)``
followed by ``reconcile(...)``. It exposes only reconciled output. It adds no
database, no authentication, no dashboard, and deploys nothing.

Trust-root independence
-----------------------
The trust root (public key + allowed registry hashes) is supplied in the
request body and pinned explicitly. The API never recovers the trust root from
the registry under inspection — doing so would let a fabricated registry supply
its own trust root and defeat pinning.

Scope
-----
A VALID result means the evidence bundle is internally consistent and
tamper-evident under the supplied (demo) trust root. It does not establish
decision correctness, model behavior fairness, or legal readiness, and this
service is not intended for critical deployment.

Run locally
-----------
    uvicorn api.server:app --host 127.0.0.1 --port 8000

Then POST to /verify with a JSON body containing bundle, registry, trust_root,
and optionally input_data.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_engine import ova_v2 as engine
from ova_demo.checks import ALL_CHECKS, reconcile


# ----------------------------------------------------------------------
# Fixed scope text. The numerator in the meaning block is filled per result;
# the denominator is the reconciled total (len(ALL_CHECKS)).
# ----------------------------------------------------------------------

MEANING = (
    "the evidence bundle is internally consistent and tamper-evident under "
    "the demo trust root."
)
NOT_MEANING = (
    "the AI decision is medically correct, unbiased, or legally compliant."
)
SCOPE_WARNING = (
    "This service verifies evidence integrity and binding only. It does not "
    "establish whether a decision was correct, whether a model behaves fairly, "
    "whether any institution meets a legal obligation, or whether this is fit "
    "for real-world critical use. Trust material supplied in the request is "
    "treated as a demo anchor; the verifier never recovers the trust root from "
    "the registry under inspection."
)


app = FastAPI(
    title="OVA Evidence Integrity Verifier (demo)",
    description=(
        "Thin demo API over an offline evidence-integrity verifier. Returns "
        "reconciled verification results only. It does not establish decision "
        "correctness, model behavior fairness, or legal readiness, and is not "
        "intended for critical deployment."
    ),
    version="0.1.0-demo",
)


class TrustRoot(BaseModel):
    trusted_root_public_key: str
    allowed_registry_hashes: list[str]


class VerifyRequest(BaseModel):
    bundle: dict[str, Any]
    registry: dict[str, Any]
    trust_root: TrustRoot
    input_data: Optional[dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional raw decision input. Required for checks that bind to "
            "the input (e.g. poo_signature_valid). If omitted, input-bound "
            "checks are not allowed to silently pass. The current engine "
            "reports poo_signature_valid as failed with an explicit "
            "input-related reason."
        ),
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "ova-evidence-integrity-verifier-demo",
        "checks_known": len(ALL_CHECKS),
    }


@app.post("/verify")
def verify(req: VerifyRequest) -> dict[str, Any]:
    # Same core path as the CLI: engine verify with explicit, independent
    # trust material, then reconcile. The trust root comes from the request,
    # never from req.registry.
    try:
        raw = engine.verify_bundle(
            req.bundle,
            expected_input_data=req.input_data,
            governance_registry=req.registry,
            trusted_root_public_key=req.trust_root.trusted_root_public_key,
            allowed_registry_hashes=set(
                req.trust_root.allowed_registry_hashes
            ),
        )
    except Exception as e:  # malformed bundle, etc.
        # Return a reconciled-style error envelope. We do NOT leak the raw
        # engine result; we report that the bundle could not be processed.
        return {
            "status": "ERROR",
            "error": (
                f"Verifier could not process the request: "
                f"{type(e).__name__}: {e}"
            ),
            "passed": [],
            "failed": [],
            "not_run": [],
            "unexpected": [],
            "counts": {
                "passed": 0,
                "failed": 0,
                "not_run": 0,
                "checks_total": len(ALL_CHECKS),
            },
            "meaning_block": _meaning_block(0),
            "scope_warning": SCOPE_WARNING,
            "input_data_provided": req.input_data is not None,
        }

    rec = reconcile(raw)

    return {
        "status": rec["status"],
        "passed": rec["passed"],
        "failed": rec["failed"],
        "not_run": rec["not_run"],
        "unexpected": rec["unexpected"],
        "counts": {
            "passed": rec["checks_passed_count"],
            "failed": rec["checks_failed_count"],
            "not_run": rec["checks_not_run_count"],
            # This is the RECONCILED total (len(ALL_CHECKS)), never the engine's
            # raw hardcoded field. We deliberately do not surface the raw
            # verifier_result.
            "checks_total": rec["checks_total"],
        },
        "meaning_block": _meaning_block(rec["checks_passed_count"]),
        "scope_warning": SCOPE_WARNING,
        "input_data_provided": req.input_data is not None,
    }


def _meaning_block(n_passed: int) -> dict[str, str]:
    n_total = len(ALL_CHECKS)
    return {
        "headline": f"{n_passed}/{n_total} integrity checks passed.",
        "meaning": MEANING,
        "not_meaning": NOT_MEANING,
    }


# ----------------------------------------------------------------------
# Optional: serve the local static dashboard from the SAME origin so the UI
# can call /health and /verify without CORS. This is the only "server change"
# and it is purely additive: if the ui/ directory is absent, nothing mounts and
# the API behaves exactly as before. It serves static files only — no database,
# no auth, no deployment. The dashboard is mounted at /ui to keep the API
# routes (/health, /verify) unambiguous.
# ----------------------------------------------------------------------
_UI_DIR = os.path.join(_ROOT, "ui")
if os.path.isdir(_UI_DIR):
    from fastapi.staticfiles import StaticFiles

    app.mount("/ui", StaticFiles(directory=_UI_DIR, html=True), name="ui")
