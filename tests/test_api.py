"""Tests for api.server.

Uses FastAPI's in-process TestClient (no network, no running server). Builds
real request bodies from freshly generated demo artifacts.

Proves:
  * /health works,
  * clean bundle returns reconciled VALID,
  * T4 tampered bundle returns reconciled INVALID,
  * T4 includes both failed and not_run checks,
  * missing input_data does not let the input-bound check silently pass (the
    engine reports poo_signature_valid as failed with an explicit reason),
  * banned overclaiming terms do not appear outside the mandatory not-meaning
    block,
  * no raw checks_total is exposed as an authoritative result (the only
    checks_total is the reconciled total == len(ALL_CHECKS), inside counts).
"""

from __future__ import annotations

import copy
import io
import json
import os
import re
import sys
import contextlib
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fastapi.testclient import TestClient

from api.server import app
from ova_demo import generate_bundle
from ova_demo.checks import ALL_CHECKS


client = TestClient(app)


BANNED_OUTSIDE_NOT_MEANING = (
    "100%",
    "certified",
    "certification",
    "clinically correct",
    "clinical correctness",
    "medically correct",
    "unbiased",
    "bias-free",
    "production-grade",
    "production grade",
    "legally compliant",
    "compliance-ready",
    "guaranteed",
)

# The fixed not-meaning sentence the API emits verbatim.
_NOT_MEANING_SENTENCE = (
    "the AI decision is medically correct, unbiased, or legally compliant."
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _make_payloads():
    """Generate fresh artifacts and return (clean_payload, t4_payload)."""
    tmp = tempfile.mkdtemp()
    paths = generate_bundle.generate(tmp)
    with open(paths["bundle"], "r", encoding="utf-8") as f:
        bundle = json.load(f)
    with open(paths["registry"], "r", encoding="utf-8") as f:
        registry = json.load(f)
    with open(paths["trust_root"], "r", encoding="utf-8") as f:
        trust_root = json.load(f)
    with open(paths["input_data"], "r", encoding="utf-8") as f:
        input_data = json.load(f)

    trust_body = {
        "trusted_root_public_key": trust_root["trusted_root_public_key"],
        "allowed_registry_hashes": trust_root["allowed_registry_hashes"],
    }
    clean_payload = {
        "bundle": bundle,
        "registry": registry,
        "trust_root": trust_body,
        "input_data": input_data,
    }
    t4_bundle = copy.deepcopy(bundle)
    t4_bundle["operational_layer"]["por"]["conclusions"][0]["derived_from"] = [
        "p1", "p2", "r1", "p_GHOST"
    ]
    t4_payload = {
        "bundle": t4_bundle,
        "registry": registry,
        "trust_root": trust_body,
        "input_data": input_data,
    }
    return clean_payload, t4_payload


def test_health():
    r = client.get("/health")
    _assert(r.status_code == 200, f"/health status {r.status_code}")
    body = r.json()
    _assert(body["status"] == "ok", body)
    _assert(body["checks_known"] == len(ALL_CHECKS), body)


def test_clean_bundle_returns_valid():
    clean_payload, _ = _make_payloads()
    r = client.post("/verify", json=clean_payload)
    _assert(r.status_code == 200, f"/verify status {r.status_code}")
    body = r.json()
    _assert(body["status"] == "VALID", body["status"])
    _assert(body["counts"]["passed"] == len(ALL_CHECKS), body["counts"])
    _assert(body["counts"]["failed"] == 0, body["counts"])
    _assert(body["counts"]["not_run"] == 0, body["counts"])
    _assert(
        body["meaning_block"]["headline"]
        == f"{len(ALL_CHECKS)}/{len(ALL_CHECKS)} integrity checks passed.",
        body["meaning_block"],
    )


def test_t4_returns_invalid_with_failed_and_not_run():
    _, t4_payload = _make_payloads()
    r = client.post("/verify", json=t4_payload)
    _assert(r.status_code == 200, f"/verify status {r.status_code}")
    body = r.json()
    _assert(body["status"] == "INVALID", body["status"])
    failed_names = {f["check"] for f in body["failed"]}
    not_run_names = {n["check"] for n in body["not_run"]}
    _assert("por_structural_consistency" in failed_names, failed_names)
    _assert(
        {"por_signature_binding_valid", "por_rule_policy_binding"}
        .issubset(not_run_names),
        not_run_names,
    )
    # Partition holds.
    total = (
        body["counts"]["passed"]
        + body["counts"]["failed"]
        + body["counts"]["not_run"]
    )
    _assert(total == len(ALL_CHECKS), body["counts"])
    _assert(len(body["failed"]) >= 1 and len(body["not_run"]) >= 1, body)


def test_missing_input_data_makes_poo_check_not_silently_pass():
    """Without input_data, the input-bound check (poo_signature_valid) must
    NOT silently pass. The engine reports it as FAILED with an explicit reason
    ('No expected_input_data provided.'); the result must be INVALID. This is
    the real anti-silent-pass guarantee."""
    clean_payload, _ = _make_payloads()
    no_input = dict(clean_payload)
    no_input.pop("input_data", None)
    r = client.post("/verify", json=no_input)
    _assert(r.status_code == 200, f"/verify status {r.status_code}")
    body = r.json()
    failed_names = {f["check"] for f in body["failed"]}
    not_run_names = {n["check"] for n in body["not_run"]}
    passed_names = set(body["passed"])
    # The input-bound check must be accounted for as failed or not_run, never
    # silently passed. (Engine behavior: failed, with a clear reason.)
    _assert(
        "poo_signature_valid" in (failed_names | not_run_names),
        f"poo_signature_valid must be failed or not_run, "
        f"failed={failed_names} not_run={not_run_names}",
    )
    _assert("poo_signature_valid" not in passed_names,
            "poo_signature_valid must NOT silently pass without input_data")
    # Confirm the explicit reason is present (no silent skip).
    poo_failed = [
        f for f in body["failed"] if f["check"] == "poo_signature_valid"
    ]
    _assert(poo_failed, "poo_signature_valid should be in failed with a reason")
    _assert("expected_input_data" in poo_failed[0]["reason"].lower()
            or "input" in poo_failed[0]["reason"].lower(),
            f"expected an input-related reason: {poo_failed[0]['reason']}")
    _assert(body["status"] == "INVALID",
            "without input_data the result cannot be VALID")
    _assert(body["input_data_provided"] is False, body)


def test_no_banned_terms_outside_not_meaning():
    clean_payload, t4_payload = _make_payloads()
    for payload in (clean_payload, t4_payload):
        r = client.post("/verify", json=payload)
        text = json.dumps(r.json())
        # Remove the fixed not-meaning sentence wherever it appears.
        stripped = text.replace(_NOT_MEANING_SENTENCE, "[[NM]]").lower()
        offenders = [t for t in BANNED_OUTSIDE_NOT_MEANING if t in stripped]
        _assert(not offenders,
                f"banned terms outside not-meaning block: {offenders}")
    # Also check /health.
    h = json.dumps(client.get("/health").json()).lower()
    offenders = [t for t in BANNED_OUTSIDE_NOT_MEANING if t in h]
    _assert(not offenders, f"/health contained banned terms: {offenders}")


def test_no_raw_checks_total_exposed_as_authoritative():
    """The only checks_total in the response is the reconciled total inside
    'counts', equal to len(ALL_CHECKS). No raw engine verifier_result object
    (with its hardcoded checks_total at top level) is surfaced."""
    clean_payload, t4_payload = _make_payloads()
    for payload in (clean_payload, t4_payload):
        body = client.post("/verify", json=payload).json()
        # checks_total exists ONLY under counts and equals len(ALL_CHECKS).
        _assert("checks_total" not in body,
                "top-level checks_total must not be exposed")
        _assert(body["counts"]["checks_total"] == len(ALL_CHECKS),
                body["counts"])
        # The raw engine result keys must not be present at top level.
        for raw_key in ("checks_passed", "checks_failed",
                        "trust_chain_summary", "verification_timestamp"):
            _assert(raw_key not in body,
                    f"raw engine key '{raw_key}' leaked into response")
        # Partition is internally consistent with the reconciled total.
        total = (body["counts"]["passed"] + body["counts"]["failed"]
                 + body["counts"]["not_run"])
        _assert(total == body["counts"]["checks_total"], body["counts"])


def test_malformed_bundle_returns_controlled_error():
    """A structurally broken bundle must yield a controlled ERROR envelope,
    not a 500 crash and not a leaked raw engine result."""
    clean_payload, _ = _make_payloads()
    broken = dict(clean_payload)
    broken["bundle"] = {"not": "a real bundle"}
    r = client.post("/verify", json=broken)
    _assert(r.status_code == 200, f"/verify status {r.status_code}")
    body = r.json()
    _assert(body["status"] == "ERROR", body)
    _assert("error" in body and body["error"], body)
    _assert(body["counts"]["checks_total"] == len(ALL_CHECKS), body)


def test_v02_additive_fields_present_and_v01_preserved():
    """v0.2 adds l3_taxonomy, verification_discipline, firewall — additively."""
    clean_payload, _ = _make_payloads()
    body = client.post("/verify", json=clean_payload).json()
    for k in ("status", "passed", "failed", "not_run", "counts",
              "meaning_block", "scope_warning"):
        _assert(k in body, f"v0.1 field dropped: {k}")
    _assert(body["status"] == "VALID", "clean must still be VALID")
    for k in ("l3_taxonomy", "verification_discipline", "firewall"):
        _assert(k in body, f"v0.2 field missing: {k}")
    vd = body["verification_discipline"]
    _assert(vd["deterministic"] is True, vd)
    _assert(vd["uses_llm_interpretation"] is False, vd)
    _assert(vd["verifies_decision_correctness"] is False, vd)
    _assert(vd["detects_silent_omission"] is False, vd)
    _assert(body["l3_taxonomy"]["l3_failure_classification"] == [],
            "clean bundle should have no L3 failures")


def test_v02_t4_taxonomy_classifies_failures():
    _, t4_payload = _make_payloads()
    body = client.post("/verify", json=t4_payload).json()
    classes = {e["check"]: e["failure_class"]
               for e in body["l3_taxonomy"]["l3_failure_classification"]}
    _assert(classes.get("por_structural_consistency") == "ghost_evidence_reference",
            classes)
    _assert(classes.get("merkle_root_match") == "hash_mismatch", classes)
    _assert(classes.get("por_signature_binding_valid") == "declared_check_not_run",
            classes)
    note = body["l3_taxonomy"]["scope_boundary_note"]
    _assert(note["detectable_from_bundle_alone"] is False, note)


def test_v02_api_payload_is_firewall_clean():
    """System-generated framing text in the response must not overclaim."""
    from ova_demo import negative_claims_firewall as fw
    clean_payload, _ = _make_payloads()
    body = client.post("/verify", json=clean_payload).json()
    _assert(body["firewall"]["findings"] == [],
            f"server firewall flagged its own output: {body['firewall']['findings']}")
    generated = {
        "meaning_block": body["meaning_block"],
        "scope_warning": body["scope_warning"],
        "verification_discipline": body["verification_discipline"],
        "l3_taxonomy": body["l3_taxonomy"],
    }
    findings = fw.scan_mapping(generated)
    _assert(findings == [], f"v0.2 generated text overclaims: {findings}")


def _run_all():
    tests = [
        test_health,
        test_clean_bundle_returns_valid,
        test_t4_returns_invalid_with_failed_and_not_run,
        test_missing_input_data_makes_poo_check_not_silently_pass,
        test_no_banned_terms_outside_not_meaning,
        test_no_raw_checks_total_exposed_as_authoritative,
        test_malformed_bundle_returns_controlled_error,
        test_v02_additive_fields_present_and_v01_preserved,
        test_v02_t4_taxonomy_classifies_failures,
        test_v02_api_payload_is_firewall_clean,
    ]
    failures = []
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}\n      {e}")
            failures.append(fn.__name__)
        except Exception as e:
            print(f"ERROR {fn.__name__}\n      {type(e).__name__}: {e}")
            failures.append(fn.__name__)
    print()
    if failures:
        print(f"{len(failures)} test(s) failed: {failures}")
        sys.exit(1)
    print(f"All {len(tests)} tests passed.")


if __name__ == "__main__":
    _run_all()
