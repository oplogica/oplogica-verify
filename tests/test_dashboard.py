"""Lightweight tests for the static dashboard (ui/).

Most are static text checks over the source files. One test confirms the
guarded static mount serves index.html from the same FastAPI origin.

Proves:
  * dashboard files exist,
  * dashboard text contains the mandatory meaning/not-meaning block,
  * dashboard text contains no banned overclaiming terms outside the mandatory
    not-meaning sentence,
  * dashboard includes the T4 failed and not_run checks by name,
  * dashboard includes the reproduction commands,
  * the static mount serves the dashboard at /ui/.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

UI_DIR = os.path.join(_ROOT, "ui")
INDEX = os.path.join(UI_DIR, "index.html")
APPJS = os.path.join(UI_DIR, "app.js")
CSS = os.path.join(UI_DIR, "style.css")

# The fixed not-meaning sentence the dashboard renders / references.
NOT_MEANING_SENTENCE = (
    "the AI decision is medically correct, unbiased, or legally compliant"
)

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
    "production ready",
    "production-ready",
    "legally compliant",
    "compliance-ready",
    "guaranteed",
)

# Affirmative-claim phrases that must never appear at all.
BANNED_ALWAYS = (
    "decision is correct",
    "the model is fair",
    "proves reasoning quality",
    "detects all conflicts",
    "detects all possible conflicts",
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def test_dashboard_files_exist():
    for p in (INDEX, APPJS, CSS):
        _assert(os.path.isfile(p), f"missing dashboard file: {p}")
        _assert(os.path.getsize(p) > 100, f"dashboard file too small: {p}")


def test_meaning_block_present():
    html = _read(INDEX)
    js = _read(APPJS)
    combined = html + "\n" + js
    # The meaning text comes from the API response and is rendered by app.js;
    # the not-meaning sentence and the meaning sentence both appear in source
    # (html banners and/or js render template). Check the key phrases exist.
    _assert("integrity checks passed" in combined or "headline" in js,
            "no meaning headline mechanism found")
    _assert("internally consistent and" in html or "Meaning:" in js,
            "meaning line not present in dashboard source")
    _assert("Not meaning:" in js, "not-meaning render line missing in app.js")
    # The literal not-meaning sentence should be reachable (it is rendered from
    # the API's meaning_block.not_meaning, but the HTML scope banner also keeps
    # the demo honest). Confirm at least the render label exists.
    _assert("not_meaning" in js, "app.js must render meaning_block.not_meaning")


def test_no_banned_terms_outside_not_meaning():
    # Banned overclaiming terms are about user-facing COPY, so we scan the HTML
    # and JS (the text and render strings). CSS is excluded from the "100%"
    # check because "100%" there is a layout dimension (e.g. width: 100%), not
    # a claim. We still scan CSS separately for claim-like phrases below.
    copy_text = (_read(INDEX) + "\n" + _read(APPJS))
    stripped = copy_text.replace(NOT_MEANING_SENTENCE, "[[NM]]").lower()
    offenders = [t for t in BANNED_OUTSIDE_NOT_MEANING if t in stripped]
    _assert(not offenders,
            f"banned terms outside not-meaning sentence (copy): {offenders}")

    # CSS must not contain claim-like banned phrases (dimensions like 100% are
    # fine and are not in this list).
    css = _read(CSS).lower()
    css_banned = [
        t for t in BANNED_OUTSIDE_NOT_MEANING
        if t in css and t != "100%"
    ]
    _assert(not css_banned, f"banned terms in CSS: {css_banned}")


def test_no_affirmative_overclaims_anywhere():
    text = (_read(INDEX) + "\n" + _read(APPJS)).lower()
    offenders = [t for t in BANNED_ALWAYS if t in text]
    _assert(not offenders, f"affirmative overclaim phrases present: {offenders}")


def test_t4_failed_and_not_run_checks_named():
    html = _read(INDEX)
    # Failed checks for T4.
    _assert("por_structural_consistency" in html,
            "T4 failed check por_structural_consistency not named in dashboard")
    _assert("merkle_root_match" in html,
            "T4 failed check merkle_root_match not named in dashboard")
    # Not-run checks for T4.
    _assert("por_signature_binding_valid" in html,
            "T4 not_run check por_signature_binding_valid not named")
    _assert("por_rule_policy_binding" in html,
            "T4 not_run check por_rule_policy_binding not named")


def test_reproduction_commands_present():
    html = _read(INDEX)
    _assert("ova_demo/run_demo.py" in html, "full demo command missing")
    _assert("verify_bundle.py exports/clean_bundle.json" in html,
            "clean verification command missing")
    _assert("verify_bundle.py exports/tampered_T4_por.json" in html,
            "T4 verification command missing")
    _assert("--trust-root exports/trust_root.json" in html,
            "trust-root argument missing from repro commands")


def test_static_mount_serves_dashboard():
    """The guarded static mount should serve index.html at /ui/."""
    from fastapi.testclient import TestClient
    from api.server import app

    client = TestClient(app)
    r = client.get("/ui/")
    _assert(r.status_code == 200, f"/ui/ status {r.status_code}")
    _assert("OVA Evidence Integrity Demo" in r.text,
            "served dashboard does not contain expected title")
    # The API routes still work alongside the mount.
    h = client.get("/health")
    _assert(h.status_code == 200, "/health broke after mounting ui")


def test_exports_datapath_verifies_valid_and_is_no_store():
    """End-to-end regression for the dashboard data path.

    Reproduces exactly what the dashboard does: generate one consistent
    ./exports set, fetch all four files via the app's /exports route, POST the
    fetched JSON to /verify, and expect a reconciled VALID 13/0/0. Also checks
    that /exports responses carry a no-store Cache-Control header (the fix that
    prevents a stale cross-generation file mix).

    Note: api.server mounts /exports at import time only if ./exports exists, so
    we generate the set BEFORE importing the app.
    """
    import os
    import json
    from ova_demo import run_demo

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exports_dir = os.path.join(root, "exports")
    # Generate one internally consistent generation.
    run_demo.run(exports_dir)

    from fastapi.testclient import TestClient
    from api.server import app

    client = TestClient(app)

    files = [
        "clean_bundle.json",
        "registry.json",
        "trust_root.json",
        "input_data.json",
    ]
    loaded = {}
    for f in files:
        r = client.get(f"/exports/{f}")
        _assert(r.status_code == 200, f"/exports/{f} -> {r.status_code}")
        loaded[f] = r.json()

    # /exports must be no-store (verified on the clean bundle response).
    cb = client.get("/exports/clean_bundle.json")
    cache_header = cb.headers.get("cache-control", "")
    _assert("no-store" in cache_header.lower(),
            f"/exports/clean_bundle.json missing no-store: {cache_header!r}")

    body = {
        "bundle": loaded["clean_bundle.json"],
        "registry": loaded["registry.json"],
        "trust_root": loaded["trust_root.json"],
        "input_data": loaded["input_data.json"],
    }
    res = client.post("/verify", json=body).json()
    _assert(res["status"] == "VALID", f"expected VALID, got {res.get('status')}")
    _assert(res["counts"] == {
        "passed": 13, "failed": 0, "not_run": 0, "checks_total": 13
    }, f"unexpected counts: {res.get('counts')}")


def _run_all():
    tests = [
        test_dashboard_files_exist,
        test_meaning_block_present,
        test_no_banned_terms_outside_not_meaning,
        test_no_affirmative_overclaims_anywhere,
        test_t4_failed_and_not_run_checks_named,
        test_reproduction_commands_present,
        test_static_mount_serves_dashboard,
        test_exports_datapath_verifies_valid_and_is_no_store,
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
