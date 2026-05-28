"""Tests for ova_demo.verify_bundle (the offline CLI).

These tests generate real on-disk artifacts via generate_bundle.generate(),
then drive the CLI's main(argv) entry point, asserting the exit-code contract
and that output is routed through reconcile() (never the engine's raw
checks_total) and always carries the mandatory meaning/not-meaning block.

No network, no mocking of the verifier. Uses a temp directory.
"""

from __future__ import annotations

import io
import json
import os
import sys
import contextlib
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo import generate_bundle  # noqa: E402
from ova_demo import verify_bundle as cli  # noqa: E402


def _gen(tmp: str) -> dict[str, str]:
    return generate_bundle.generate(tmp)


def _run_cli(argv: list[str]) -> tuple[int, str]:
    """Run the CLI main() capturing stdout. Returns (exit_code, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_clean_bundle_exit_zero_and_full_thirteen():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        code, out = _run_cli([
            p["bundle"],
            "--registry", p["registry"],
            "--trust-root", p["trust_root"],
            "--input-data", p["input_data"],
        ])
        _assert(code == cli.EXIT_VALID, f"expected exit 0, got {code}")
        _assert("Reconciled status: VALID" in out, out)
        _assert("13 passed, 0 failed, 0 not run (of 13 total)" in out, out)
        # Mandatory meaning/not-meaning block present.
        _assert("13/13 integrity checks passed." in out, out)
        _assert("Not meaning:" in out, out)
        # Never renders a bare percentage.
        _assert("100%" not in out, "CLI must never print 100%")
        _assert("%" not in out, "CLI should not render any percentage")


def test_dangling_por_reference_exit_one_and_accounting():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        with open(p["bundle"], "r", encoding="utf-8") as f:
            bundle = json.load(f)
        bundle["operational_layer"]["por"]["conclusions"][0][
            "derived_from"
        ] = ["does_not_exist"]
        bad_path = os.path.join(tmp, "tampered_por.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f)

        code, out = _run_cli([
            bad_path,
            "--registry", p["registry"],
            "--trust-root", p["trust_root"],
            "--input-data", p["input_data"],
        ])
        _assert(code == cli.EXIT_INVALID, f"expected exit 1, got {code}")
        _assert("Reconciled status: INVALID" in out, out)
        # The two short-circuited checks must appear under NOT RUN, by name.
        _assert("por_signature_binding_valid" in out, out)
        _assert("por_rule_policy_binding" in out, out)
        _assert("NOT RUN (2):" in out, out)
        _assert("FAILED (2):" in out, out)
        _assert("9 passed, 2 failed, 2 not run (of 13 total)" in out, out)
        # Meaning block still present on failure, with the right numerator.
        _assert("9/13 integrity checks passed." in out, out)
        _assert("100%" not in out, "CLI must never print 100%")


def test_missing_bundle_file_exit_two():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        code, _ = _run_cli([
            os.path.join(tmp, "does_not_exist.json"),
            "--registry", p["registry"],
            "--trust-root", p["trust_root"],
        ])
        _assert(code == cli.EXIT_USAGE, f"expected exit 2, got {code}")


def test_bad_json_exit_two():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        code, _ = _run_cli([
            bad,
            "--registry", p["registry"],
            "--trust-root", p["trust_root"],
        ])
        _assert(code == cli.EXIT_USAGE, f"expected exit 2, got {code}")


def test_malformed_trust_root_exit_two():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        bad_root = os.path.join(tmp, "badroot.json")
        with open(bad_root, "w", encoding="utf-8") as f:
            json.dump({"foo": "bar"}, f)
        code, _ = _run_cli([
            p["bundle"],
            "--registry", p["registry"],
            "--trust-root", bad_root,
        ])
        _assert(code == cli.EXIT_USAGE, f"expected exit 2, got {code}")


def test_missing_required_args_exit_two():
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        # Omit --registry and --trust-root. argparse exits; we normalize to 2.
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = _run_cli([p["bundle"]])
        _assert(code == cli.EXIT_USAGE, f"expected exit 2, got {code}")


def test_no_input_data_reports_poo_check_as_failed_not_silent():
    """Without --input-data, poo_signature_valid cannot be evaluated. The
    engine reports it as FAILED with an explicit reason (not silently passed,
    not mislabeled as not-run). The run must be INVALID."""
    with tempfile.TemporaryDirectory() as tmp:
        p = _gen(tmp)
        code, out = _run_cli([
            p["bundle"],
            "--registry", p["registry"],
            "--trust-root", p["trust_root"],
            # deliberately no --input-data
        ])
        _assert(code == cli.EXIT_INVALID, f"expected exit 1, got {code}")
        _assert("[FAIL] poo_signature_valid" in out,
                "poo_signature_valid should be listed under FAILED")
        _assert("No expected_input_data provided." in out,
                "expected the input-absent failure reason")
        _assert("reported above as FAILED" in out,
                "input-absent note must say the check FAILED, not not-run")


def _run_all():
    tests = [
        test_clean_bundle_exit_zero_and_full_thirteen,
        test_dangling_por_reference_exit_one_and_accounting,
        test_missing_bundle_file_exit_two,
        test_bad_json_exit_two,
        test_malformed_trust_root_exit_two,
        test_missing_required_args_exit_two,
        test_no_input_data_reports_poo_check_as_failed_not_silent,
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
