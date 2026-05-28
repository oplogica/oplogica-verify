"""Tests for ova_demo.run_demo.

Proves:
  * run_demo generates all expected files,
  * the report exists,
  * the manifest exists,
  * all 6 tamper cases are present,
  * the generated report contains the mandatory meaning/not-meaning block,
  * the pipeline returns success on a good run,
  * usage/file errors return a controlled non-zero exit code.

Uses temp directories. Real engine, no mocks.
"""

from __future__ import annotations

import io
import os
import sys
import contextlib
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo import run_demo


EXPECTED_IDS = {
    "T1_pon_break_quorum_axiom",
    "T2_poe_break_chain_link",
    "T3_poo_change_input_hash",
    "T4_por_invalid_reference",
    "T5_poc_silence_conflict",
    "T6_merkle_root_direct_swap",
}

EXPECTED_FILES = (
    "clean_bundle.json",
    "registry.json",
    "trust_root.json",
    "input_data.json",
    "tampered_T1_pon.json",
    "tampered_T2_poe.json",
    "tampered_T3_poo.json",
    "tampered_T4_por.json",
    "tampered_T5_poc.json",
    "tampered_T6_merkle.json",
    "tamper_manifest.json",
    "evidence_integrity_report.md",
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_run_generates_all_expected_files():
    with tempfile.TemporaryDirectory() as tmp:
        result = run_demo.run(tmp)
        for name in EXPECTED_FILES:
            path = os.path.join(tmp, name)
            _assert(os.path.isfile(path), f"expected file missing: {name}")
        _assert(result["clean_status"] == "VALID",
                f"clean bundle should be VALID, got {result['clean_status']}")


def test_report_and_manifest_exist():
    with tempfile.TemporaryDirectory() as tmp:
        run_demo.run(tmp)
        _assert(os.path.isfile(os.path.join(tmp, "tamper_manifest.json")),
                "manifest missing")
        _assert(os.path.isfile(os.path.join(tmp, "evidence_integrity_report.md")),
                "report missing")


def test_all_six_tamper_cases_present():
    with tempfile.TemporaryDirectory() as tmp:
        result = run_demo.run(tmp)
        ids = {c["test_id"] for c in result["tamper_cases"]}
        _assert(ids == EXPECTED_IDS, f"tamper case ids mismatch: {ids}")
        _assert(len(result["tamper_cases"]) == 6, "expected 6 tamper cases")
        for c in result["tamper_cases"]:
            _assert(c["status"] == "INVALID",
                    f"{c['test_id']} should be INVALID")


def test_report_contains_meaning_block():
    with tempfile.TemporaryDirectory() as tmp:
        run_demo.run(tmp)
        with open(os.path.join(tmp, "evidence_integrity_report.md"),
                  "r", encoding="utf-8") as f:
            text = f.read()
        _assert("integrity checks passed." in text,
                "meaning block numerator missing from report")
        _assert("Meaning: the evidence bundle is internally consistent and "
                "tamper-evident under the demo trust root." in text,
                "meaning line missing from report")
        _assert("Not meaning: the AI decision is medically correct, unbiased, "
                "or legally compliant." in text,
                "not-meaning line missing from report")


def test_main_exit_zero_on_success():
    with tempfile.TemporaryDirectory() as tmp:
        argv_backup = sys.argv
        sys.argv = ["run_demo.py", "--out", tmp]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = run_demo.main()
        finally:
            sys.argv = argv_backup
        _assert(code == run_demo.EXIT_OK, f"expected exit 0, got {code}")


def test_controlled_error_on_bad_output_dir():
    """Point --out at a path under an existing FILE so makedirs fails. The
    pipeline must return the controlled non-zero exit code, not crash."""
    with tempfile.TemporaryDirectory() as tmp:
        # Create a regular file, then try to use a subpath of it as a dir.
        blocker = os.path.join(tmp, "iam_a_file")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        bad_out = os.path.join(blocker, "subdir")  # cannot mkdir under a file

        argv_backup = sys.argv
        sys.argv = ["run_demo.py", "--out", bad_out]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                code = run_demo.main()
        finally:
            sys.argv = argv_backup
        _assert(code == run_demo.EXIT_ERROR,
                f"expected controlled error exit 1, got {code}")


def test_run_raises_demoerror_on_bad_output_dir():
    """The run() function (not main) should raise DemoError, not a raw OSError."""
    with tempfile.TemporaryDirectory() as tmp:
        blocker = os.path.join(tmp, "iam_a_file")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        bad_out = os.path.join(blocker, "subdir")
        try:
            run_demo.run(bad_out)
        except run_demo.DemoError:
            return
        except Exception as e:
            raise AssertionError(
                f"expected DemoError, got {type(e).__name__}: {e}"
            )
        raise AssertionError("expected DemoError, but run() succeeded")


def _run_all():
    tests = [
        test_run_generates_all_expected_files,
        test_report_and_manifest_exist,
        test_all_six_tamper_cases_present,
        test_report_contains_meaning_block,
        test_main_exit_zero_on_success,
        test_controlled_error_on_bad_output_dir,
        test_run_raises_demoerror_on_bad_output_dir,
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
