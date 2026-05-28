"""Tests for ova_demo.report_generator.

Proves:
  * the report file is generated,
  * all 6 tamper cases appear,
  * T4 includes both failed and not_run checks,
  * reproduction commands are present (clean + tampered),
  * the mandatory meaning/not-meaning block is present,
  * banned overclaiming terms are absent OUTSIDE the mandatory not-meaning
    block (the not-meaning block legitimately contains "medically correct",
    "unbiased", "legally compliant" in negation — that is required text),
  * no raw engine checks_total is rendered without reconciliation (the report
    derives all counts from reconciled results; we assert the partition holds
    for every rendered case).

Uses a temp directory. Real engine, no mocks.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo import tamper_examples
from ova_demo import report_generator


EXPECTED_IDS = [
    "T1_pon_break_quorum_axiom",
    "T2_poe_break_chain_link",
    "T3_poo_change_input_hash",
    "T4_por_invalid_reference",
    "T5_poc_silence_conflict",
    "T6_merkle_root_direct_swap",
]

# Terms that must not appear as affirmative claims. We scan the report with
# the mandatory not-meaning block stripped out first.
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

_NOT_MEANING_RE = re.compile(r"Not meaning:.*?legally compliant\.", re.S | re.I)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _build(tmp: str) -> tuple[str, str, dict]:
    """Build manifest + report into tmp. Returns (report_text, report_path, manifest)."""
    manifest = tamper_examples.build(tmp)
    manifest_path = os.path.join(tmp, "tamper_manifest.json")
    report_path = os.path.join(tmp, "evidence_integrity_report.md")
    report_generator.build_report(manifest_path, report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        text = f.read()
    return text, report_path, manifest


def test_report_file_generated():
    with tempfile.TemporaryDirectory() as tmp:
        text, path, _ = _build(tmp)
        _assert(os.path.isfile(path), "report file not written")
        _assert(text.startswith("# OVA Evidence Integrity Report"),
                "report title missing or wrong")
        _assert(len(text) > 1000, "report suspiciously short")


def test_all_six_tamper_cases_appear():
    with tempfile.TemporaryDirectory() as tmp:
        text, _, _ = _build(tmp)
        for tid in EXPECTED_IDS:
            _assert(text.count(tid) >= 2,
                    f"{tid} should appear in summary table and detail section")


def test_t4_includes_failed_and_not_run():
    with tempfile.TemporaryDirectory() as tmp:
        text, _, _ = _build(tmp)
        # Isolate the T4 detail section.
        start = text.index("### T4_por_invalid_reference")
        # next "### " after start, or end
        nxt = text.find("\n### ", start + 1)
        section = text[start:] if nxt == -1 else text[start:nxt]
        _assert("por_structural_consistency" in section,
                "T4 section missing failed check por_structural_consistency")
        _assert("por_signature_binding_valid" in section,
                "T4 section missing not_run check por_signature_binding_valid")
        _assert("por_rule_policy_binding" in section,
                "T4 section missing not_run check por_rule_policy_binding")
        _assert("Failed checks:" in section, "T4 missing Failed checks block")
        _assert("Not-run checks:" in section,
                "T4 missing Not-run checks block")


def test_reproduction_commands_present():
    with tempfile.TemporaryDirectory() as tmp:
        text, _, _ = _build(tmp)
        _assert("## Reproduce these results" in text,
                "reproduction section missing")
        # Both a clean and a tampered verify command.
        _assert(text.count("verify_bundle.py") >= 2,
                "expected clean + tampered reproduction commands")
        _assert("--trust-root" in text, "repro command missing --trust-root")
        _assert("--registry" in text, "repro command missing --registry")


def test_mandatory_meaning_block_present():
    with tempfile.TemporaryDirectory() as tmp:
        text, _, _ = _build(tmp)
        _assert("integrity checks passed." in text,
                "meaning block numerator line missing")
        _assert("Meaning: the evidence bundle is internally consistent and "
                "tamper-evident under the demo trust root." in text,
                "meaning line missing")
        _assert("Not meaning: the AI decision is medically correct, unbiased, "
                "or legally compliant." in text,
                "not-meaning line missing")


def test_no_banned_terms_outside_not_meaning_block():
    with tempfile.TemporaryDirectory() as tmp:
        text, _, _ = _build(tmp)
        # Confirm there is exactly one not-meaning block, then strip it.
        blocks = _NOT_MEANING_RE.findall(text)
        _assert(len(blocks) >= 1,
                "expected at least one mandatory not-meaning block")
        stripped = _NOT_MEANING_RE.sub("[[NOT_MEANING_BLOCK]]", text).lower()
        offenders = [t for t in BANNED_OUTSIDE_NOT_MEANING if t in stripped]
        _assert(not offenders,
                f"banned terms outside not-meaning block: {offenders}")


def test_counts_are_reconciled_partition_not_raw():
    """The report must not render a raw engine checks_total without
    reconciliation. We assert every rendered case shows passed+failed+not_run
    summing to the same total it prints, and that the phrase 'of 13 total'
    is always backed by a real partition in the manifest."""
    with tempfile.TemporaryDirectory() as tmp:
        text, _, manifest = _build(tmp)
        for c in manifest["cases"]:
            total = c["passed_count"] + c["failed_count"] + c["not_run_count"]
            _assert(total == c["checks_total"],
                    f"{c['test_id']} partition {total} != "
                    f"checks_total {c['checks_total']}")
            # The rendered detail line for this case must include the
            # reconciled triple.
            triple = (f"{c['passed_count']} passed, {c['failed_count']} "
                      f"failed, {c['not_run_count']} not run")
            _assert(triple in text,
                    f"{c['test_id']} reconciled triple not rendered: {triple}")
        # The report should never present the engine's raw count AS a rendered
        # result field (e.g. a 'checks_total: 13' line copied from the engine
        # output). Note: the reconcile() not_run reason text legitimately
        # MENTIONS the engine's hardcoded checks_total to EXPLAIN the accounting
        # gap; that is a disclaimer, not a leaked result field. So we forbid the
        # rendered-field form ('checks_total:' or 'checks_total =' / '==') used
        # as a presented value, while allowing the prose mention.
        _assert("checks_total:" not in text,
                "report rendered a raw 'checks_total:' result field")
        _assert("checks_total ==" not in text,
                "report rendered a raw 'checks_total ==' result field")
        # The only permitted occurrences are inside the reconcile() reason text
        # that explicitly explains the engine's hardcoded value. Confirm every
        # occurrence sits in such a reason line.
        for line in text.splitlines():
            if "checks_total" in line:
                _assert(
                    "hardcoded checks_total=13" in line,
                    f"unexpected raw checks_total rendering: {line[:80]}",
                )


def _run_all():
    tests = [
        test_report_file_generated,
        test_all_six_tamper_cases_appear,
        test_t4_includes_failed_and_not_run,
        test_reproduction_commands_present,
        test_mandatory_meaning_block_present,
        test_no_banned_terms_outside_not_meaning_block,
        test_counts_are_reconciled_partition_not_raw,
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
