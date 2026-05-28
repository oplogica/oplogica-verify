"""Tests for ova_demo.check_explanations.

Proves:
  * every name in ALL_CHECKS has an explanation,
  * no explanation exists for an unknown check (get_explanation raises),
  * required fields are present and well-typed for every check,
  * no explanation text contains banned overclaiming terms.

No engine, no I/O. Pure data validation.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ova_demo.checks import ALL_CHECKS
from ova_demo.check_explanations import (
    REQUIRED_FIELDS,
    get_explanation,
    all_explanations,
)


# Terms that would overclaim. We scan all explanation text for these as
# case-insensitive substrings. The list intentionally includes both the
# hyphenated and spaced forms where relevant. Because the explanations are
# meant to be entirely free of these, a strict substring scan is correct
# here (there is no legitimate use to protect).
BANNED_TERMS = (
    "compliant",
    "compliance",
    "certified",
    "certification",
    "clinically correct",
    "clinical correctness",
    "medically correct",      # belongs only in the fixed meaning-block, not here
    "unbiased",
    "bias-free",
    "production-grade",
    "production grade",
    "100%",
    "guarantee",              # avoid absolute guarantees in per-check text
    "guaranteed",
)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _text_blob(entry: dict) -> str:
    parts = [
        str(entry["meaning"]),
        str(entry["failure_means"]),
        str(entry["does_not_mean"]),
    ]
    parts.extend(str(x) for x in entry["fields_checked"])
    return " ".join(parts).lower()


def test_every_canonical_check_has_an_explanation():
    exps = all_explanations()
    missing = [name for name in ALL_CHECKS if name not in exps]
    _assert(not missing, f"checks with no explanation: {missing}")
    # And there is exactly one explanation per canonical check (no extras).
    extra = [name for name in exps if name not in ALL_CHECKS]
    _assert(not extra, f"explanations for non-canonical checks: {extra}")
    _assert(
        len(exps) == len(ALL_CHECKS),
        f"explanation count {len(exps)} != ALL_CHECKS {len(ALL_CHECKS)}",
    )


def test_unknown_check_has_no_explanation():
    for bogus in ("not_a_real_check", "", "MERKLE_ROOT_MATCH", "poc"):
        try:
            get_explanation(bogus)
        except KeyError:
            continue
        raise AssertionError(
            f"get_explanation unexpectedly returned for unknown '{bogus}'"
        )


def test_required_fields_present_and_well_typed():
    for name in ALL_CHECKS:
        e = get_explanation(name)
        for field in REQUIRED_FIELDS:
            _assert(field in e, f"[{name}] missing required field '{field}'")
        # Types and non-emptiness.
        _assert(
            isinstance(e["meaning"], str) and e["meaning"].strip(),
            f"[{name}] meaning must be a non-empty string",
        )
        _assert(
            isinstance(e["failure_means"], str) and e["failure_means"].strip(),
            f"[{name}] failure_means must be a non-empty string",
        )
        _assert(
            isinstance(e["does_not_mean"], str) and e["does_not_mean"].strip(),
            f"[{name}] does_not_mean must be a non-empty string",
        )
        _assert(
            isinstance(e["fields_checked"], list) and e["fields_checked"],
            f"[{name}] fields_checked must be a non-empty list",
        )
        for item in e["fields_checked"]:
            _assert(
                isinstance(item, str) and item.strip(),
                f"[{name}] fields_checked items must be non-empty strings",
            )


def test_no_banned_overclaiming_terms():
    offenders = []
    exps = all_explanations()
    for name, e in exps.items():
        blob = _text_blob(e)
        for term in BANNED_TERMS:
            if term in blob:
                offenders.append((name, term))
    _assert(not offenders, f"banned terms found: {offenders}")


def test_every_does_not_mean_is_distinct_from_meaning():
    """A sanity check that the boundary text is not just a copy of meaning."""
    for name in ALL_CHECKS:
        e = get_explanation(name)
        _assert(
            e["does_not_mean"].strip() != e["meaning"].strip(),
            f"[{name}] does_not_mean duplicates meaning",
        )


def test_returned_entries_are_copies_not_registry_references():
    """Mutating a returned explanation must not corrupt the registry."""
    e = get_explanation("merkle_root_match")
    e["fields_checked"].append("INJECTED")
    e["meaning"] = "MUTATED"
    fresh = get_explanation("merkle_root_match")
    _assert("INJECTED" not in fresh["fields_checked"],
            "registry fields_checked was mutated through a returned copy")
    _assert(fresh["meaning"] != "MUTATED",
            "registry meaning was mutated through a returned copy")


def _run_all():
    tests = [
        test_every_canonical_check_has_an_explanation,
        test_unknown_check_has_no_explanation,
        test_required_fields_present_and_well_typed,
        test_no_banned_overclaiming_terms,
        test_every_does_not_mean_is_distinct_from_meaning,
        test_returned_entries_are_copies_not_registry_references,
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
