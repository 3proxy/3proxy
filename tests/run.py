#!/usr/bin/env python3
"""Run the 3proxy regression tests.

    python3 tests/run.py                 every case
    python3 tests/run.py httpsrv         cases whose name matches
    python3 tests/run.py --bin build/bin/3proxy
    python3 tests/run.py --keep          leave the temporary files behind

Each case under tests/cases/ defines the configurations it needs and the
positive and negative scenarios expected from them.
"""

import argparse
import importlib.util
import os
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import Failure, Tester  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_binary():
    """Find a built 3proxy: the Makefiles put it in bin/, CMake in build/bin/,
    and multi-configuration generators one level below that again."""
    name = "3proxy.exe" if os.name == "nt" else "3proxy"
    candidates = [os.path.join(ROOT, "bin", name),
                  os.path.join(ROOT, "build", "bin", name)]
    for config in ("Release", "Debug", "RelWithDebInfo", "MinSizeRel"):
        candidates.append(os.path.join(ROOT, "build", "bin", config, name))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return candidates[0]


def load_case(path):
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location("case_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return name, module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pattern", nargs="?", default="",
                        help="only run cases whose name contains this")
    parser.add_argument("--bin", dest="binary", default=None,
                        help="the 3proxy binary to test")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print every check, not just the failures")
    args = parser.parse_args()

    binary = args.binary or os.environ.get("BIN") or default_binary()
    binary = os.path.abspath(binary)
    if not os.path.isfile(binary):
        print(f"no 3proxy binary at {binary} (build first, or pass --bin)",
              file=sys.stderr)
        return 2

    case_dir = os.path.join(ROOT, "tests", "cases")
    paths = sorted(os.path.join(case_dir, f) for f in os.listdir(case_dir)
                   if f.endswith(".py") and not f.startswith("_"))
    paths = [p for p in paths if args.pattern in os.path.basename(p)]
    if not paths:
        print(f"no cases matched {args.pattern!r}", file=sys.stderr)
        return 2

    tmpdir = tempfile.mkdtemp(prefix="3proxy-tests.")
    print(f"3proxy tests: {binary}")
    print(f"working in:   {tmpdir}\n")

    passed = failed = skipped = 0
    failures = []

    try:
        for path in paths:
            name, module = load_case(path)
            print(f"  {name}")
            tester = Tester(binary, tmpdir, name)
            error = None
            try:
                module.run(tester)
            except Failure as exc:
                error = str(exc)
            except Exception:
                error = traceback.format_exc()
            finally:
                tester.stop_all()

            for status, label, expected, actual in tester.checks:
                if status is None:
                    skipped += 1
                    print(f"    skip {label}")
                elif status:
                    passed += 1
                    if args.verbose:
                        print(f"    ok   {label}")
                else:
                    failed += 1
                    failures.append(f"{name}: {label}")
                    print(f"    FAIL {label}")
                    if expected is not None:
                        print(f"         expected: {expected}")
                    if actual is not None:
                        print(f"         actual:   {actual}")

            if tester.checks and any(status is False for status, _, _, _ in tester.checks):
                for name, text in tester.logs:
                    lines = [line for line in text.splitlines() if line.strip()]
                    if not lines:
                        continue
                    print(f"    --- {name} said ---")
                    for line in lines[-12:]:
                        print(f"      {line}")

            if error:
                failed += 1
                failures.append(f"{name}: case aborted")
                print("    ERROR the case could not finish:")
                for line in error.rstrip().splitlines():
                    print(f"      {line}")
            print()
    finally:
        if args.keep:
            print(f"temporary files left in {tmpdir}")
        else:
            shutil.rmtree(tmpdir, ignore_errors=True)

    print("-" * 41)
    total = passed + failed
    summary = f"cases: {len(paths)}   checks: {total}   passed: {passed}   failed: {failed}"
    if skipped:
        summary += f"   skipped: {skipped}"
    print(summary)
    for item in failures:
        print(f"  FAIL {item}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
