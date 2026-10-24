"""The event loop and fibers on their own: tests/looptest.c and
tests/fibertest.c, built by CMake next to the 3proxy binary, each run with
a few seeds. Skipped where they were not built (the Makefiles do not build
them)."""

import os
import subprocess


def run(t):
    here = os.path.dirname(os.path.abspath(t.binary))
    for unit in ("looptest", "fibertest"):
        path = os.path.join(here, unit + (".exe" if os.name == "nt" else ""))
        if not os.path.exists(path):
            t.skip(f"{unit} is built by CMake only")
            continue
        for seed in ("1", "2", "3"):
            try:
                done = subprocess.run([path, seed], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, timeout=120)
            except subprocess.TimeoutExpired:
                t.fail(f"{unit} {seed} finishes")
                continue
            out = done.stdout.decode(errors="replace")
            for line in out.splitlines():
                if line.startswith("ok "):
                    t.ok(f"{unit} {seed}: {line[3:]}")
                elif line.startswith("FAIL "):
                    label, _, what = line[5:].partition(": ")
                    t.fail(f"{unit} {seed}: {label}", actual=what)
            if done.returncode and "FAIL " not in out:
                t.fail(f"{unit} {seed} exits cleanly", 0, done.returncode)
