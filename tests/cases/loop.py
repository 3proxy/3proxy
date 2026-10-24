"""The event loop on its own: tests/looptest.c, built by CMake next to the
3proxy binary, run with a few seeds for its timers. Skipped where it was not
built (the Makefiles do not build it)."""

import os
import subprocess


def run(t):
    name = "looptest.exe" if os.name == "nt" else "looptest"
    path = os.path.join(os.path.dirname(os.path.abspath(t.binary)), name)
    if not os.path.exists(path):
        t.skip("looptest is built by CMake only")
        return
    for seed in ("1", "2", "3"):
        try:
            done = subprocess.run([path, seed], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=120)
        except subprocess.TimeoutExpired:
            t.fail(f"looptest {seed} finishes")
            continue
        out = done.stdout.decode(errors="replace")
        for line in out.splitlines():
            if line.startswith("ok "):
                t.ok(f"seed {seed}: {line[3:]}")
            elif line.startswith("FAIL "):
                label, _, what = line[5:].partition(": ")
                t.fail(f"seed {seed}: {label}", actual=what)
        if done.returncode and "FAIL " not in out:
            t.fail(f"looptest {seed} exits cleanly", 0, done.returncode)
