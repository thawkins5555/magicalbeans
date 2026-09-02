"""Runs every tests/test_*.py as its own process from the repo root and
reports PASS/FAIL per suite. Exit status is non-zero when any suite failed.

    python3 tests/run_all.py            # everything
    python3 tests/run_all.py --only mib # suites whose filename contains "mib"

A suite that cannot run at all on this machine — the SSH terminal suite
needs paramiko, the one optional dependency the application has — exits
with SKIP_EXIT_CODE instead of failing, prints why on its last line, and is
reported as SKIP rather than counted. That is a deployment fact, not a
broken test; every other non-zero status is still a failure.
"""
import glob
import os
import subprocess
import sys
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
TAIL = 15
# `raise SystemExit(SKIP_EXIT_CODE)` from a suite with nothing it can test
# here. 77 is the automake convention for exactly this.
SKIP_EXIT_CODE = 77


def main(argv) -> int:
    only = ""
    if "--only" in argv:
        rest = argv[argv.index("--only") + 1:]
        if not rest:
            print("usage: run_all.py [--only <substring>]")
            return 2
        only = rest[0]
    suites = sorted(glob.glob(os.path.join(TESTS_DIR, "test_*.py")))
    suites = [s for s in suites if only in os.path.basename(s)]
    if not suites:
        print("no suites matched")
        return 2
    failed, skipped = [], []
    for path in suites:
        name = os.path.basename(path)
        started = time.time()
        code = 1
        try:
            run = subprocess.run([sys.executable, path], cwd=REPO_ROOT,
                                 capture_output=True, text=True, timeout=600)
            code, output = run.returncode, run.stdout + run.stderr
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "") + "\n<timed out after 600 s>"
        elapsed = time.time() - started
        if code == SKIP_EXIT_CODE:
            skipped.append(name)
            reason = (output.strip().splitlines() or ["no reason given"])[-1]
            print(f"SKIP  {name}  ({elapsed:.1f}s)  {reason.strip()}", flush=True)
            continue
        ok = code == 0
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({elapsed:.1f}s)", flush=True)
        if not ok:
            failed.append(name)
            for line in output.strip().splitlines()[-TAIL:]:
                print("      " + line)
    print()
    ran = len(suites) - len(skipped)
    print(f"{ran - len(failed)}/{ran} suites passed"
          + (f"; skipped: {', '.join(skipped)}" if skipped else "")
          + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
