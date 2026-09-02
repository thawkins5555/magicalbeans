"""Runs every tests/test_*.py as its own process from the repo root and
reports PASS/FAIL per suite. Exit status is non-zero when any suite failed.

    python3 tests/run_all.py            # everything
    python3 tests/run_all.py --only mib # suites whose filename contains "mib"
"""
import glob
import os
import subprocess
import sys
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
TAIL = 15


def main(argv) -> int:
    only = ""
    if "--only" in argv:
        only = argv[argv.index("--only") + 1]
    suites = sorted(glob.glob(os.path.join(TESTS_DIR, "test_*.py")))
    suites = [s for s in suites if only in os.path.basename(s)]
    if not suites:
        print("no suites matched")
        return 2
    failed = []
    for path in suites:
        name = os.path.basename(path)
        started = time.time()
        try:
            run = subprocess.run([sys.executable, path], cwd=REPO_ROOT,
                                 capture_output=True, text=True, timeout=600)
            ok, output = run.returncode == 0, run.stdout + run.stderr
        except subprocess.TimeoutExpired as exc:
            ok, output = False, (exc.stdout or "") + (exc.stderr or "") + "\n<timed out after 600 s>"
        elapsed = time.time() - started
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({elapsed:.1f}s)", flush=True)
        if not ok:
            failed.append(name)
            for line in output.strip().splitlines()[-TAIL:]:
                print("      " + line)
    print()
    print(f"{len(suites) - len(failed)}/{len(suites)} suites passed"
          + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
