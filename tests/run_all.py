"""Runs every tests/test_*.py as its own process from the repo root and
reports PASS/FAIL per suite. Exit status is non-zero when any suite failed.

    python3 tests/run_all.py            # everything
    python3 tests/run_all.py --only mib # suites whose filename contains "mib"

A suite that cannot run at all on this machine — the two SSH suites need
paramiko, the one optional dependency the application has — exits with
SKIP_EXIT_CODE instead of failing, prints why on its last line, and is
reported as SKIP rather than counted. That is a deployment fact, not a
broken test; every other non-zero status is still a failure. When nothing
ran at all the summary says so rather than "0/0 suites passed".
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
            # encoding/errors rather than text=True: text=True decodes with the
            # locale encoding, which on Windows is cp1252, and every suite here
            # prints em dashes. That raised UnicodeDecodeError inside the reader
            # thread, left run.stdout as None, and killed the whole runner on the
            # first suite whose output said "—" instead of reporting a result.
            run = subprocess.run([sys.executable, path], cwd=REPO_ROOT,
                                 capture_output=True, timeout=600,
                                 encoding="utf-8", errors="replace")
            code, output = run.returncode, (run.stdout or "") + (run.stderr or "")
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
    if not ran:
        # Everything skipped: "0/0 suites passed" reads like a pass and is
        # meaningless either way. Say what actually happened. Still exit 0 —
        # a missing optional dependency is a deployment fact, not a failure.
        print(f"no suites ran; skipped: {', '.join(skipped)}")
        return 0
    print(f"{ran - len(failed)}/{ran} suites passed"
          + (f"; skipped: {', '.join(skipped)}" if skipped else "")
          + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
