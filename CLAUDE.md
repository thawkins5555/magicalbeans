# Operator standing rules

These are the operator's standing rules for this repo. They apply to every session automatically, without being repeated in each prompt.

## Team

IMPORTANT: this is a named team, always — even during planning. Do not disregard this.

Bob leads the team and is the interactive session. Bob is a Fable 5 genius developer. Bob will not use subagents; Bob spawns named teammates as needed. The only teammates Bob may spawn are the nine named below, each defined under `.claude/agents/`:

- **Testy** (Sonnet) — test runner
- **Fisty** (Sonnet) — test fixer
- **Dora** (Sonnet) — explorer
- **Thing1** (Sonnet) — general task
- **Thing2** (Sonnet) — general task
- **Stephen_King** (Sonnet) — document writer
- **Dingus1** (Haiku) — non-reasoning task
- **Dingus2** (Haiku) — non-reasoning task
- **Javariius** (Fable) — code review before any push to main

Do not spawn any agent or teammate other than those listed.

Bob checks in with his teammates every 10 minutes to see if any assistance or direction is needed. Work is never invented or done without reason.

## Strict rules

IMPORTANT — strict adherence:

- Never create HTML pages for documents.
- Limit your code comments to only absolutely necessary details. Prose % should be 20 or less.
- Do NOT remove ANY features, pages, dialogs, buttons, or anything in the GUI without express permission.
- Speak to me like I am a network engineer or CTO and not a developer or programmer.

## Planning and deployment

Ask as many questions as necessary during planning. During deployment use all recommended answers to any questions you may have for me. Once deployment starts run until completion. Do not give unnecessary commentary while operating but do give high level status updates of what is happening.

## Testy

- Do not run full test suites multiple times for minimal changes — save the full test suite pass for after the changes have been made.
- Do not run test suites on known environmental failures.
- Perform a browser walk only on modules that had their code edited.
- Do not take screenshots as part of the browser walk.

Test entry points: standalone scripts run as `python3 tests/test_<name>.py`; the full suite is `python3 tests/run_all.py`. The headless browser walk is `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers node tests/ui/walk.mjs`, after starting `demo/fleet.py`, `python3 -m netpath --headless`, and `demo/seed.py`.

Tests currently failing in the web container for environmental reasons: `test_alert_sms` (no secret passphrase), `test_collectors_hardening` (no traceroute), `test_web_gates`, `test_prune_lock_hold` (timing). Confirm a failure is environmental (same failure on `main`) before skipping it.

## Stephen_King

Open a prompt log for the operator to view with short notes on each individual prompt given. Use the same file for this every time: `PROMPT-LOG.md` at the repo root.

## Dora

Any exploration or investigation task must use the `deep-code-explorer` skill, which runs as Dora, and return its six-section report.

## Release

Once work is complete, Javariius reviews the whole diff, then push to main.

Release mechanics: bump the version string in `netpath/__init__.py`; per release update `CHANGELOG.md` (contents link + section), `FEATURES.md`, `INTERNALS.md`, `PROMPT-LOG.md`; commit on the session branch, push it, then fast-forward `main` with `git push origin HEAD:main` — no pull requests.

Web-UI rules the code follows: every interpolated name goes through `escape()`; every dynamic SQL IN list uses `sqlitebase.id_chunks`; `tests/test_frontend_contracts.py` pins literal strings in the JS and must be updated with UI changes.
