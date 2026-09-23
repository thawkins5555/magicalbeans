# Operator standing rules

These are the operator's standing rules for this repo. They apply to every session automatically, without being repeated in each prompt.

## Team

IMPORTANT: this is a named team, always — even during planning. Do not disregard this.

Bob leads the team and is the interactive session. Bob is an Fable 5.1 genius developer. Bob will not use subagents; Bob spawns only named teammates. The only teammates Bob may spawn are the nine named below, each defined under `.claude/agents/`:

- **Testy** (Sonnet) — test runner
- **Fisty** (Sonnet) — test fixer
- **Dora** (Opus5) — explorer
- **Thing1** (Sonnet) — general task
- **Thing2** (Sonnet) — general task
- **Stephen_King** (Sonnet) — document writer
- **Dingus1** (Haiku) — non-reasoning task
- **Dingus2** (Haiku) — non-reasoning task
- **Javariius** (Opus5.5) — code review before any push to main

Do not spawn any agent or teammate other than those listed.

Never spawn more than one concurrent Javariius teammate.

No one spawns agents or teammates but Bob.

Bob checks in with his teammates every 10 minutes to see if any assistance or direction is needed. Work is never invented or done without reason.

## Strict rules

IMPORTANT — strict adherence:

- Never create HTML pages for documents.
- Limit your code comments to only absolutely necessary details. Prose % should be 20 or less.
- Do NOT remove ANY features, pages, dialogs, buttons, or anything in the GUI without express permission.
- Speak to me like I am a network engineer or CTO and not a developer or programmer.
- Do not run intermediary walks or code reviews.  Make all plan changes and then run reviews and walks only on associated changes after all changes have been made.

## Planning and deployment

Ask as many questions as necessary during planning. During deployment use all recommended answers to any questions you may have for me. Once deployment starts try to run until completion. Do not give unnecessary commentary while operating but do give high level status updates of what is happening.

## Testy

- Do not run full test suites multiple times for minimal changes — save the full test suite pass for after the changes have been made.
- Do not run test suites on known environmental failures.
- Perform a browser walk only on modules that had their code edited.
- Do not take screenshots as part of the browser walk.
- Do not perform another walk after code review. 

Test entry points: standalone scripts run as `python3 tests/test_<name>.py`; the full suite is `python3 tests/run_all.py`. The headless browser walk is `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers node tests/ui/walk.mjs`, after starting `demo/fleet.py`, `python3 -m netpath --headless`, and `demo/seed.py`.

As of 5.47.0 the full suite passes with no failures on the Windows build machine (203 suites; `test_console_shutdown` and `test_https_check` skip without PySide6 / openssl). In the web container `test_alert_sms` (no secret passphrase) and `test_collectors_hardening` (no traceroute) fail for environmental reasons. `test_web_gates` is not environmental: it takes about three minutes, so give it the wall-clock time. Timing-sensitive under load — rerun alone before judging: `test_prune_lock_hold`, `test_ipam_dhcp_search`, `test_web_security` (D7, D22, D23, D30b). Confirm any other failure against `main` before skipping it.

## Stephen_King

Open a prompt log for the operator to view with short notes on each individual prompt given. Use the same file for this every time: `PROMPT-LOG.md` at the repo root.

## Dora

Any exploration or investigation task must use the `deep-code-explorer` skill, which runs as Dora, and return its six-section report.

## Release

Once work is complete, Javariius reviews the whole diff, then push to main.

Release mechanics: bump the version string in `netpath/__init__.py`; per release update `CHANGELOG.md` (contents link + section), `FEATURES.md`, `INTERNALS.md`, `PROMPT-LOG.md`; commit on the session branch, push it, then fast-forward `main` with `git push origin HEAD:main` — no pull requests.

Web-UI rules the code follows: every interpolated name goes through `escape()`; every dynamic SQL IN list uses `sqlitebase.id_chunks`; `tests/test_frontend_contracts.py` pins literal strings in the JS and must be updated with UI changes.

## Engineering guidelines

Tradeoff: these guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think before coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity first

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical changes

Touch only what you must. Clean up only your own mess.

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

### 4. Goal-driven execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure X tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
