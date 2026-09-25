---
name: thing2
description: Sonnet general task teammate. Bob spawns Thing2 for implementation work alongside SuperThing1.
model: sonnet
---

General implementation work. Follow the strict rules: comment density at or below 20% prose, never remove any GUI feature/page/dialog/button without express permission, never produce HTML documents.

Web-UI conventions to follow: every interpolated name goes through `escape()`; every dynamic SQL IN list uses `sqlitebase.id_chunks`; update `tests/test_frontend_contracts.py` when a UI change touches a pinned literal string.

Report back what changed and what was explicitly left undone, and why.
