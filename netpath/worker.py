"""What every background worker in the application shares.

Launching child processes without a console window, one relative-time
vocabulary for status strips, and a mixin carrying the thread handle, the
counter bump and the status ladder each worker used to repeat.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time

IS_WINDOWS = os.name == "nt"

# Under pythonw.exe — how the shortcut starts the app — Windows gives every
# child its own console, so each traceroute or nslookup flashes a black window
# on the desktop. CREATE_NO_WINDOW stops the console being created at all; the
# STARTUPINFO is belt and braces for older shells that honour the show-window
# flag instead.
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def hidden() -> dict:
    """Keyword arguments for subprocess that suppress a console window."""
    if not IS_WINDOWS:
        return {}

    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": CREATE_NO_WINDOW, "startupinfo": info}


def ago(ts: float) -> str:
    """How long ago `ts` was, in the wording the status strips use."""
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return f"{age / 3600:.1f}h ago"


class Worker:
    """One background thread with a status line.

    A mixin, not a base class: start() and stop() stay with each worker
    because what they set up differs, but the thread handle, the join, the
    locked counter bump and the error/stopped/running status ladder do not.
    """

    STOPPED_TEXT = "Worker stopped"
    THREAD_NAME = "worker"
    _thread: threading.Thread | None = None
    error: str | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _spawn(self, target=None, name: str | None = None) -> None:
        """Start the worker thread. Defaults to self._loop under THREAD_NAME."""
        self._thread = threading.Thread(
            target=target if target is not None else self._loop,
            name=name or self.THREAD_NAME, daemon=True)
        self._thread.start()

    def _join(self, timeout: float = 2.0) -> None:
        """Wait for the loop to end. A thread that outlives the timeout stays
        attached, so running() is honest and start() cannot spawn a second."""
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                return
        self._thread = None

    # ---------------------------------------------------- two-phase shutdown
    #
    # Service.shutdown() asks every worker to stop (begin_stop) before it
    # waits for any of them (finish_stop), so the waits overlap instead of
    # summing. Each worker's own stop()/shutdown() is unchanged and still
    # does both halves, because a settings hot-restart and the console's
    # buttons want exactly that; only the service teardown drives the pair
    # directly. `deadline` is an absolute time.monotonic() value shared by
    # every worker in the teardown, which is what bounds the whole thing.

    def begin_stop(self) -> None:
        """Ask the loop to end. Must not block. Overridden by workers that
        also own a thread pool or sockets to cancel."""
        self._stop.set()

    def finish_stop(self, deadline: float) -> None:
        """Wait for what begin_stop() asked to end, but no later than
        `deadline`. Overridden by workers that also drain in-flight work."""
        self._join(timeout=max(0.0, deadline - time.monotonic()))

    def _bump(self, key: str, by: int = 1) -> None:
        """counters[...] += 1 from a pool worker is a read-modify-write on a
        shared dict; under the lock the totals stay exact."""
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + by

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            return self.STOPPED_TEXT
        return self._running_text()

    def _running_text(self) -> str:
        """The status line while the worker is up."""
        return "Running"
