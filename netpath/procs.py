"""Launching child processes without a console window.

The app shells out to traceroute and nslookup. When the parent has a console
those children inherit it and nothing appears. When it does not — running under
pythonw.exe, which is how the shortcut starts it — Windows gives each child its
own console, so every trace flashes a black window on the desktop.

CREATE_NO_WINDOW stops the console being created at all. The STARTUPINFO is
belt and braces for older shells that honour the show-window flag instead.
"""

from __future__ import annotations

import os
import subprocess

IS_WINDOWS = os.name == "nt"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def hidden() -> dict:
    """Keyword arguments for subprocess that suppress a console window."""
    if not IS_WINDOWS:
        return {}

    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": CREATE_NO_WINDOW, "startupinfo": info}
