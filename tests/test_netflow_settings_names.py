"""NetFlow custom port and interface names are operator-typed text that every
viewer's flow table renders. api._check_netflow_settings refuses markup
characters before the save (api.post_settings calls it for scope "netflow").

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web import api

FAILS = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


for key in ("custom_ports", "interface_names"):
    try:
        api._check_netflow_settings({key: "22609 = <img src=x onerror=alert(1)>"})
        check(f"{key} with a tag is refused", False)
    except ValueError as exc:
        check(f"{key} with a tag is refused", "<" in str(exc), str(exc))
    try:
        api._check_netflow_settings({key: "22609 = NVR\n10.0.0.1:3 = Uplink to core"})
        check(f"{key} plain names are accepted", True)
    except ValueError as exc:
        check(f"{key} plain names are accepted", False, str(exc))

check("a request that doesn't mention either key is a no-op",
      api._check_netflow_settings({"enabled": True}) is None)

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
