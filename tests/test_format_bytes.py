"""services.format_bytes is decimal (base 1000), matching how the network
industry counts a byte count for display -- KB/MB/GB/TB labels kept as they
were, only the divisor changed.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.services import format_bytes

FAILS = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


check("1,000,000 bytes is 1.0 MB", format_bytes(1_000_000) == "1.0 MB",
      format_bytes(1_000_000))
check("1,000 bytes is 1.0 KB", format_bytes(1_000) == "1.0 KB", format_bytes(1_000))
check("1,000,000,000 bytes is 1.0 GB",
      format_bytes(1_000_000_000) == "1.0 GB", format_bytes(1_000_000_000))
check("1,000,000,000,000 bytes is 1.0 TB",
      format_bytes(1_000_000_000_000) == "1.0 TB", format_bytes(1_000_000_000_000))
check("under 1000 bytes is whole bytes", format_bytes(512) == "512 B", format_bytes(512))
check("zero is 0 B", format_bytes(0) == "0 B", format_bytes(0))
# Under the old base-1024 divisor this read as 1.4 MB (1,500,000 / 1024 /
# 1024); base 1000 reads it as 1.5 MB, the same figure a disk vendor or an
# ISP would print for it.
check("1,500,000 bytes is 1.5 MB, not the 1.4 MB base 1024 would print",
      format_bytes(1_500_000) == "1.5 MB", format_bytes(1_500_000))

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
