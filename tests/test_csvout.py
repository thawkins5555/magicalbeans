"""netpath/csvout.py: the CSV formatting shared by the web export routes and
reportsched's email attachment. test_csv_export.py only tolerates the BOM
(`if text.startswith(...)`), so this pins the surface that suite leaves
unpinned: the BOM itself, the \\r\\n row terminator, csv_cell passing a
non-str value through unchanged, and the two CSV_FORMULA_LEAD members
("\\t", "\\r") no route currently feeds.
"""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.csvout import CSV_FORMULA_LEAD, csv_cell, csv_text

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------------- csv_cell

check("CSV_FORMULA_LEAD covers tab and carriage return, not just = + - @",
      "\t" in CSV_FORMULA_LEAD and "\r" in CSV_FORMULA_LEAD, CSV_FORMULA_LEAD)

for lead in CSV_FORMULA_LEAD:
    cell = csv_cell(lead + "x")
    check(f"a cell starting with {lead!r} is made inert with a leading apostrophe",
          cell == "'" + lead + "x", cell)

check("an ordinary string is untouched",
      csv_cell("ordinary") == "ordinary", csv_cell("ordinary"))

# .startswith() would raise TypeError on a non-str; csv_text feeds csv_cell
# every cell in every row, including ids and counts that were never strings.
for value in (42, 3.14, None, True, False):
    check(f"csv_cell passes a non-str value through unchanged: {value!r}",
          csv_cell(value) is value, csv_cell(value))

# ------------------------------------------------------------------- csv_text

text = csv_text(["a", "b"], [["1", "2"], ["3", "4"]])
check("csv_text leads with the UTF-8 BOM", text.startswith("﻿"), text[:1])
check("csv_text's rows are terminated with \\r\\n, not a bare \\n",
      text[1:] == "a,b\r\n1,2\r\n3,4\r\n", text[1:])

check("csv_text runs csv_cell on every row, not just the first",
      csv_text(["m"], [["=cmd"], ["ok"], ["+2"]])
      == "﻿m\r\n'=cmd\r\nok\r\n'+2\r\n")

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
