"""CSV formatting shared outside the web layer.

Split out of netpath/web/api.py (which keeps thin aliases so nothing else
there had to change) so netpath/reportsched.py can build the same
formula-safe CSV text for an email attachment, without importing the web
package's route handlers just for two small functions.
"""

from __future__ import annotations

import csv
import io

# A spreadsheet treats a cell starting with one of these as a formula; the leading apostrophe is the conventional inert prefix.
CSV_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value):
    if isinstance(value, str) and value.startswith(CSV_FORMULA_LEAD):
        return "'" + value
    return value


def csv_text(header: list[str], rows) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows([csv_cell(cell) for cell in row] for row in rows)
    return "﻿" + buf.getvalue()
