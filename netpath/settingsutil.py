"""Type coercion for settings dicts loaded from or written to the settings table.

save_settings() only filters by key -- it never checks that a value's type
matches the corresponding default, so anything JSON-serializable can land in
the database under a known key. settings() then loads whatever was stored
and hands it straight to callers, several of which do arithmetic on it (for
example Service.__init__ does int(settings["trace_workers"])). A null once
written through the settings API, or a browser-side Number("abc") turning
into NaN and then JSON-encoding to null, is therefore enough to make every
subsequent startup raise TypeError before the service ever comes up.

coerce_settings() is the single place that turns raw stored/submitted values
into values that match their defaults' types. The API's post_settings hook
calls it with strict=True so a bad submission is rejected with a 400 instead
of being written at all; every settings() loader calls it with strict=False
so a database that is already poisoned (from before this fix, or from a
future bug) still falls back to sane defaults and the service still starts.
"""

import math

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}


def _coerce_bool(value):
    if isinstance(value, bool):
        return value, True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 0:
            return False, True
        if value == 1:
            return True, True
        return None, False
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _BOOL_TRUE:
            return True, True
        if text in _BOOL_FALSE:
            return False, True
    return None, False


def _coerce_number(value, kind):
    if isinstance(value, bool) or value is None:
        return None, False
    if isinstance(value, (int, float)):
        num = value
    elif isinstance(value, str):
        try:
            num = float(value)
        except (ValueError, TypeError):
            return None, False
    else:
        return None, False
    if isinstance(num, float) and (math.isnan(num) or math.isinf(num)):
        return None, False
    return (int(num) if kind is int else float(num)), True


def _coerce_list_of_str(value):
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value), True
    return None, False


def _coerce_str(value):
    if isinstance(value, bool):
        return None, False
    if isinstance(value, str):
        return value, True
    if isinstance(value, (int, float)):
        return str(value), True
    return None, False


def coerce_settings(defaults: dict, values: dict, *, strict: bool) -> dict:
    """Coerce each key in `values` that also exists in `defaults` to match
    that default's type. Keys not present in `defaults` are dropped.

    strict=True: a value that cannot be coerced raises
    ValueError(f"{key} must be a {kind}"). strict=False: it is replaced with
    the default value instead.

    Only the keys present in `values` come back. post_settings hands the
    result to an apply_* method that update()s the live dict, so a result
    padded out with every default would reset each setting the request did
    not mention.
    """
    result = {}
    for key, value in values.items():
        if key not in defaults:
            continue
        default = defaults[key]
        if isinstance(default, bool):
            coerced, ok = _coerce_bool(value)
            kind = "true/false value"
        elif isinstance(default, int):
            coerced, ok = _coerce_number(value, int)
            kind = "number"
        elif isinstance(default, float):
            coerced, ok = _coerce_number(value, float)
            kind = "number"
        elif isinstance(default, list):
            coerced, ok = _coerce_list_of_str(value)
            kind = "list of strings"
        elif isinstance(default, str):
            coerced, ok = _coerce_str(value)
            kind = "string"
        else:
            coerced, ok = value, True
        if ok:
            result[key] = coerced
        elif strict:
            raise ValueError(f"{key} must be a {kind}")
        else:
            result[key] = default
    return result
