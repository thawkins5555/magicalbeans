"""Location-tolerant source readers for the suites that assert on shipped
source as text. A block is found by NAME, so moving it within a file, or to a
sibling file in the same group, does not break the suite; deleting or
renaming it raises SourceError."""
import ast
import os
import re

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
NETPATH = os.path.join(REPO_ROOT, "netpath")
STATIC = os.path.join(NETPATH, "web", "static")


class SourceError(LookupError):
    pass


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def static_text(*names):
    """The named static files joined in order: a page module plus the lazy
    extras cut out of it read as one source."""
    return "\n".join(_read(os.path.join(STATIC, name)) for name in names)


def python_files(dotted):
    """Every .py file of netpath.<dotted>, whether it is a module or a
    package, sorted. `dotted` is relative to netpath ("web.api")."""
    base = os.path.join(NETPATH, *dotted.split("."))
    if os.path.isfile(base + ".py"):
        return [base + ".py"]
    if not os.path.isdir(base):
        raise SourceError("no module or package netpath.%s" % dotted)
    found = []
    for root, _dirs, files in os.walk(base):
        found.extend(os.path.join(root, f) for f in files if f.endswith(".py"))
    return sorted(found)


def python_text(dotted):
    return "\n".join(_read(path) for path in python_files(dotted))


def python_functions(dotted):
    """{name: (ast node, source segment)} for every top-level function of the
    module or package. A name defined in two files raises."""
    out = {}
    for path in python_files(dotted):
        text = _read(path)
        for node in ast.parse(text).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in out:
                    raise SourceError("%s is defined twice in netpath.%s" % (node.name, dotted))
                out[node.name] = (node, ast.get_source_segment(text, node))
    return out


def python_function(dotted, name):
    try:
        return python_functions(dotted)[name][1]
    except KeyError:
        raise SourceError("no function %s in netpath.%s" % (name, dotted)) from None


def _only(pattern, text, what):
    found = list(re.finditer(pattern, text, re.M))
    if len(found) != 1:
        raise SourceError("%d matches for %s, expected one" % (len(found), what))
    return found[0]


def _block(text, opener, what):
    """From the line matching `opener` (group 1 = its indentation) to the
    first later line that closes at the same indentation. A block whose
    braces do not balance was cut short, and raises."""
    found = _only(opener, text, what)
    closer = re.compile(r"^%s[}\])]" % re.escape(found.group(1)), re.M)
    end = closer.search(text, found.end())
    if not end:
        raise SourceError("%s never closes" % what)
    line_end = text.find("\n", end.end())
    return text[found.start():len(text) if line_end < 0 else line_end]


def js_function(text, name):
    """`function name(...) { ... }` (sync or async, any indentation)."""
    opener = r"^([ \t]*)(?:async[ \t]+)?function[ \t]+%s[ \t]*\(" % re.escape(name)
    return _block(text, opener, "function %s" % name)


def js_functions(text, *names):
    return "\n".join(js_function(text, name) for name in names)


def js_const(text, name):
    """`const|let name = ...` through its closing bracket; a one-line
    declaration is returned as that line."""
    opener = r"^([ \t]*)(?:const|let|var)[ \t]+%s\b" % re.escape(name)
    found = _only(opener, text, "declaration %s" % name)
    return _balanced(text, found.start(), ";", "declaration %s" % name)


def _balanced(text, start, last, what):
    """From `start` to the end of the first line that ends with `last` while
    every bracket opened since `start` is closed again."""
    depth = 0
    pos = start
    while pos < len(text):
        line_end = text.find("\n", pos)
        line_end = len(text) if line_end < 0 else line_end
        line = text[pos:line_end]
        depth += sum(line.count(c) for c in "([{") - sum(line.count(c) for c in ")]}")
        if depth <= 0 and line.rstrip().endswith(last):
            return text[start:line_end]
        pos = line_end + 1
    raise SourceError("%s never closes" % what)


def css_block(text, header):
    """A nested at-rule (`@keyframes name`, `@media (...)`) through its
    matching closing brace."""
    found = _only(r"^[ \t]*%s[ \t]*\{" % re.escape(header), text, "CSS block %s" % header)
    return _balanced(text, found.start(), "}", "CSS block %s" % header)


def css_rule(text, selector):
    """The one rule whose selector list is exactly `selector`."""
    return _only(r"^[ \t]*%s[ \t]*\{[^}]*\}" % re.escape(selector), text,
                 "CSS rule %s" % selector).group(0)
