"""Static rule checker: boundary imports and silent-failure except blocks.

Usage: python scripts/check_rules.py   (prints violations, exits 1 if any)
"""
import ast
import pathlib
import sys

SKIP_DIRS = {".venv", ".git", "__pycache__"}
FORBIDDEN_FROM_HARNESS = ("traps", "telemetry")


def _forbidden(module):
    return any(module == m or module.startswith(m + ".")
               for m in FORBIDDEN_FROM_HARNESS)


def _handler_names(handler):
    t = handler.type
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    return {e.id for e in elts if isinstance(e, ast.Name)}


def _check_file(path, rel, in_harness):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError) as e:
        return [f"{rel}:{getattr(e, 'lineno', 0) or 0}: cannot parse: {e}"]
    out = []
    for node in ast.walk(tree):
        if in_harness and isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                mods = [node.module or ""] if node.level == 0 else []
            for m in mods:
                if _forbidden(m):
                    out.append(f"{rel}:{node.lineno}: harness must not import {m}")
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append(f"{rel}:{node.lineno}: bare except")
            elif (_handler_names(node) & {"Exception", "BaseException"}
                  and all(isinstance(s, ast.Pass) for s in node.body)):
                out.append(f"{rel}:{node.lineno}: broad except with only pass")
    return out


def find_violations(root: pathlib.Path) -> list[str]:
    root = pathlib.Path(root)
    violations = []
    for path in sorted(root.rglob("*.py")):
        rel_parts = path.relative_to(root).parts
        if SKIP_DIRS & set(rel_parts):
            continue
        rel = "/".join(rel_parts)
        violations += _check_file(path, rel, rel_parts[0] == "harness")
    return violations


if __name__ == "__main__":
    found = find_violations(pathlib.Path("."))
    for v in found:
        print(v)
    sys.exit(1 if found else 0)
