#!/usr/bin/env python3
"""Verify package source/documentation hashes, or regenerate them with --write.

Generated reports, interpreter caches, and local environments are excluded.
The embedded historical ZIP is covered as one byte-for-byte preserved file.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
IGNORED_PARTS = {"reports", "__pycache__", ".venv", ".git", ".pytest_cache"}


def source_files():
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if not path.is_file() or path == MANIFEST:
            continue
        if any(part in IGNORED_PARTS for part in rel.parts) or path.suffix == ".pyc":
            continue
        yield rel.as_posix(), path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Regenerate the package source manifest")
    args = parser.parse_args()
    actual = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in source_files()}
    if args.write:
        MANIFEST.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(actual.items())), encoding="utf-8")
        print(f"Wrote {len(actual)} source/documentation hashes")
        return 0
    expected = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if name in expected:
            raise ValueError(f"Duplicate manifest path: {name}")
        expected[name] = digest
    problems = [name for name in sorted(set(expected) | set(actual)) if expected.get(name) != actual.get(name)]
    for name in problems:
        print(f"MISMATCH: {name}")
    print(f"{'RED' if problems else 'PASS'}: {len(expected)} source/documentation hashes; {len(problems)} mismatches")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
