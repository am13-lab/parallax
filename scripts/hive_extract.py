#!/usr/bin/env python3
"""Extract parallax report JSON from a hive workspace and merge them.

hive-sim logs one report per category test via t.Logf("report:\\n%s", ...).
hive collects those details into the workspace (simtests JSON and simulator
logs). This tool walks a workspace directory (or a single file), pulls out
every v1 report it finds, deduplicates them, merges the results into one
report, and writes it ready for:

    go run ./cmd/parallax analyze --report report.json --html

Usage:
    python3 scripts/hive_extract.py [--workspace hive/workspace] [--out report.json]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

MARKER = "report:"
DECODER = json.JSONDecoder()


def looks_like_report(obj):
    return (
        isinstance(obj, dict)
        and obj.get("schema_version") == 1
        and isinstance(obj.get("results"), list)
    )


def walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)


def extract_from_text(text, found):
    start = 0
    while True:
        i = text.find(MARKER, start)
        if i < 0:
            return
        chunk = text[i + len(MARKER):].lstrip()
        obj = None
        if chunk[:1] in ("{", "["):
            try:
                obj, _ = DECODER.raw_decode(chunk)
            except json.JSONDecodeError:
                obj = None
        if looks_like_report(obj):
            found.append(obj)
        start = i + len(MARKER)


def extract_file(path, found):
    try:
        text = path.read_text(errors="replace")
    except OSError as e:
        print(f"skip {path}: {e}", file=sys.stderr)
        return
    stripped = text.lstrip()
    if path.suffix == ".json" and stripped[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            if looks_like_report(data):
                found.append(data)
            else:
                # details fields embed the report as escaped text; walk the
                # parsed structure so we match against real newlines.
                for s in walk_strings(data):
                    extract_from_text(s, found)
                return
    extract_from_text(text, found)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def merge(reports):
    if len(reports) == 1:
        return reports[0]
    base = dict(reports[0])
    results = []
    for r in reports:
        results.extend(r.get("results") or [])
    base["results"] = results
    summary = {"total": 0, "passed": 0, "divergent": 0, "skipped": 0, "errors": 0, "executed": 0}
    for r in results:
        summary["total"] += 1
        st = r.get("status")
        key = {"pass": "passed", "divergent": "divergent", "skipped": "skipped", "error": "errors"}.get(st)
        if key:
            summary[key] += 1
        if st != "skipped":
            summary["executed"] += 1
    base["summary"] = summary
    starts = [r.get("started_at") for r in reports if r.get("started_at")]
    ends = [r.get("ended_at") for r in reports if r.get("ended_at")]
    if starts:
        base["started_at"] = min(starts)
    if ends:
        base["ended_at"] = max(ends)
    return base


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", default="hive/workspace",
                    help="hive workspace directory, or a single log/json file")
    ap.add_argument("--out", default="report.json", help="merged report output path")
    args = ap.parse_args()

    root = Path(args.workspace)
    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = sorted(p for p in root.rglob("*") if p.suffix in (".json", ".log") and p.is_file())
    else:
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    found = []
    for p in files:
        extract_file(p, found)

    seen = {}
    for r in found:
        seen.setdefault(hashlib.sha256(canonical(r).encode()).hexdigest(), r)
    unique = list(seen.values())
    if not unique:
        print(f"no parallax reports found under {root}", file=sys.stderr)
        return 1

    merged = merge(unique)
    Path(args.out).write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
    print(f"extracted {len(unique)} report(s) from {len(files)} file(s) "
          f"-> {args.out} ({merged.get('summary', {}).get('total', 0)} results)")
    print(f'next: go run ./cmd/parallax analyze --report {args.out} '
          f'--allowlist knowledge/known_divergences.json --html')
    return 0


if __name__ == "__main__":
    sys.exit(main())
