#!/usr/bin/env python3
"""compare-audit.py - Diff two audit JSON reports (baseline vs. after).

Accepts output from any of the toolkit's auditors:
  linux/audit.sh --json              {"summary": ..., "results": [...]}
  windows/Invoke-HardeningAudit.ps1  {"Summary": ..., "Results": [...]}
  windows/Invoke-ADAudit.ps1         {"Summary": ..., "Results": [...]}

Usage:
  compare-audit.py BEFORE.json AFTER.json [--all]

Exit: 0 no regressions | 1 regressions present | 2 usage/parse error
"""

import json
import signal
import sys

# Exit quietly when piped into head/less instead of a BrokenPipeError trace.
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

RANK = {"PASS": 0, "NOTAPPLICABLE": 0, "N/A": 0, "UNKNOWN": 1, "WARN": 2, "FAIL": 3}


def load(path):
    try:
        # utf-8-sig: Windows PowerShell 5.1 writes a BOM with -Encoding UTF8.
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.exit(f"compare-audit: cannot read {path}: {exc}")

    lower = {k.lower(): v for k, v in doc.items()} if isinstance(doc, dict) else {}
    results = lower.get("results")
    if not isinstance(results, list):
        sys.exit(f"compare-audit: {path} has no results array")

    checks = {}
    for r in results:
        r = {k.lower(): v for k, v in r.items()}
        cid = str(r.get("id", "")).strip()
        if not cid:
            continue
        checks[cid] = {
            "status": str(r.get("status", "UNKNOWN")).upper(),
            "title": str(r.get("title", "")),
            "severity": str(r.get("severity", "")),
            "observed": str(r.get("observed", "")),
        }
    summary = {k.lower(): v for k, v in (lower.get("summary") or {}).items()}
    return checks, summary


def score(checks):
    graded = [c for c in checks.values() if c["status"] in ("PASS", "FAIL", "WARN")]
    if not graded:
        return 0
    return round(100 * sum(c["status"] == "PASS" for c in graded) / len(graded))


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    show_all = "--all" in argv
    if len(args) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    before, _ = load(args[0])
    after, _ = load(args[1])

    regressed, improved, changed, added, removed = [], [], [], [], []
    for cid in sorted(set(before) | set(after)):
        b, a = before.get(cid), after.get(cid)
        if b is None:
            added.append((cid, a))
        elif a is None:
            removed.append((cid, b))
        elif b["status"] != a["status"]:
            delta = RANK.get(a["status"], 1) - RANK.get(b["status"], 1)
            bucket = regressed if delta > 0 else improved if delta < 0 else changed
            bucket.append((cid, b, a))

    sb, sa = score(before), score(after)
    print(f"Score    : {sb}% -> {sa}% ({sa - sb:+d})")
    print(f"Checks   : {len(before)} -> {len(after)}")
    print(f"Improved : {len(improved)}   Regressed : {len(regressed)}   "
          f"Other changes : {len(changed)}")
    print()

    def show(title, rows):
        if not rows:
            return
        print(f"--- {title} ---")
        for cid, b, a in rows:
            sev = f" [{a['severity']}]" if a["severity"] else ""
            print(f"  {cid:<10} {b['status']:>7} -> {a['status']:<7}{sev} {a['title']}")
            if a["status"] in ("FAIL", "WARN") and a["observed"]:
                print(f"             observed: {a['observed']}")
        print()

    show("REGRESSIONS", regressed)
    show("IMPROVEMENTS", improved)
    show("OTHER CHANGES", changed)

    if show_all or added or removed:
        for title, rows in (("NEW CHECKS", added), ("REMOVED CHECKS", removed)):
            if rows:
                print(f"--- {title} ---")
                for cid, c in rows:
                    print(f"  {cid:<10} {c['status']:<7} {c['title']}")
                print()

    still = [(cid, c) for cid, c in sorted(after.items())
             if c["status"] == "FAIL" and c["severity"] in ("Critical", "High")]
    if still:
        print("--- STILL FAILING (Critical/High) ---")
        for cid, c in still:
            print(f"  [{c['severity']}] {cid} - {c['title']}")
        print()

    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
