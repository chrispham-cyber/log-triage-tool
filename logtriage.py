#!/usr/bin/env python3
"""
logtriage - a small SSH auth.log triage tool.

Reads Linux auth logs, pulls out SSH authentication events, and flags likely
brute-force activity and suspicious successful logins. Standard library only.

Usage:
    python3 logtriage.py /var/log/auth.log
    python3 logtriage.py samples/auth.log --threshold 5 --window 120
    python3 logtriage.py /var/log/auth.log --json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# --- log line patterns -------------------------------------------------------
# Matches both classic syslog timestamps ("Sep 17 05:00:19") and ISO 8601
# timestamps ("2026-09-17T05:00:19...") that newer distros write.
TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_USER = re.compile(r"Failed password for invalid user (?P<user>\S+)")


def parse_timestamp(line):
    """Return a datetime if we can read one off the line, else None."""
    m = TS_ISO.match(line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1))
        except ValueError:
            return None
    m = TS_SYSLOG.match(line)
    if m:
        # Syslog omits the year; assume the current one.
        try:
            return datetime.strptime(
                f"{datetime.now().year} {m.group(1)}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None
    return None


def parse(lines):
    """Walk the log and collect failed and accepted SSH auth events."""
    failed, accepted = [], []
    for line in lines:
        ts = parse_timestamp(line)
        m = FAILED.search(line)
        if m:
            failed.append(
                {
                    "ts": ts,
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                    "invalid_user": bool(INVALID_USER.search(line)),
                }
            )
            continue
        m = ACCEPTED.search(line)
        if m:
            accepted.append({"ts": ts, "user": m.group("user"), "ip": m.group("ip")})
    return failed, accepted


def detect_bruteforce(failed, threshold, window):
    """
    Flag an IP when it racks up >= threshold failures inside a `window`-second
    sliding window. Returns one finding per offending IP.
    """
    by_ip = defaultdict(list)
    for e in failed:
        by_ip[e["ip"]].append(e)

    findings = []
    for ip, events in by_ip.items():
        timed = sorted([e for e in events if e["ts"]], key=lambda e: e["ts"])
        burst = 0
        # Sliding window over timestamped failures.
        if timed:
            start = 0
            for i in range(len(timed)):
                while (timed[i]["ts"] - timed[start]["ts"]).total_seconds() > window:
                    start += 1
                burst = max(burst, i - start + 1)
        # Fall back to a raw count if the log had no usable timestamps.
        count = len(events)
        if burst >= threshold or (not timed and count >= threshold):
            users = sorted({e["user"] for e in events})
            times = [e["ts"] for e in timed]
            findings.append(
                {
                    "ip": ip,
                    "failures": count,
                    "peak_in_window": burst,
                    "users_tried": users,
                    "first_seen": times[0].isoformat() if times else None,
                    "last_seen": times[-1].isoformat() if times else None,
                    "mitre": "T1110",
                }
            )
    return sorted(findings, key=lambda f: f["failures"], reverse=True)


def detect_compromise(failed, accepted):
    """A success from an IP that also failed a lot may be a cracked password."""
    failed_ips = defaultdict(int)
    for e in failed:
        failed_ips[e["ip"]] += 1
    hits = []
    for a in accepted:
        if failed_ips.get(a["ip"], 0) >= 3:
            hits.append(
                {
                    "ip": a["ip"],
                    "user": a["user"],
                    "prior_failures": failed_ips[a["ip"]],
                    "ts": a["ts"].isoformat() if a["ts"] else None,
                    "mitre": "T1110 -> T1078",
                }
            )
    return hits


def top(counter, n=5):
    return sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:n]


def build_report(failed, accepted, bruteforce, compromise):
    ip_counts, user_counts = defaultdict(int), defaultdict(int)
    for e in failed:
        ip_counts[e["ip"]] += 1
        user_counts[e["user"]] += 1
    return {
        "totals": {
            "failed_logins": len(failed),
            "accepted_logins": len(accepted),
            "unique_source_ips": len(ip_counts),
        },
        "bruteforce_findings": bruteforce,
        "possible_compromise": compromise,
        "top_source_ips": top(ip_counts),
        "top_targeted_users": top(user_counts),
    }


def print_report(r):
    t = r["totals"]
    print("=" * 60)
    print("  SSH AUTH LOG TRIAGE REPORT")
    print("=" * 60)
    print(f"  Failed logins   : {t['failed_logins']}")
    print(f"  Accepted logins : {t['accepted_logins']}")
    print(f"  Unique src IPs  : {t['unique_source_ips']}")

    print("\n  [!] BRUTE-FORCE FINDINGS (MITRE T1110)")
    if not r["bruteforce_findings"]:
        print("      none")
    for f in r["bruteforce_findings"]:
        print(
            f"      {f['ip']}: {f['failures']} failures "
            f"(peak {f['peak_in_window']} in window), "
            f"users tried: {', '.join(f['users_tried'][:8])}"
        )
        if f["first_seen"]:
            print(f"          window: {f['first_seen']} -> {f['last_seen']}")

    print("\n  [!!] POSSIBLE COMPROMISE (success after many failures)")
    if not r["possible_compromise"]:
        print("      none")
    for c in r["possible_compromise"]:
        print(
            f"      {c['ip']} logged in as '{c['user']}' "
            f"after {c['prior_failures']} failures  [{c['mitre']}]"
        )

    print("\n  Top source IPs   :", ", ".join(f"{ip}({n})" for ip, n in r["top_source_ips"]))
    print("  Top targeted users:", ", ".join(f"{u}({n})" for u, n in r["top_targeted_users"]))
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description="Triage SSH auth logs for brute force.")
    ap.add_argument("logfile", help="path to an auth.log style file, or - for stdin")
    ap.add_argument("--threshold", type=int, default=5,
                    help="failures from one IP to flag as brute force (default 5)")
    ap.add_argument("--window", type=int, default=120,
                    help="sliding window in seconds for the threshold (default 120)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args()

    stream = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace")
    with stream as fh:
        failed, accepted = parse(fh)

    bruteforce = detect_bruteforce(failed, args.threshold, args.window)
    compromise = detect_compromise(failed, accepted)
    report = build_report(failed, accepted, bruteforce, compromise)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    # Non-zero exit if anything fired, so it's CI/cron friendly.
    sys.exit(1 if bruteforce or compromise else 0)


if __name__ == "__main__":
    main()
