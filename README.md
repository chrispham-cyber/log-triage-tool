# logtriage

A small command-line tool that reads Linux SSH auth logs and flags likely
brute-force activity and suspicious logins. Written in plain Python (standard
library only, no installs), so it runs anywhere.

I built it as a follow-on to my [home SOC lab](https://github.com/chrispham-cyber/home-soc-lab):
after generating an SSH brute force against my lab with hydra, I wanted a script that
would surface that attack from the raw logs the way an analyst triages them.

## What it does

- Parses `Failed password` and `Accepted` SSH events (handles both classic syslog and
  ISO 8601 timestamps).
- Flags **brute force** (MITRE T1110): an IP with N+ failures inside a sliding time
  window, with the usernames it tried and the time span.
- Flags **possible compromise** (T1110 to T1078): a successful login from an IP that
  had just failed many times.
- Prints top source IPs and top targeted users.
- `--json` for piping into other tooling; exits non-zero when anything fires, so it
  drops into a cron job or CI step.

## Usage

```bash
python3 logtriage.py /var/log/auth.log
python3 logtriage.py samples/auth.log --threshold 5 --window 120
python3 logtriage.py /var/log/auth.log --json
cat /var/log/auth.log | python3 logtriage.py -
```

- `--threshold` failures from one IP to call it brute force (default 5)
- `--window` sliding window in seconds for that threshold (default 120)

## Example

Run against `samples/auth.log` (the real hydra brute force from my SOC lab):

```
============================================================
  SSH AUTH LOG TRIAGE REPORT
============================================================
  Failed logins   : 20
  Accepted logins : 2
  Unique src IPs  : 1

  [!] BRUTE-FORCE FINDINGS (MITRE T1110)
      192.168.3.135: 20 failures (peak 20 in window), users tried: ubuntu
          window: 2026-09-17T05:00:19 -> 2026-09-17T05:00:38
  ...
```

## Samples

- `samples/auth.log` mirrors the actual brute force I ran in the SOC lab (hydra vs
  one host, 20 tries, user `ubuntu`).
- `samples/auth_compromised.log` is a small synthetic log used to exercise the
  compromise detector (failures followed by a success from the same IP).

## Limits / next steps

- SSH only right now. Windows Event Log and web-server (nginx/apache) parsers would be
  the natural next parsers to add.
- Detection is threshold-based. A production setup would push these events into a SIEM
  (like the Wazuh instance in my SOC lab) and correlate across sources.
- No geo/reputation lookups yet; adding an IP reputation check would cut false
  positives from noisy-but-benign sources.
