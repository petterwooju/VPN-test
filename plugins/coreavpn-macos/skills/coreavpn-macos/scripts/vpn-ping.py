#!/usr/bin/env python3
"""Measure a user-confirmed macOS IKEv2 route without changing VPN or DNS settings."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
from uuid import uuid4

TARGET = "168.126.63.1"


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def route_interface():
    result = subprocess.run(["/sbin/route", "-n", "get", "-inet", TARGET],
                            capture_output=True, text=True, timeout=5)
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.M)
    if result.returncode or not match:
        raise RuntimeError("Cannot verify the destination route")
    return match[1]


def parse_ping(output):
    packets = re.search(r"(\d+) packets transmitted, (\d+)(?: packets)? received", output)
    if not packets:
        return None
    sent, received = map(int, packets.groups())
    if not sent or received > sent:
        return None
    summary = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+ ms", output)
    minimum, average, maximum = map(float, summary.groups()) if summary else (None, None, None)
    return dict(sent=sent, received=received, loss_pct=100 * (sent - received) / sent,
                minimum_ms=minimum, average_ms=average, maximum_ms=maximum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--tunnel", required=True, help="Observed macOS ipsecN interface")
    parser.add_argument("--log-dir", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"ipsec[0-9]+", args.tunnel):
        parser.error("The route must use the observed IKEv2 ipsec interface")
    if not re.fullmatch(r"[a-z0-9-]+\.coreavpn\.(net|com|kr)", args.server):
        parser.error("Use a CoreaVPN server hostname")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    raw = args.log_dir / f"ping-{args.server}-{uuid4().hex[:8]}.txt"
    entry = dict(started=timestamp(), server=args.server, target=TARGET, tunnel=args.tunnel,
                 ping=None, valid=False)
    try:
        if route_interface() != args.tunnel:
            raise RuntimeError("Destination route differs from the expected VPN before ping")
        with raw.open("x", encoding="utf-8") as output:
            result = subprocess.run(
                ["/sbin/ping", "-n", "-b", args.tunnel, "-c", "20", "-i", "1", "-t", "22", TARGET],
                stdout=output, stderr=subprocess.STDOUT, timeout=25
            )
        entry["ping_exit"] = result.returncode
        entry["ping"] = parse_ping(raw.read_text(encoding="utf-8", errors="replace"))
        if route_interface() != args.tunnel:
            raise RuntimeError("Destination route changed during ping")
        if entry["ping"] is None or entry["ping"]["sent"] != 20:
            raise RuntimeError("Ping did not complete 20 probes")
        entry["valid"] = True
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        entry["error"] = str(error)
    entry["ended"] = timestamp()
    if raw.exists():
        entry["raw_output"] = raw.name
    line = json.dumps(entry, ensure_ascii=False)
    with (args.log_dir / "ping-results.jsonl").open("a", encoding="utf-8") as log:
        log.write(line + "\n")
    print(line)
    return 0 if entry["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
