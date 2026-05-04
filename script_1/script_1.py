#!/usr/bin/env python3
"""
script.py
Usage: sudo python3 script.py [output_dir]

Phases per target:
  1. Baseline  - plain ping to host using icmpv6
  2. EH probes - ping followed by trace for each of: hbh (HBH8), frag (FH512), dst (DO8)
  3. Diagnose  - flarex diagnose per EH
"""

import csv
import os
import re
import sys
import subprocess
import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_FILE = HERE / "targets_1000.csv"
FLAREX = HERE.parent / ".venv/bin/flarex"

EH_TYPES = {
    "hbh":  ("HBH8",  []),
    "frag": ("FH512", ["--payload-size", "512"]),
    "dst":  ("DO8",   []),
}


def new_result(index, host):
    return {
        "index": index,
        "host": host,
        "baseline_loss": None,
        "ping_loss": {},
        "trace": {},
        "diagnose": {},
        "diag_hop": {},
    }

def run(args, out):
    """Run a flarex command, append output to file, return stdout (None on error)."""
    cmd = [str(FLAREX)] + args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    with open(out, "a") as f:
        f.write("\n$ " + " ".join(cmd) + "\n")
        f.write("-" * 60 + "\n")
        f.write(proc.stdout)
        if proc.stderr:
            f.write(proc.stderr)
    if proc.returncode != 0:
        return None
    return proc.stdout

def parse_ping_loss(output):
    if not output:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", output)
    if m:
        return float(m.group(1))
    return None

def parse_trace(output):
    if not output:
        return "N/A"
    if "routing loop detected" in output:
        return "LOOP"
    if "max hops reached" in output:
        return "MAXHOP"
    if "Traceroute complete." in output:
        return "REACH"
    return "N/A"

def parse_diagnose(output):
    if not output:
        return "N/A", None
    if "no packet loss detected" in output:
        return "CLEAN", None
    m = re.search(r"filtering hop identified\s+[--]\s+(\S+)", output)
    if m:
        return "FILT", m.group(1)
    if "no filtering hop identified" in output:
        return "LOSS", None
    return "N/A", None

def parse_csv(path):
    targets = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            idx = row[0].strip()
            host = row[1].strip()
            targets.append((idx, host))
    return targets

def fmt_loss(v):
    if v is None:
        return "N/A"
    return f"{v:g}%"

def sorted_by_count(counts):
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)

def write_summary(results, out_dir):
    sep  = "=" * 100
    dash = "-" * 100
    col_fmt    = "{:<5} {:<20} {:<6} | {:<6} {:<6} {:<7} {:<6} {:<6} {:<7} {:<6} {:<6} {:<7}"
    header_fmt = "{:<5} {:<20} {:<6} | {:<20} {:<20} {:<20}"

    lines = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(sep)
    lines.append(f" flarex EH probe report - {now}")
    lines.append(sep)
    lines.append(header_fmt.format("", "", "", "HBH", "FRAG", "DST"))
    lines.append(col_fmt.format("IDX", "HOST", "BASE",
                                "ping", "trace", "diag",
                                "ping", "trace", "diag",
                                "ping", "trace", "diag"))
    lines.append(dash)

    for r in results:
        row = [r["index"], r["host"], fmt_loss(r["baseline_loss"])]
        for eh in ("hbh", "frag", "dst"):
            row.append(fmt_loss(r["ping_loss"].get(eh)))
            row.append(r["trace"].get(eh, "N/A"))
            row.append(r["diagnose"].get(eh, "N/A"))
        lines.append(col_fmt.format(*row))
    lines.append(dash)


    eligible = [r for r in results if r["baseline_loss"] is not None]
    skipped = len(results) - len(eligible)

    lines.append(f" aggregate over {len(eligible)} host(s) with valid baseline"
                 f" (excluded {skipped}):")
    for eh in EH_TYPES:
        losses = []
        for r in eligible:
            v = r["ping_loss"].get(eh)
            if v is not None:
                losses.append(v)
        if losses:
            avg = f"{sum(losses)/len(losses):.1f}%"
        else:
            avg = "N/A"
        lines.append(f"   {eh:<5} mean ping loss = {avg}  (n={len(losses)})")

    lines.append("")
    lines.append(" filtering hops by EH:")

    combined = {}
    for eh in EH_TYPES:
        counts = {}
        for r in results:
            hop = r["diag_hop"].get(eh)
            if not hop:
                continue
            counts[hop] = counts.get(hop, 0) + 1
            combined[hop] = combined.get(hop, 0) + 1

        if not counts:
            lines.append(f"   {eh:<5} (none identified)")
            continue
        lines.append(f"   {eh}: (total={sum(counts.values())})")
        for hop, n in sorted_by_count(counts):
            lines.append(f"     {hop:<40} {n}")

    if combined:
        lines.append(f"   total: (total={sum(combined.values())})")
        for hop, n in sorted_by_count(combined):
            lines.append(f"     {hop:<40} {n}")
    else:
        lines.append("   total: (none identified)")
    lines.append(sep)

    text = "\n".join(lines)
    print(text)
    (out_dir / "summary.txt").write_text(text)


def main():
    if os.geteuid() != 0:
        sys.exit("Error: flarex requires root. Re-run with sudo.")
    if not CSV_FILE.exists():
        sys.exit(f"Error: {CSV_FILE} not found.")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = HERE / "results" / f"results_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = parse_csv(CSV_FILE)
    if not targets:
        sys.exit("Error: no valid targets in CSV.")

    print(f"Loaded {len(targets)} target(s) -> {out_dir}\n")
    all_results = []

    for index, host in targets:
        target_file = out_dir / f"{index}_{host}.txt"
        r = new_result(index, host)
        print(f"[{index}] {host}")

        # Phase 1 - baseline
        baseline_out = run(["ping", host], target_file)
        r["baseline_loss"] = parse_ping_loss(baseline_out)
        print(f"  baseline     -> {fmt_loss(r['baseline_loss'])} packetloss")

        # Phase 2 - EH probes
        for eh_name in EH_TYPES:
            rfc_name, extra_args = EH_TYPES[eh_name]
            base_args = ["-T", "tcp", "--eh", eh_name] + extra_args

            ping_out = run(base_args + ["ping", host], target_file)
            ping = parse_ping_loss(ping_out)
            r["ping_loss"][eh_name] = ping

            if ping is not None and ping < 100.0:
                trace_out = run(base_args + ["trace", host], target_file)
                r["trace"][eh_name] = parse_trace(trace_out)

            trace_str = r["trace"].get(eh_name, "N/A")
            print(f"  {rfc_name:<6}  ping={fmt_loss(ping):<6}  trace={trace_str}")

        # Phase 3 - diagnose
        for eh_name in EH_TYPES:
            _, extra_args = EH_TYPES[eh_name]
            diag_out = run(["--eh", eh_name] + extra_args + ["diagnose", host], target_file)
            verdict, hop = parse_diagnose(diag_out)
            r["diagnose"][eh_name] = verdict
            if hop:
                r["diag_hop"][eh_name] = hop

        print()
        all_results.append(r)

    write_summary(all_results, out_dir)


if __name__ == "__main__":
    main()
