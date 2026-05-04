#!/usr/bin/env python3
"""
script_2.py
Usage: sudo python3 script_2.py [output_dir]

For each of the 3 dropping_devices CSV files (hbh, frag, dst), probe every
listed device with a set of plain (no-EH) configurations:

  1. Plain ICMP ping
  2. Plain HTTPS ping
  3. Plain UDP ping

Results are written to 3 separate CSV files.
"""

import csv
import os
import re
import sys
import subprocess
import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLAREX = HERE.parent / ".venv/bin/flarex"
INPUT_DIR = HERE.parent / "script_1" / "results"

INPUT_FILES = {
    "hbh":  INPUT_DIR / "hbh_dropping_devices.csv",
    "frag": INPUT_DIR / "frag_dropping_devices.csv",
    "dst":  INPUT_DIR / "dst_dropping_devices.csv",
}

PROBES = [
    ("icmp",  None),
    ("https", "https"),
    ("udp",   "udp"),
]


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

def parse_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = row.get("idx", "").strip()
            hop = row.get("hop", "").strip()
            company = row.get("company", "").strip()
            if not idx or not hop:
                continue
            rows.append({"idx": idx, "hop": hop, "company": company})
    return rows

def fmt_loss(v):
    if v is None:
        return "N/A"
    return f"{v:g}%"


def probe_device(host, target_file):
    """Run all plain probes against host, return {label: loss}."""
    losses = {}
    for label, transport in PROBES:
        args = []
        if transport is not None:
            args += ["-T", transport]
        args += ["ping", host]
        out = run(args, target_file)
        losses[label] = parse_ping_loss(out)
    return losses


def process_file(eh_name, csv_path, out_dir):
    devices = parse_csv(csv_path)
    if not devices:
        print(f"[{eh_name}] no rows in {csv_path.name}, skipping")
        return []

    eh_dir = out_dir / eh_name
    eh_dir.mkdir(parents=True, exist_ok=True)
    results_csv = out_dir / f"{eh_name}_plain_probes.csv"

    print(f"[{eh_name}] {len(devices)} device(s) -> {results_csv.name}")

    results = []
    header = ["idx", "host", "company"] + [label for label, _ in PROBES]

    with open(results_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for d in devices:
            target_file = eh_dir / f"{d['idx']}_{d['hop']}.txt"
            print(f"  [{d['idx']}] {d['hop']} ({d['company']})")

            losses = probe_device(d["hop"], target_file)
            writer.writerow(
                [d["idx"], d["hop"], d["company"]]
                + [fmt_loss(losses[label]) for label, _ in PROBES]
            )
            results.append({
                "idx": d["idx"],
                "host": d["hop"],
                "company": d["company"],
                "losses": losses,
            })

            for label, _ in PROBES:
                print(f"    {label:<5} -> {fmt_loss(losses[label])}")
            print()

    return results


def write_summary(per_eh_results, out_dir):
    sep  = "=" * 100
    dash = "-" * 100
    labels = [label for label, _ in PROBES]

    row_fmt    = "{:<5} {:<40} {:<10} " + " ".join("{:<8}" for _ in labels)
    header_fmt = row_fmt

    lines = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(sep)
    lines.append(f" flarex plain-probe report - {now}")
    lines.append(sep)

    for eh_name, results in per_eh_results.items():
        lines.append("")
        lines.append(f"[{eh_name.upper()}] dropping_devices - {len(results)} device(s)")
        lines.append(dash)
        lines.append(header_fmt.format("IDX", "HOST", "COMPANY", *labels))
        lines.append(dash)

        for r in results:
            lines.append(row_fmt.format(
                r["idx"], r["host"], r["company"],
                *[fmt_loss(r["losses"][label]) for label in labels],
            ))
        lines.append(dash)

        lines.append(f" aggregate over {len(results)} device(s):")
        for label in labels:
            vals = [r["losses"][label] for r in results
                    if r["losses"][label] is not None]
            if vals:
                mean = f"{sum(vals)/len(vals):.1f}%"
                responded = sum(1 for v in vals if v < 100.0)
            else:
                mean = "N/A"
                responded = 0
            lines.append(f"   {label:<5} mean loss = {mean:<8}  "
                         f"responded={responded}/{len(results)}  (n={len(vals)})")

    lines.append("")
    lines.append(sep)
    lines.append(" combined across all dropping_devices files:")
    all_results = [r for results in per_eh_results.values() for r in results]
    lines.append(f"   total devices = {len(all_results)}")
    for label in labels:
        vals = [r["losses"][label] for r in all_results
                if r["losses"][label] is not None]
        if vals:
            mean = f"{sum(vals)/len(vals):.1f}%"
            responded = sum(1 for v in vals if v < 100.0)
        else:
            mean = "N/A"
            responded = 0
        lines.append(f"   {label:<5} mean loss = {mean:<8}  "
                     f"responded={responded}/{len(all_results)}  (n={len(vals)})")
    lines.append(sep)

    text = "\n".join(lines)
    print(text)
    (out_dir / "summary.txt").write_text(text)


def main():
    if os.geteuid() != 0:
        sys.exit("Error: flarex requires root. Re-run with sudo.")

    for path in INPUT_FILES.values():
        if not path.exists():
            sys.exit(f"Error: {path} not found.")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = HERE / "results" / f"results_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output -> {out_dir}\n")

    per_eh_results = {}
    for eh_name, csv_path in INPUT_FILES.items():
        per_eh_results[eh_name] = process_file(eh_name, csv_path, out_dir)

    write_summary(per_eh_results, out_dir)


if __name__ == "__main__":
    main()
