#!/usr/bin/env python3
"""
script.py
Usage: sudo python3 script.py [output_dir]

CSV format (no header):  <index>,<hostname>

Phases per target:
  1. Baseline  — plain ping, TCP
  2. EH probes — ping + trace for each of: hbh (HBH8), frag (FH512), dst (DO8)
  3. Diagnose  — flarex diagnose per EH
"""

import csv, os, sys, subprocess, datetime
from pathlib import Path
from dataclasses import dataclass, field

_HERE     = Path(__file__).resolve().parent
CSV_FILE  = _HERE / "targets.csv"
FLAREX    = _HERE.parent / ".venv/bin/flarex"

@dataclass
class Result:
    index: str
    host: str
    baseline: str = "N/A"
    ping:     dict = field(default_factory=dict)
    trace:    dict = field(default_factory=dict)
    diagnose: dict = field(default_factory=dict)

@dataclass
class EH:
    name: str
    rfc_name: str
    extra_args: list

EH_TYPES = [
    EH("hbh",  "HBH8",  []),
    EH("frag", "FH512", ["--payload-size", "512"]),
    EH("dst",  "DO8",   []),
]


def run(args: list, out: Path) -> bool:
    """Run a flarex command, append output to the target file. Returns True on success."""
    cmd = [str(FLAREX)] + args
    with open(out, "a") as f:
        f.write(f"\n$ {' '.join(cmd)}\n{'-'*60}\n")
        f.flush()
        return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode == 0


def parse_csv(path: Path) -> list[tuple[str, str]]:
    with open(path, newline="") as f:
        return [
            (row[0].strip(), row[1].strip())
            for row in csv.reader(f)
            if len(row) >= 2 and not row[0].strip().startswith("#")
        ]


def write_summary(results: list[Result], out_dir: Path):
    col  = "{:<5} {:<20} {:<6} | {:<5} {:<6} {:<5} {:<5} {:<6} {:<5} {:<5} {:<6} {:<5}"
    sep  = "=" * 90
    dash = "-" * 90

    def eh_vals(r, eh):
        return (
            r.ping.get(eh, "N/A"),
            "COMPL" if r.trace.get(eh) == "COMPLETE" else "INCOMP" if r.trace.get(eh) == "INCOMPLETE" else "N/A",
            r.diagnose.get(eh, "N/A"),
        )

    lines = [
        sep,
        f" flarex EH probe report — {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
        sep,
        "{:<5} {:<20} {:<6} | {:<17} {:<17} {:<17}".format("", "", "", "HBH", "FRAG", "DST"),
        col.format("IDX", "HOST", "BASE", "ping", "trace", "diag", "ping", "trace", "diag", "ping", "trace", "diag"),
        dash,
        *[col.format(r.index, r.host, r.baseline, *eh_vals(r, "hbh"), *eh_vals(r, "frag"), *eh_vals(r, "dst"))
          for r in results],
        sep,
    ]
    text = "\n".join(lines)
    print(text)
    (out_dir / "summary.txt").write_text(text)



def main():
    if os.geteuid() != 0:
        sys.exit("Error: flarex requires root. Re-run with sudo.")
    if not CSV_FILE.exists():
        sys.exit(f"Error: {CSV_FILE} not found.")

    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 \
              else Path(f"results_{datetime.datetime.now():%Y%m%d_%H%M%S}")
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = parse_csv(CSV_FILE)
    if not targets:
        sys.exit("Error: no valid targets in CSV.")

    print(f"Loaded {len(targets)} target(s) -> {out_dir}\n")
    all_results = []

    for index, host in targets:
        target_file = out_dir / f"{index}_{host}.txt"
        r = Result(index=index, host=host)
        print(f"[{index}] {host}")

        # Phase 1 - baseline
        ok = run(["--transport", "tcp", "ping", host], target_file)
        r.baseline = "PASS" if ok else "FAIL"
        print(f"  baseline     -> {r.baseline}")

        # Phase 2 - EH probes
        for eh in EH_TYPES:
            base_args = ["--transport", "tcp", "--eh", eh.name] + eh.extra_args

            ok = run(base_args + ["ping",  host], target_file)
            r.ping[eh.name] = "PASS" if ok else "DROP"

            ok = run(base_args + ["trace", host], target_file)
            r.trace[eh.name] = "COMPLETE" if ok else "INCOMPLETE"

            print(f"  {eh.rfc_name:<6}  ping={r.ping[eh.name]:<5}  trace={r.trace[eh.name]}")

        # Phase 3 - diagnose
        for eh in EH_TYPES:
            ok = run(["--eh", eh.name] + eh.extra_args + ["diagnose", host], target_file)
            r.diagnose[eh.name] = "PASS" if ok else "FAIL"

        print()
        all_results.append(r)

    write_summary(all_results, out_dir)


if __name__ == "__main__":
    main()