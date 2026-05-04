#!/usr/bin/env python3
"""
append_companies.py
Usage: python3 append_companies.py

Adds a `company` column to each `*_dropping_devices.csv` file in `results/`,
naming the organisation that owns each filtering-hop IPv6 address.

Method:
    1. Collect every unique address from the three dropping_devices CSVs.
    2. Send the list as a single bulk query to Team Cymru's IP-to-ASN whois
    service (whois.cymru.com:43, "begin/verbose/.../end" protocol). The
    service returns, for each address: origin ASN, announced prefix,
    registry, allocation date, and the AS-name string.
    3. Map the AS-name token (e.g. "GOOGLE", "FACEBOOK", "CISCO-UMBRELLA")
    to a human-friendly label via AS_TO_COMPANY. Any AS-name not in the
    table is written as "N/A" so unidentified hosts are explicit.
    4. Rewrite each CSV with the new column appended, preserving line
    endings.
"""

import csv
import socket
from pathlib import Path

AS_TO_COMPANY = {
    "LEVEL3": "Lumen",
    "TWELVE99": "Arelion",
    "CISCOSYSTEMS": "Cisco",
    "GOOGLE": "Google",
    "JANET": "JANET",
    "AMOBEE": "Amobee",
    "LIBERTYGLOBAL": "Liberty Global",
    "GOOGLE-CLOUD-PLATFORM": "Google",
    "AMAZON-02": "Amazon",
    "MICROSOFT-CORP-MSN-AS-BLOCK": "Microsoft",
    "CISCO-UMBRELLA": "Cisco",
    "YAHOO-ULS": "Yahoo",
    "APPLE-AUSTIN": "Apple",
    "FACEBOOK": "Meta",
}

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
RESULTS_DIR = Path(__file__).resolve().parent / "results"
CSV_FILES = (
    "frag_dropping_devices.csv",
    "dst_dropping_devices.csv",
    "hbh_dropping_devices.csv",
)


def read_csv(path):
    raw = path.read_bytes()
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode().replace("\r\n", "\n").rstrip("\n")
    rows = list(csv.reader(text.splitlines()))
    return newline, rows[0], rows[1:]


def collect_unique_addresses(csv_paths):
    addrs = set()
    for path in csv_paths:
        _, _, rows = read_csv(path)
        for row in rows:
            addrs.add(row[1])
    return sorted(addrs)


def cymru_lookup(addresses):
    payload = "begin\nverbose\n" + "\n".join(addresses) + "\nend\n"
    with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=30) as sock:
        sock.sendall(payload.encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks).decode()

    result = {}
    for line in response.splitlines():
        if "|" not in line or line.startswith("Bulk"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        addr = parts[1]
        as_name_token = parts[6].split(" ")[0].rstrip(",")
        result[addr] = as_name_token
    return result


def main():
    csv_paths = [RESULTS_DIR / name for name in CSV_FILES]
    addresses = collect_unique_addresses(csv_paths)
    print(f"resolving {len(addresses)} unique addresses via {CYMRU_HOST}")

    as_by_addr = cymru_lookup(addresses)
    company_by_addr = {
        addr: AS_TO_COMPANY.get(as_by_addr.get(addr, ""), "N/A")
        for addr in addresses
    }

    unknown = sorted(
        {as_by_addr[a] for a in addresses
         if as_by_addr.get(a) and as_by_addr[a] not in AS_TO_COMPANY}
    )
    if unknown:
        print("AS-names with no mapping (will be labelled N/A):")
        for name in unknown:
            print(f"  {name}")

    for path in csv_paths:
        newline, header, rows = read_csv(path)
        if header[-1] == "company":
            new_header = header
            new_rows = [r[:-1] + [company_by_addr.get(r[1], "N/A")] for r in rows]
        else:
            new_header = header + ["company"]
            new_rows = [r + [company_by_addr.get(r[1], "N/A")] for r in rows]
        out_text = newline.join(",".join(r) for r in [new_header] + new_rows) + newline
        path.write_bytes(out_text.encode())
        print(f"updated {path.name}: {len(new_rows)} rows")


if __name__ == "__main__":
    main()
