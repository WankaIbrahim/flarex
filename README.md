# flarex

A command-line diagnostic tool for evaluating IPv6 Extension Header (EH) support across Internet paths.

`flarex` lets you probe IPv6 destinations with arbitrary EH configurations, perform traceroute-style hop-by-hop path discovery, and localise the network node responsible for filtering EH-bearing packets. It was developed as part of an undergraduate research project at the University of Southampton evaluating the current state of IPv6 EH support on the public Internet.

## Features

- **Three core operations**: `ping`, `trace`, and `diagnose`.
- **Configurable Extension Header chains** of up to three EHs per packet.
- **Supported EH types**: Hop-by-Hop Options (`hop`/`hbh`), Destination Options (`dst`), Fragment (`frag`). Routing, Authentication, ESP, and Mobility are recognised by the parser; full implementation is planned.
- **Seven transport protocols**: ICMPv6, UDP, DNS, TCP, SSH, HTTP, HTTPS.
- **Two diagnostic methods**: `confirm-last` (efficient boundary detection) and `hop-scan` (full per-hop scan with hop-counting algorithm).
- **Optional Path MTU Discovery** integrated into `ping`.

## Installation

```sh
pip install flarex
```

`flarex` requires Python 3.10 or newer. Because it sends raw packets via Scapy, it must be run as root (`sudo flarex …`) or as Administrator on Windows.

### From source

```sh
git clone https://github.com/WankaIbrahim/flarex.git
cd flarex
pip install -e .
```

## Quick start

```sh
# Plain IPv6 ping
sudo flarex ping google.com

# Ping carrying an 8-byte Hop-by-Hop Options header over TCP/443
sudo flarex --eh hop --transport https ping google.com

# Traceroute carrying a Destination Options header
sudo flarex --eh dst trace google.com

# Diagnose where a Fragment-bearing packet is being dropped
sudo flarex --eh frag --transport https diagnose google.com

# Diagnose using the more thorough hop-scan method
sudo flarex --eh frag --transport https diagnose google.com --method hop-scan

# Chain two EHs (with auto-ordering per RFC 8200)
sudo flarex --eh hop,dst --eh-auto-order ping google.com
```

For full help on any subcommand:

```sh
flarex ping --help
flarex trace --help
flarex diagnose --help
```

## Subcommands

### `ping`

Tests end-to-end reachability with the configured packet structure. Reports per-probe round-trip time and a summary of packet loss. Supports optional Path MTU Discovery via the `--pmtud` flag (combine with `--pmtu-size` to set the initial probe size, minimum 1280 bytes). PMTUD is not supported with the TCP-family transports (`tcp`, `ssh`, `http`, `https`), since those probes carry no resizable payload.

### `trace`

Performs traceroute-style hop-by-hop path discovery. Sends probes with incrementally increasing hop limits, terminating when the destination responds, when the maximum hop count is reached, or when a routing loop is detected.

### `diagnose`

Determines whether EH-bearing packets are being filtered on the path to a destination, and identifies the responsible hop. Operates in three phases:

1. A short ping burst — exits early if no packet loss is detected.
2. A clean traceroute (no EH) — discovers the path.
3. A locate phase — probes individual hops with paired baseline (no-EH) and test (configured EH) packets to find the filtering node.

Two locate methods are available:

- `confirm-last` (default): forward-scans the path, stopping at the first filtering hop and re-probing the previous hop to confirm the boundary.
- `hop-scan`: probes every hop and processes the results using a hop-counting algorithm derived from De Boer and Bosma's PMTU black hole detection method.

## Project structure

```
flarex/
  cli/         # Typer CLI commands, models, validators
  net/         # utils.py, ping.py, traceroute.py, diagnose.py
  output/      # render.py
  tests/net/   # pytest suite
```

## Testing

```sh
pytest
```

The test suite uses mocking to replace Scapy's `send()` and `sniff()` with controlled stubs, so it does not require network access or root privileges.

## Citing

If you use `flarex` in academic work, please cite:

> Wanka, I. (2026). *Evaluating IPv6 Extension Header Support*. BSc Computer Science Project, University of Southampton.

## License

Released under the MIT License. See [`LICENSE`](LICENSE) for the full text.

## Acknowledgements

Developed under the supervision of Dr. Graeme Bragg at the School of Electronics and Computer Science, University of Southampton. Built on top of [Scapy](https://scapy.net/), [Typer](https://typer.tiangolo.com/) and [pytest](https://pytest.org/).
