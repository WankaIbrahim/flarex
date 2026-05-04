from __future__ import annotations

import time
from dataclasses import replace
from typing import Any, Dict, Iterator, List, Optional

from flarex.cli.models import CommonConfig, Destination, DiagnoseMethod, Transport
from flarex.net.ping import ping as ping_stream
from flarex.net.traceroute import traceroute
from flarex.net.utils import (
    apply_eh_chain,
    apply_transport_layer,
    build_ipv6_base,
    resolve_address,
    send_packet,
)

_PING_COUNT = 4


def diagnose(
    cfg: CommonConfig,
    dest: Destination,
    *,
    method: Optional[DiagnoseMethod] = None,
    max_steps: Optional[int] = None,
) -> Iterator[Dict[str, Any]]:
    """
    Stream diagnostic events that locate where EH packets are filtered on a path.

    Runs in three phases:

    1. Ping - sends a small burst of probes using the caller's config. If
       all packets are received the destination is reachable with no loss, a
       ``result`` event with ``filtered_hop=None`` is yielded and the generator
       exits early.

    2. Traceroute - if ping detects loss, a clean traceroute (ICMP, no EH)
       is run to discover the path and populate the hop list.

    3. Locate - the selected method probes individual TTLs to find the
       first hop that silently drops EH packets.

    Args:
        cfg: Common configuration options shared across commands.
        dest: Destination to probe.
        method: Location method to use. Defaults to
            ``DiagnoseMethod.confirm_last``.
        transport: Transport protocol for the test probe. Falls back to
            ``cfg.transport`` and then ``Transport.icmp``.
        max_steps: Maximum number of hops to examine in the locate phase.
            If ``None`` all discovered hops are used.

    Yields:
        Dictionaries describing diagnostic events with ``type`` values of
        ``start``, ``ping_result``, ``trace_hop``, ``probe``, ``result``,
        and ``done``.
    """
    
    method = method or DiagnoseMethod.confirm_last
    transport = cfg.transport or Transport.icmp
    timeout = float(cfg.timeout) if cfg.timeout is not None else 2.0
    ident = int(time.time()) & 0xFFFF

    target = resolve_address(dest)

    yield {
        "type": "start",
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "method": method.value,
        "transport": transport.value,
    }

    # Ping
    ping_events = list(ping_stream(cfg, dest, count=_PING_COUNT))
    for event in ping_events:
        yield {"type": "ping_result", "event": event}

    summary = next(e for e in ping_events if e["type"] == "summary")
    if summary["received"] == _PING_COUNT:
        yield {"type": "result", "filtered_hop": None, "reason": "no_loss"}
        yield {"type": "done"}
        return

    # Traceroute
    clean_cfg = replace(cfg, transport=Transport.icmp, eh_chain=None)
    hops: List[Optional[str]] = []
    for event in traceroute(clean_cfg, dest):
        if event["type"] == "hop":
            hops.append(event["source"]["resolved"])
            yield {**event, "type": "trace_hop"}

    if max_steps is not None:
        hops = hops[:max_steps]

    # Locate
    if method == DiagnoseMethod.confirm_last:
        yield from _confirm_last(cfg, target, dest, hops, transport, timeout, ident)
    elif method == DiagnoseMethod.hop_scan:
        yield from _hop_scan(cfg, target, dest, hops, transport, timeout, ident)

    yield {"type": "done"}


def _probe(
    cfg: CommonConfig,
    target: str,
    dest: Destination,
    ttl: int,
    transport: Transport,
    timeout: float,
    ident: int,
    seq: int,
    *,
    baseline: bool,
) -> bool:
    """
    Send a single probe at a given TTL and return whether any reply was received.

    When ``baseline`` is ``True`` the probe is sent with ICMP and no extension
    headers, establishing a clean reference signal. When ``baseline`` is
    ``False`` the probe uses the caller's configured transport and EH chain,
    representing the packet under test.

    Args:
        cfg: Common configuration options shared across commands.
        target: Resolved IPv6 address of the destination.
        dest: Destination object used for transport-layer construction.
        ttl: Hop limit to set on the outgoing packet.
        transport: Transport protocol for the test probe (ignored when
            ``baseline`` is ``True``).
        timeout: Time in seconds to wait for a reply.
        ident: ICMPv6 Echo identifier shared across probes in one session.
        seq: ICMPv6 Echo sequence number for this probe.
        baseline: If ``True``, send a clean ICMP probe with no EH chain.
            If ``False``, send the configured transport and EH chain.

    Returns:
        ``True`` if any reply was received within ``timeout``, ``False``
        otherwise.
    """
    if baseline:
        probe_cfg = replace(cfg, eh_chain=None)
        probe_transport = Transport.icmp
    else:
        probe_cfg = cfg
        probe_transport = transport

    base = build_ipv6_base(probe_cfg, dest=target, hop_limit=ttl)
    pkt = apply_eh_chain(probe_cfg, base)
    pkt = apply_transport_layer(
        probe_cfg,
        pkt,
        transport=probe_transport,
        dest=dest,
        icmp_id=ident,
        icmp_seq=seq,
    )
    reply, _ = send_packet(
        pkt,
        target=target,
        transport=probe_transport,
        timeout=timeout,
        is_traceroute=True,
    )
    return reply is not None

def _hop_count(classified: List[tuple]) -> Dict[str, List[int]]:
    """
    Apply the hop-counting algorithm to a list of classified TTL observations.

    Each entry in ``classified`` pairs a hop IP address with a boolean
    indicating whether the test probe at that TTL was forwarded (``True``) or
    dropped (``False``). The resulting counts mirror the algorithm from
    de Boer & Bosma. - for every TTL observation the responding router's
    unfiltered or filtered counter is incremented by one.

    Args:
        classified: List of ``(hop_ip, is_unfiltered)`` tuples, one per
            probed TTL.

    Returns:
        Dictionary mapping each hop IP to a two-element list
        ``[unfiltered_count, filtered_count]``.
    """
    counts: Dict[str, List[int]] = {}
    for hop_ip, is_unfiltered in classified:
        if hop_ip not in counts:
            counts[hop_ip] = [0, 0]
        if is_unfiltered:
            counts[hop_ip][0] += 1
        else:
            counts[hop_ip][1] += 1
    return counts

def _find_filtering_hop(counts: Dict[str, List[int]]) -> Optional[str]:
    """
    Identify the most likely filtering hop from hop-count data.

    First looks for a hop whose filtered count is non-zero and whose
    unfiltered count is zero - a clean signal that the router consistently
    drops EH packets. If no such hop exists, falls back to the hop with the
    highest filtered ratio, provided it exceeds 0.5. Returns ``None`` when
    the evidence is insufficient to name a culprit.

    Args:
        counts: Mapping of hop IP to ``[unfiltered_count, filtered_count]``
            as returned by ``_hop_count``.

    Returns:
        The IP address of the identified filtering hop, or ``None`` if no
        hop meets the confidence threshold.
    """
    for hop_ip, (unfiltered, filtered) in counts.items():
        if filtered > 0 and unfiltered == 0:
            return hop_ip

    best: Optional[str] = None
    best_ratio = 0.5
    for hop_ip, (unfiltered, filtered) in counts.items():
        total = unfiltered + filtered
        if total == 0:
            continue
        ratio = filtered / total
        if ratio > best_ratio:
            best_ratio = ratio
            best = hop_ip
    return best

def _confirm_last(
    cfg: CommonConfig,
    target: str,
    dest: Destination,
    hops: List[Optional[str]],
    transport: Transport,
    timeout: float,
    ident: int,
) -> Iterator[Dict[str, Any]]:
    """
    Locate the filtering hop by scanning forward and confirming the boundary.

    Probes TTLs in ascending order, sending both a baseline (ICMP, no EH)
    and a test probe (configured transport + EH chain) at each hop. Stops at
    the first TTL where the baseline passes but the test fails. The previous
    TTL is then re-probed to confirm it is genuinely unfiltered; if the
    re-probe contradicts (previous TTL now also drops the test probe), the
    boundary is shifted back by one.

    This method requires no hop-counting and converges quickly for simple,
    single-boundary paths.

    Args:
        cfg: Common configuration options shared across commands.
        target: Resolved IPv6 address of the destination.
        dest: Destination object.
        hops: Ordered list of hop IP addresses from the discovery traceroute.
            Entries may be ``None`` for unresponsive hops.
        transport: Transport protocol for the test probe.
        timeout: Per-probe timeout in seconds.
        ident: ICMPv6 Echo identifier shared across probes in one session.

    Yields:
        ``probe`` events for each TTL examined and a final ``result`` event
        with ``filtered_hop`` set to the IP of the first filtering router,
        or ``None`` if no boundary was found.
    """
    seq = 1
    boundary: Optional[int] = None

    for ttl in range(1, len(hops) + 1):
        hop_ip = hops[ttl - 1]

        baseline_ok = _probe(cfg, target, dest, ttl, transport, timeout, ident, seq, baseline=True)
        seq += 1
        test_ok = _probe(cfg, target, dest, ttl, transport, timeout, ident, seq, baseline=False)
        seq += 1

        yield {
            "type": "probe",
            "ttl": ttl,
            "hop": hop_ip,
            "baseline": baseline_ok,
            "test": test_ok,
        }

        if baseline_ok and not test_ok:
            boundary = ttl

            if ttl > 1:
                prev_ip = hops[ttl - 2]
                prev_baseline = _probe(cfg, target, dest, ttl - 1, transport, timeout, ident, seq, baseline=True)
                seq += 1
                prev_test = _probe(cfg, target, dest, ttl - 1, transport, timeout, ident, seq, baseline=False)
                seq += 1

                yield {
                    "type": "probe",
                    "ttl": ttl - 1,
                    "hop": prev_ip,
                    "baseline": prev_baseline,
                    "test": prev_test,
                    "confirmation": True,
                }

                if prev_baseline and not prev_test:
                    boundary = ttl - 1

            break

    filtering_hop = hops[boundary - 1] if boundary is not None and boundary <= len(hops) else None
    yield {
        "type": "result",
        "method": DiagnoseMethod.confirm_last.value,
        "filtered_hop": filtering_hop,
        "ttl": boundary,
    }

def _hop_scan(
    cfg: CommonConfig,
    target: str,
    dest: Destination,
    hops: List[Optional[str]],
    transport: Transport,
    timeout: float,
    ident: int,
) -> Iterator[Dict[str, Any]]:
    """
    Locate the filtering hop by probing every hop and applying hop-counting.

    Sends a baseline and a test probe at every TTL in the discovered path,
    classifying each hop as unfiltered (both respond) or filtered (baseline
    responds, test does not). The full observation set is passed to
    ``_hop_count`` and ``_find_filtering_hop`` to produce a confidence-scored
    result that is robust to noisy or asymmetric paths.

    This is the most thorough method and the most accurate for paths with
    multiple filtering points or rate-limited routers.

    Args:
        cfg: Common configuration options shared across commands.
        target: Resolved IPv6 address of the destination.
        dest: Destination object.
        hops: Ordered list of hop IP addresses from the discovery traceroute.
            Entries may be ``None`` for unresponsive hops.
        transport: Transport protocol for the test probe.
        timeout: Per-probe timeout in seconds.
        ident: ICMPv6 Echo identifier shared across probes in one session.

    Yields:
        ``probe`` events for every TTL examined and a final ``result`` event
        with ``filtered_hop`` set to the identified filtering router IP,
        along with the raw ``counts`` dict from ``_hop_count``.
    """
    classified: List[tuple] = []
    seq = 1

    for ttl in range(1, len(hops) + 1):
        hop_ip = hops[ttl - 1]

        baseline_ok = _probe(cfg, target, dest, ttl, transport, timeout, ident, seq, baseline=True)
        seq += 1
        test_ok = _probe(cfg, target, dest, ttl, transport, timeout, ident, seq, baseline=False)
        seq += 1

        yield {
            "type": "probe",
            "ttl": ttl,
            "hop": hop_ip,
            "baseline": baseline_ok,
            "test": test_ok,
        }

        if hop_ip is not None:
            classified.append((hop_ip, test_ok))

    counts = _hop_count(classified)
    filtering_hop = _find_filtering_hop(counts)

    yield {
        "type": "result",
        "method": DiagnoseMethod.hop_scan.value,
        "filtered_hop": filtering_hop,
        "counts": counts,
    }
