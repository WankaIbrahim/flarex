from __future__ import annotations

import time
from typing import Optional, Iterator, Dict, Any

from flarex.cli.models import CommonConfig, Destination, Transport
from flarex.net.utils import *
from flarex.cli.validators import parse_destination

def traceroute(
    cfg: CommonConfig,
    dest: Destination,
    *,
    first_hop: Optional[int] = None,
    max_hop: Optional[int] = None,
    probes: Optional[int] = None,
    wait_probe: Optional[float] = None,
    loop_threshold: Optional[int] = None,
    no_dns: bool = False,
    ) -> Iterator[Dict[str, Any]]:
    """
    Stream traceroute events for a destination.

    Sends ``probes`` packets at each hop limit from ``first_hop`` to
    ``max_hop``, yielding a structured event per hop. Stops early if the
    destination replies or a routing loop is detected. The stream is intended
    to be consumed by a renderer such as ``render_traceroute``.

    Args:
        cfg: Common configuration options shared across commands.
        dest: Destination to probe.
        first_hop: TTL to start from. Defaults to 1.
        max_hop: Maximum TTL to probe. Defaults to 30.
        probes: Number of probes per TTL. Defaults to 3.
        wait_probe: Delay in seconds between probes at the same TTL.
            Defaults to 0.
        loop_threshold: Number of consecutive repeated source addresses
            before a routing loop is declared. Defaults to 3.
        no_dns: If ``True``, suppresses DNS resolution of hop addresses and
            overrides the ``dns`` transport with ``udp``.

    Yields:
        Dictionaries describing traceroute events with ``type`` values of
        ``start``, ``hop``, and ``done``.

    Raises:
        ValueError: If ``first_hop``, ``max_hop``, or ``probes`` is less than
            1, ``wait_probe`` is negative, or the effective timeout is not
            greater than 0.
    """
    DEFAULT_PAYLOAD = 60  
    
    first_hop = int(first_hop) if first_hop is not None else 1
    max_hop = int(max_hop) if max_hop is not None else 30
    probes = int(probes) if probes is not None else 3
    wait_probe = float(wait_probe) if wait_probe is not None else 0
    loop_threshold = int(loop_threshold) if loop_threshold is not None else 3
    timeout = float(cfg.timeout) if cfg.timeout is not None else 2.0
    
    if first_hop <= 0:
        raise ValueError("--first-hop must be >= 1")
    if max_hop <= 0:
        raise ValueError("--max-hop must be >= 1") 
    if probes <= 0:
        raise ValueError("--probes must be >= 1")
    if wait_probe < 0:
        raise ValueError("--wait-probe must be >= 0")
    if timeout <= 0:
        raise ValueError("--timeout must be > 0")
    
    transport = cfg.transport or Transport.udp
    if no_dns == True and transport == Transport.dns:
        transport = Transport.udp
    
    target = resolve_address(dest)
    
    yield {
        "type": "start",
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "max_hops": max_hop,
        "payload_size": cfg.payload_size if cfg.payload_size is not None else DEFAULT_PAYLOAD,
        "eh_chain": [getattr(e, "value", str(e)) for e in (cfg.eh_chain or [])] if cfg.eh_chain is not None else None,
        "loop_threshold": loop_threshold,
    }
    
    ident = int(time.time()) & 0xFFFF
    reached = False
    loop_detected = False
    seen_sources: dict[str, int] = {}
    repeated_hops = 0
    
    
    for hop in range(first_hop, max_hop + 1):
        hop_source = None
        rtts = []
        reached_target = False
        
        for i in range(1, probes + 1):
            base = build_ipv6_base(cfg, dest=target, hop_limit=hop)
            pkt = apply_eh_chain(cfg, base)
            pkt = apply_transport_layer(
                cfg,
                pkt,
                payload=b"\x00" * DEFAULT_PAYLOAD,
                dest=dest,
                icmp_id=ident,
                icmp_seq=i,
                tcp_flags="S"
            )
        
            reply, rtt_ms = send_packet(pkt, target=target, transport=transport, timeout=timeout, is_traceroute=True)
    
            reply_status = interpret_reply(reply)
            
            if reply_status != "timeout" and reply is not None:
                rtts.append(rtt_ms)
                if reply.haslayer(IPv6):
                    src = reply[IPv6].src
                    if hop_source is None:
                        hop_source = src
                    if src == target:
                        reached_target = True
            else:
                rtts.append("*")
            
            if wait_probe > 0 and i < probes:
                time.sleep(wait_probe)

        if hop_source is not None:
            parsed_source = parse_destination(hop_source)
            resolved_source = resolve_address(parsed_source) if not no_dns else hop_source
            source_info = {
                "raw": parsed_source.raw,
                "resolved": resolved_source,
            }
        else:
            source_info = {
                "raw": None,
                "resolved": None,
            }

        yield {
            "type": "hop",
            "hop": hop,
            "source": source_info,
            "destination": {
                "raw": dest.raw,
                "kind": dest.kind,
                "value": dest.value,
                "resolved": target,
            },
            "rtts": rtts,
        }
        
        if reached_target:
            reached = True
            break

        if hop_source is not None:
            if hop_source in seen_sources:
                repeated_hops += 1
                if repeated_hops >= loop_threshold:
                    loop_detected = True
                    break
            else:
                seen_sources[hop_source] = hop
                repeated_hops = 0        
    
    yield {
        "type": "done",
        "reached": reached,
        "loop_detected": loop_detected,
    }        
