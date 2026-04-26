from __future__ import annotations

import time
from typing import Optional, Iterator, Dict, Any

from flarex.cli.models import CommonConfig, Destination, Transport
from flarex.net.utils import *

def ping(
    cfg: CommonConfig,
    dest: Destination,
    *,
    count: Optional[int] = None,
    interval: Optional[float] = None,
    per_probe_timeout: Optional[float] = None,
    pmtud: bool = False,
    pmtu_size: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
    """
    Stream ping events for a destination.

    Builds and sends one probe per sequence number, yielding structured
    events for the start of the run, each probe result, and the final
    summary.

    Args:
        cfg: Common configuration options shared across commands.
        dest: Destination to probe.
        count: Number of probes to send. Defaults to 4.
        interval: Delay in seconds between probes. Defaults to 1.0.
        per_probe_timeout: Timeout in seconds to wait for each reply.
            Falls back to ``cfg.timeout`` and then 2.0 seconds.
        pmtud: When True, enables Path MTU Discovery. Probes are
            sized to ``pmtu_size`` and ICMPv6 Packet Too Big replies are
            captured. Each such reply reduces the probe size for subsequent
            probes to the advertised MTU.
        pmtu_size: Initial total probe packet size (IPv6 header + ICMPv6
            header + payload) when PMTUD is enabled. Defaults to 1500.
            Must be >= 1280 (IPv6 minimum MTU).

    Yields:
        Dictionaries describing ping events with ``type`` values of
        ``start``, ``probe``, and ``summary``.

    Raises:
        ValueError: If count is less than 1, interval is negative, or the
            effective timeout is not greater than 0.
    """
    
    _DEFAULT_PAYLOAD = 56
    _IPV6_HDR = 40
    _TRANSPORT_HDR = 0
    _DEFAULT_PMTU = 1500
    _MIN_MTU = 1280

    count = int(count) if count is not None else 4
    interval = float(interval) if interval is not None else 1.0
    timeout = float(per_probe_timeout if per_probe_timeout is not None
                    else cfg.timeout if cfg.timeout is not None
                    else 2.0)
        
    if count <= 0:
        raise ValueError("--count must be >= 1")
    if interval < 0:
        raise ValueError("--interval must be >= 0")
    if timeout <= 0:
        raise ValueError("--per-probe-timeout/--timeout must be > 0")
    
    transport = cfg.transport or Transport.icmp
    
    if transport in (Transport.icmp, Transport.udp, Transport.dns):
        _TRANSPORT_HDR = 8
    elif transport in (Transport.tcp, Transport.http, Transport.https, Transport.ssh):
        _TRANSPORT_HDR = 20
    
    if pmtud:
        if pmtu_size is not None and pmtu_size < _MIN_MTU:
            raise ValueError(f"--pmtu-size must be >= {_MIN_MTU} (IPv6 minimum MTU)")
        current_mtu = pmtu_size if pmtu_size is not None else _DEFAULT_PMTU
        probe_payload = max(0, current_mtu - _IPV6_HDR - _TRANSPORT_HDR)
    else:
        current_mtu = None
        probe_payload = None

    
    target = resolve_address(dest)
    
    start_payload_size = (
        probe_payload if pmtud
        else cfg.payload_size if cfg.payload_size is not None
        else _DEFAULT_PAYLOAD
    )
    
    yield {
        "type": "start",
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "payload_size": start_payload_size,
        "pmtud": pmtud,
        "pmtu_size": current_mtu,
        "eh_chain": [getattr(e, "value", str(e)) for e in (cfg.eh_chain or [])] if cfg.eh_chain is not None else None,
    }
        
    received = 0
    rtts = []
    ident = int(time.time()) & 0xFFFF

    total_start = now_ms()
    
    for seq in range(1, count + 1):
        base = build_ipv6_base(cfg, dest=target)
        pkt = apply_eh_chain(cfg, base)
        force_payload = b"\x00" * probe_payload if probe_payload is not None else None
        default_payload = b"\x00" * _DEFAULT_PAYLOAD
        pkt = apply_transport_layer(
            cfg,
            pkt,
            payload=default_payload,
            dest=dest,
            icmp_id=ident,
            icmp_seq=seq,
            tcp_flags="S",
            force_payload=force_payload,
        )
        #TODO: Remove debug print statement
        print(pkt)
        reply, rtt_ms = send_packet(pkt, target=target, transport=transport, timeout=timeout, pmtud=pmtud)
        reply_status = interpret_reply(reply)

        discovered_mtu = None
        reply_src = None
        
        if reply_status == "icmp_packet_too_big" and reply is not None:
            discovered_mtu = int(reply[ICMPv6PacketTooBig].mtu)
            if pmtud:
                current_mtu = max(discovered_mtu, _MIN_MTU)
                probe_payload = max(0, current_mtu - _IPV6_HDR - _TRANSPORT_HDR)
            if reply.haslayer(IPv6):
                reply_src = reply[IPv6].src

        if reply_status not in ("timeout", "icmp_packet_too_big") and reply is not None:
            received += 1
            rtts.append(rtt_ms)

        yield {
            "type": "probe",
            "status": reply_status,
            "reply_size": len(reply) if reply is not None else 0,
            "destination": {
                "raw": dest.raw,
                "kind": dest.kind,
                "value": dest.value,
                "resolved": target,
            },
            "seq": seq,
            "rtt_ms": rtt_ms,
            "pmtu": discovered_mtu,
            "reply_src": reply_src,
        }

        if seq != count:
            time.sleep(interval)
    
    total_time = int(round(now_ms() - total_start))
    sent = count
    pkt_loss = (1.0 - (received / sent)) * 100.0 if sent else 0
    
    yield {
        "type": "summary",
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "sent": sent,
        "received": received,
        "pkt_loss": int(round(pkt_loss)),
        "total_time": total_time,
        "min_ms": round(min(rtts), 2) if rtts else None,
        "avg_ms": round((sum(rtts) / len(rtts)), 2) if rtts else None,
        "max_ms": round(max(rtts), 2) if rtts else None,
    }
