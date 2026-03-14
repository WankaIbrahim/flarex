from __future__ import annotations

import time
from typing import Optional, Iterator, Dict, Any

from flarex.cli.models import CommonConfig, Destination, OnOff, Transport
from flarex.net.utils import *

def ping_stream(
    cfg: CommonConfig,
    dest: Destination,
    *,
    count: Optional[int] = None,
    interval: Optional[float] = None,
    per_probe_timeout: Optional[float] = None,
    pmtud: Optional[OnOff] = None,
    pmtu_size: Optional[int] = None,
    identify_drop: Optional[OnOff] = None,
    ) -> Iterator[Dict[str, Any]]:
    """
    Stream ping events for a destination.

    Builds and sends one probe per sequence number, yielding structured
    events for the start of the run, each probe result, and the final
    summary. The stream is intended to be consumed by a renderer such as
    ``render_ping_stream``.

    Args:
        cfg: Common configuration options shared across commands.
        dest: Destination to probe.
        count: Number of probes to send. Defaults to 4.
        interval: Delay in seconds between probes. Defaults to 1.0.
        per_probe_timeout: Timeout in seconds to wait for each reply.
            Falls back to ``cfg.timeout`` and then 2.0 seconds.
        pmtud: Reserved PMTUD toggle. Currently unused.
        pmtu_size: Reserved PMTU probe size override. Currently unused.
        identify_drop: Reserved drop identification toggle. Currently unused.

    Yields:
        Dictionaries describing ping events with ``type`` values of
        ``start``, ``probe``, and ``summary``.

    Raises:
        ValueError: If count is less than 1, interval is negative, or the
            effective timeout is not greater than 0.
    """

    DEFAULT_PAYLOAD = 56    
    
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
    
    target = resolve_address(dest)
    
    yield {
        "type": "start",
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "payload_size": cfg.payload_size if cfg.payload_size is not None else DEFAULT_PAYLOAD,
        "eh_chain": [getattr(e, "value", str(e)) for e in (cfg.eh_chain or [])] if cfg.eh_chain is not None else None,     
    }
        
    received = 0
    rtts = []
    ident = int(time.time()) & 0xFFFF

    total_start = now_ms()
    for seq in range(1, count + 1):
        base = build_ipv6_base(cfg, dest=target)
        pkt = apply_eh_chain(cfg, base)
        pkt = apply_transport_layer(
            cfg,
            pkt,
            transport=transport,
            payload=b"\x00" * DEFAULT_PAYLOAD,
            dest=dest,
            icmp_id=ident,
            icmp_seq=seq,
            tcp_flags="S"
        )
        reply, rtt_ms = send_packet(pkt, target=target, transport=transport, timeout=timeout)
        reply_status = interpret_reply(transport, reply)
        
        if reply_status != "timeout" and reply is not None:
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
