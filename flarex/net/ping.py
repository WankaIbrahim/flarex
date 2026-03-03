from __future__ import annotations

import time
from typing import Optional, Iterator, Dict, Any

from flarex.cli.models import CommonConfig, Destination, OnOff, Transport
from flarex.net.utils import resolve_address, build_ipv6_base, apply_eh_chain, apply_transport_layer

from scapy.all import send, sniff, Packet
from scapy.layers.inet6 import ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6EchoReply
from scapy.layers.inet import UDP, TCP

def _now_ms() -> float:
    return time.perf_counter() * 1000.0

def _interpret_reply(t: Transport, reply: Optional[Packet]):
    if reply is None:
        return "timeout"

    if reply.haslayer(ICMPv6EchoReply):
        return "icmp_reply"

    if reply.haslayer(ICMPv6TimeExceeded):
        return "icmp_time_exceeded"

    if reply.haslayer(ICMPv6DestUnreach):
        return "icmp_dest_unreach"
    
    if reply.haslayer(TCP):
        return "tcp_reply"

    if reply.haslayer(UDP):
        return "udp_reply"

    return "unknown_reply"

def _send_packet(pkt, *, target, transport, timeout):
    if transport == Transport.icmp:
        filter = f"icmp6 and ip6 src {target} and ip6[40] == 129"

    elif transport == Transport.udp:
        filter = (
            f"(ip6 and udp and ip6 src {target}) or "
            f"(icmp6 and ip6 src {target})"
        )

    elif transport == Transport.dns:
        filter = (
            f"(ip6 and udp and ip6 src {target} and port 53) or "
            f"(icmp6 and ip6 src {target})"
        )

    elif transport == Transport.tcp:
        filter = f"ip6 and tcp and ip6 src {target}"

    elif transport == Transport.ssh:
        filter = f"ip6 and tcp and ip6 src {target} and port 22"

    elif transport == Transport.http:
        filter = f"ip6 and tcp and ip6 src {target} and port 80"

    elif transport == Transport.https:
        filter = f"ip6 and tcp and ip6 src {target} and port 443"

    else:
        filter = f"ip6 and ip6 src {target}"
    
    t0: Dict[str, Optional[int]] = {"ns": None}

    def _on_start():
        t0["ns"] = time.perf_counter_ns()
        send(pkt, verbose=False)
    
    pkts = sniff(
        count = 1,
        timeout=timeout,
        filter=filter,
        started_callback=_on_start,
        store = True
    )
    
    if not pkts or t0["ns"] is None:
        return None, None

    rtt_ms = (time.perf_counter_ns() - t0["ns"]) / 1_000_000
    return pkts[0], rtt_ms
    
#TODO: document the new code

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

    DEFAULT_PAYLOAD = 56    
    
    n = int(count) if count is not None else 4
    gap = float(interval) if interval is not None else 1.0
    
    tmo = per_probe_timeout
    if tmo is None:
        tmo = cfg.timeout if getattr(cfg, "timeout", None) is not None else 2.0
    if tmo is not None:
        tmo = float(tmo)
    else:
        tmo = 2.0
        
    if n <= 0:
        raise ValueError("--count must be >= 1")
    if gap < 0:
        raise ValueError("--interval must be >= 0")
    if tmo <= 0:
        raise ValueError("--per-probe-timeout/--timeout must be > 0")
    
    t = cfg.transport or Transport.icmp
    
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

    total_start = _now_ms()
    for seq in range(1, n + 1):
        base = build_ipv6_base(cfg, dest=target)
        pkt = apply_eh_chain(cfg, base)
        pkt = apply_transport_layer(
            cfg,
            pkt,
            transport=t,
            payload=b"\x00" * DEFAULT_PAYLOAD,
            dest=dest,
            icmp_id=ident,
            icmp_seq=seq,
            tcp_flags="S"
        )
        
        reply, rtt_ms = _send_packet(pkt, target=target, transport=t, timeout=tmo)
        
        reply_status = _interpret_reply(t, reply)
        
        if reply is not None:
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
        
        if seq != n:
            time.sleep(gap)
    
    total_time = int(round(_now_ms() - total_start))
    sent = n
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