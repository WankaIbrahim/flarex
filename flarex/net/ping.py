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

def _send_packet(pkt, *, transport, timeout):
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
        
    pkts = sniff(
        timeout=timeout,
        filter=filter,
        started_callback=lambda: send(pkt, verbose=False),
    )
    return pkts[-1] if pkts else None
    
#TODO: document the new code

def ping(
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
        "cmd": "ping",
        "transport": getattr(t, "value", str(t)),
        "destination": {
            "raw": dest.raw,
            "kind": dest.kind,
            "value": dest.value,
            "resolved": target,
        },
        "count": n,
        "interval": gap,
        "timeout": tmo,
        "payload_size": getattr(cfg, "payload_size", None),
        "eh_chain": [getattr(e, "value", str(e)) for e in (cfg.eh_chain or [])] if cfg.eh_chain is not None else None,     
    }
    
    received = 0
    rtts = []
    ident = int(time.time()) & 0xFFFF

    for seq in range(1, n + 1):
        base = build_ipv6_base(cfg, dest=target)
        pkt = apply_eh_chain(cfg, base)
        pkt = apply_transport_layer(
            cfg,
            pkt,
            transport=t,
            dest=dest,
            icmp_id=ident,
            icmp_seq=seq,
            tcp_flags="S"
        )
        
        start_ms = _now_ms()
        reply = _send_packet(pkt, transport=t, timeout=tmo)
        rtt_ms = _now_ms() - start_ms
        
        reply_status = _interpret_reply(t, reply)
        
        out_rtt = None
        if reply is not None:
            received += 1
            rtts.append(rtt_ms)
            out_rtt = round(rtt_ms, 3)
        
        yield {
            "type": "probe",
            "seq": seq,
            "addr": target,
            "transport": str(t),
            "status": reply_status,
            "rtt_ms": out_rtt,
        }
        
        if seq != n:
            time.sleep(gap)
            
    sent = n
    pkt_loss = (1.0 - (received / sent)) * 100.0 if sent else 0
    summary = {
        "sent": sent,
        "received": received,
        "loss_pct": pkt_loss,
        "min_ms": min(rtts) if rtts else None,
        "avg_ms": (sum(rtts) / len(rtts)) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
    }

    yield {"type": "summary", "summary": summary}
    
    
    
if __name__ == "__main__":
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrHopByHop
    from scapy.all import sniff, send
    from flarex.cli.models import CommonConfig, Destination, Transport, EHName

    
    """
    AAAA Records
    muerte.ecs --> 2001:630:d0:1002::f003
    grim.ecs ----> 2001:630:d0:1002::d1e3
    """
    target = "2001:630:d0:1002::f003"

    #Individual Packet
    pkt = IPv6(dst=target) / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()
    filter = f"icmp6 and ip6 src {target} and ip6[40] == 129"
    pkts = sniff(
        timeout=2,
        filter=filter,
        started_callback=lambda: send(pkt, verbose=False),
    )
    reply = pkts[-1] if pkts else None
    print(reply)

    #Ping
    transport = Transport.icmp
    eh_chain = [EHName.hop]
    count = 2
    payload_size = 0

    cfg = CommonConfig(
        hop_limit=None,
        src=None,
        flowlabel=None,
        payload_size=payload_size,
        timeout=2,
        wait=None,
        quiet=False,
        verbose=False,
        json=False,
        eh_auto_order=False,
        eh_strict=False,
        eh_chain=eh_chain,
        transport=transport,
    )

    dest = Destination(
        raw=target,
        kind="hostname" if ":" not in target else "ipv6",
        value=target,
    )

    for event in ping(cfg, dest, count=count, interval=1):
        print(event, end="\n\n")