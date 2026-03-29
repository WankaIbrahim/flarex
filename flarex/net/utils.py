from __future__ import annotations

import socket
import time
from typing import Any, Optional, List, Dict

from flarex.cli.models import CommonConfig, EHName, Transport, Destination

from scapy.all import send, sniff, Packet, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, TCP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
    ICMPv6DestUnreach,
    ICMPv6TimeExceeded,
    ICMPv6EchoReply,
    ICMPv6PacketTooBig,
)

def _build_payload(cfg: CommonConfig, default: bytes | None = None) -> bytes:
    """
    Build a payload bytes object.

    If cfg.payload_size is set, returns that many bytes.
    Otherwise, returns "default" if provided.
    If neither is set, returns b"".

    
    Raises:
        ValueError: If payload_size is negative.
    """
    n = getattr(cfg, "payload_size", None)

    if n is not None:
        n = int(n)
        if n < 0:
            raise ValueError("--payload-size must be >= 0")
        return b"\x00" * n

    if default is not None:
        return default

    return b""

def now_ms() -> float:
    """
    Get the current time in milliseconds
    
    Returns:
        The current time in milliseconds
    """
    return time.perf_counter() * 1000.0

def interpret_reply(t: Transport, reply: Optional[Packet]):
    """
    Looks through a packets layers to determine what the packet is responding to
    
    Args:
        t: The transport protocol used
        reply: The packet to be interpreted
        
    Returns:
        A string indicating what sort of packet reply is
    """
    if reply is None:
        return "timeout"

    if reply.haslayer(ICMPv6EchoReply):
        return "icmp_reply"

    if reply.haslayer(ICMPv6PacketTooBig):
        return "icmp_packet_too_big"

    if reply.haslayer(ICMPv6TimeExceeded):
        return "icmp_time_exceeded"

    if reply.haslayer(ICMPv6DestUnreach):
        return "icmp_dest_unreach"
    
    if reply.haslayer(TCP):
        return "tcp_reply"

    if reply.haslayer(UDP):
        return "udp_reply"

    return "unknown_reply"

def send_packet(pkt, *, target, transport, timeout, is_traceroute: bool = False, pmtud: bool = False):
    """
    Send a single probe packet and return the first matching reply.

    Builds a BPF capture filter tuned to the transport and mode, then fires
    the packet via Scapy's ``send()`` inside ``sniff()``'s start callback so
    that the timestamp is recorded atomically with transmission.

    Args:
        pkt: Assembled Scapy packet ready to send.
        target: Resolved IPv6 address of the destination (used in filters).
        transport: Transport protocol; controls which reply packets are accepted.
        timeout: Maximum seconds to wait for a reply.
        is_traceroute: When ``True``, relaxes the source filter to accept
            ICMPv6 Time Exceeded from any router, not just the target.
        pmtud: When ``True``, appends an additional filter clause to capture
            ICMPv6 Packet Too Big (type 2) messages from any intermediate
            router, enabling Path MTU Discovery.

    Returns:
        A ``(packet, rtt_ms)`` tuple where ``packet`` is the first captured
        reply and ``rtt_ms`` is the round-trip time in milliseconds. Returns
        ``(None, None)`` if no reply arrives within ``timeout``.
    """
    icmp_filter = "icmp6" if is_traceroute else f"icmp6 and ip6 src {target}"

    if transport == Transport.icmp:
        if is_traceroute:
            filter = f"(icmp6 and ip6 src {target} and ip6[40] == 129) or (icmp6 and ip6[40] == 3)"
        else:
            filter = f"icmp6 and ip6 src {target} and ip6[40] == 129"

    elif transport == Transport.udp:
        if is_traceroute:
            filter = icmp_filter
        else:
            filter = (
                f"(ip6 and udp and ip6 src {target}) or "
                f"{icmp_filter}"
            )

    elif transport == Transport.dns:
        filter = (
            f"(ip6 and udp and ip6 src {target} and port 53) or "
            f"{icmp_filter}"
        )

    elif transport in (Transport.tcp, Transport.ssh, Transport.http, Transport.https):
        port = {
            Transport.tcp: 443,
            Transport.ssh: 22,
            Transport.http: 80,
            Transport.https: 443,
        }[transport]
        filter = (
            f"(ip6 and tcp and ip6 src {target} and port {port}) or "
            f"{icmp_filter}"
        )

    else:
        filter = f"(ip6 and ip6 src {target}) or {icmp_filter}"

    if pmtud:
        filter += " or (icmp6 and ip6[40] == 2)"

    t0: Dict[str, Optional[int]] = {"ns": None}

    def _on_start():
        t0["ns"] = time.perf_counter_ns()
        send(pkt, verbose=False)

    pkts = sniff(
        count=1,
        timeout=timeout,
        filter=filter,
        started_callback=_on_start,
        store=True,
    )

    if not pkts or t0["ns"] is None:
        return None, None

    rtt_ms = (time.perf_counter_ns() - t0["ns"]) / 1_000_000
    return pkts[0], rtt_ms

def resolve_address(dest: Destination) -> str:
    """
    Resolve a destination into a single IPv6 address
    
    Args:
        dest: A Destination object containing either an IPv6 literal or a hostname.
    
    Returns:
        The first resolved IPv6 address as a string
        
    Raises:
        RuntimeError: If no IPv6 address is found.
    """
    if dest.kind == "ipv6":
        return dest.value
    
    infos = socket.getaddrinfo(dest.value, None, socket.AF_INET6, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"No IPv6 addresses found for hostname: {dest.value}")
    
    return str(infos[0][4][0])

def apply_eh_chain(cfg: CommonConfig, pkt: Any):
    """
    Apply an IPv6 extension header chain to a Scapy IPv6 packet.
    
    Supported EHs
    - Hop-by-hop options (hop, hbh)
    - Destination options (dst)
    - Routing (rt)
    - Fragmentation (frag)
    
    Unsupported EHs
    - Authentication (ah)
    - Encapsulating Security Payload (esp)
    - Mobility (mobility)
    
    Args:
        pkt: A Scapy IPv6 packet with base header fields populated.
        cfg: Common configuration options shared across commands.
    
    Returns:
        A Scapy IPv6 packet with extension headers attached to it or 
            the input packet if no extension headers were specified
        
    Raises:
        ValueError: If more than 3 extension headers are chained together or
            if conflicting flags are provided or if an EH is not implemented
    """
    if cfg.eh_chain is None:
        return pkt
    
    if len(cfg.eh_chain) == 0:
        return pkt
    
    if len(cfg.eh_chain) > 3:
        raise ValueError("Cannot chain more than 3 extension headers together")

    if cfg.eh_auto_order and cfg.eh_strict:
        raise ValueError("Cannot use --eh-auto-order and --eh-strict together.")

    chain: List[EHName] = list(cfg.eh_chain)
    
    if cfg.eh_auto_order:
        order = {
            EHName.hop: 10,
            EHName.hbh: 10,
            EHName.dst: 20,
            EHName.rt: 30,
            EHName.frag: 40,
            EHName.ah: 50,
            EHName.esp: 60,
            EHName.mobility: 70,
        }
        chain.sort(key=lambda eh: order.get(eh, 999))

    for eh in chain:
        if eh in (EHName.hop, EHName.hbh):
            pkt = pkt / IPv6ExtHdrHopByHop()
        elif eh == EHName.dst:
            pkt = pkt / IPv6ExtHdrDestOpt()
        elif eh == EHName.rt:
            pkt = pkt / IPv6ExtHdrRouting()
        elif eh == EHName.frag:
            pkt = pkt / IPv6ExtHdrFragment()
        elif eh in (EHName.ah, EHName.esp, EHName.mobility):
            raise ValueError(f"Extension header '{eh.value}' is not implemented yet.")
        else:
            raise ValueError(f"Unexpected EH value: {eh!r}")
    
    return pkt

def apply_transport_layer(
    cfg: CommonConfig,
    pkt: Any,
    *,
    transport: Optional[Transport] = None,
    payload: bytes | None = None,
    dest: "Destination | None" = None,
    icmp_id: Optional[int] = None,
    icmp_seq: Optional[int] = None,
    tcp_flags: str = "S",
    force_payload: bytes | None = None,
) -> Any:
    """
    Apply a transport layer to a Scapy IPv6 packet.
    
    If "payload" is None and cfg.payload_size is set, a payload of that size
    is automatically generated and attached. If "payload" is provided it is used as-is.

    Args:
        pkt: Scapy IPv6 packet.
        cfg: A CommonConfig object.
        transport: Override transport. If None, uses cfg.transport, else defaults to ICMP.
        payload: Optional payload bytes. If None, may be generated from cfg.payload_size.
        dest: Destination object.
        icmp_id: ICMPv6 Echo identifier.
        icmp_seq: ICMPv6 Echo sequence.
        tcp_flags: TCP flags string for TCP probes.
        force_payload: If provided, used as the exact payload bytes, bypassing
            both ``payload`` and ``cfg.payload_size``. Used by PMTUD to enforce
            a specific probe size regardless of user-supplied payload settings.

    Returns:
        Packet with transport layer attached.

    Raises:
        ValueError: For unsupported or unhandled transports.
    """
    data = force_payload if force_payload is not None else _build_payload(cfg, default=payload)
    
    t = transport if transport is not None else cfg.transport
    if t is None:
        t = Transport.icmp

    if t == Transport.icmp:
        layer = ICMPv6EchoRequest()
        if icmp_id is not None:
            layer.id = int(icmp_id)
        if icmp_seq is not None:
            layer.seq = int(icmp_seq)
            
        pkt = pkt / layer
        return (pkt / Raw(load=data)) if data else pkt

    if t == Transport.dns:
        if dest is None or dest.kind != "hostname":
            raise ValueError("Transport 'dns' requires a destination of type hostname")

        qname = dest.value
        dns_payload = DNS(rd=1, qd=DNSQR(qname=qname, qtype="AAAA"))
        return pkt / UDP(dport=53) / dns_payload

    if t == Transport.udp:
        pkt = pkt / UDP(dport=33434)
        return (pkt / Raw(load=data)) if data else pkt

    if t == Transport.tcp:
        pkt = pkt / TCP(dport=443, flags=tcp_flags)
        return (pkt / Raw(load=data)) if data else pkt

    if t == Transport.ssh:
        pkt = pkt / TCP(dport=22, flags=tcp_flags)
        return (pkt / Raw(load=data)) if data else pkt

    if t == Transport.http:
        pkt = pkt / TCP(dport=80, flags=tcp_flags)
        return (pkt / Raw(load=data)) if data else pkt

    if t == Transport.https:
        pkt = pkt / TCP(dport=443, flags=tcp_flags)
        return (pkt / Raw(load=data)) if data else pkt

    raise RuntimeError(f"Unhandled transport enum: {t!r}")
    
def build_ipv6_base(cfg: CommonConfig, dest: str, *, hop_limit: int | None = None):
    """
    Build a base IPv6 header using CommonConfig fields.
    
    Args:
        cfg: Common configuration options shared across commands.
        dest: Destination IPv6 address string.
    
    Returns:
        A Scapy IPv6 packet with base header fields populated
    """
    pkt = IPv6(dst=dest, hlim=hop_limit if hop_limit is not None else 64)
    
    if getattr(cfg, "src", None):
        pkt.src = cfg.src
    
    hlim = getattr(cfg, "hop_limit", None)
    if hlim is not None and hop_limit is None:
        pkt.hlim = int(hlim)
    
    flowlabel = getattr(cfg, "flowlabel", None)
    if flowlabel is not None:
        pkt.fl = int(flowlabel)
        
    return pkt
