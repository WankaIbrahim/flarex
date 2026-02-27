from __future__ import annotations

import socket
from typing import Any, Optional, List

from flarex.cli.models import CommonConfig, EHName, Transport, Destination

from scapy.packet import Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, TCP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
)

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


#TODO: set a limit on the number of extension headers that can be chained
def apply_eh_chain(cfg: CommonConfig, pkt: Any):
    """
    Apply an IPv6 extension header chain to a Scapy IPv6 packet.
    
    Supported EHs
    - Hop-by-hop options (hop, hbh)
    - Destination options (dst)
    - Routing (rt)
    - Fragementation (frag)
    
    Unsupported EHs
    - Authentication (ah)
    - Encapsulating Security Payload (esp)
    - Mobility (mobility)
    
    Args:
        pkt: A Scapy IPv6 packet with base header fields populated.
        cfg: Common configuration options shared across commands.
    
    Returns:
        - A Scapy IPv6 packet with extension headers attached to it or 
            the input packet if no extension headers were specified
        
    Raises:
        ValueError: If conflicting flags are provided or if an EH is not implemented
    """
    if cfg.eh_chain is None:
        return pkt
    
    if len(cfg.eh_chain) == 0:
        return pkt

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

def _build_payload(cfg: CommonConfig, override: bytes | None = None) -> bytes:
    """
    Build a payload bytes object.

    If "override" is provided, it is returned as-is.
    Otherwise, if cfg.payload_size is set, returns that many bytes.
    If cfg.payload_size is not set, returns b"".

    Raises:
        ValueError: If payload_size is negative.
    """
    if override is not None:
        return override

    n = getattr(cfg, "payload_size", None)
    if n is None:
        return b""

    n = int(n)
    if n < 0:
        raise ValueError("--payload-size must be >= 0")

    return b"\x00" * n

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

    Returns:
        Packet with transport layer attached.

    Raises:
        ValueError: For unsupported or unhandled transports.
    """
    data = _build_payload(cfg, override=payload)
    
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
            raise ValueError("Transport 'dns' requeires a destination of type hostname")
        
        qname = dest.value if dest.kind == "hostname" else "ipv6test.google.com"
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

    raise AssertionError(f"Unhandled transport enum: {t!r}")
    
def build_ipv6_base(cfg: CommonConfig, dest: str):
    """
    Build a base IPv6 header using CommonConfig fields.
    
    Args:
        cfg: Common configuration options shared across commands.
        dst: Destination IPv6 address.
    
    Returns:
        A Scapy IPv6 packet with base header fields populated
    """
    pkt = IPv6(dst=dest)
    
    if getattr(cfg, "src", None):
        pkt.src = cfg.src
    
    hlim = getattr(cfg, "hop_limit", None)
    if hlim is not None:
        pkt.hlim = int(hlim)
    
    flowlabel = getattr(cfg, "flowlabel", None)
    if flowlabel is not None:
        pkt.fl = int(flowlabel)
        
    return pkt