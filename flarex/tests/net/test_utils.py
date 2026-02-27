from __future__ import annotations

import pytest

from flarex.net.utils import (
    resolve_address,
    apply_transport_layer,
    _build_payload,
    build_ipv6_base,
)
from flarex.cli.models import CommonConfig, Transport, Destination

from scapy.layers.inet import UDP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS
from scapy.packet import Raw


def mk_cfg(
    *,
    payload_size=None,
    transport=None,
    eh_chain=None,
    eh_auto_order=False,
    eh_strict=False,
    src=None,
    hop_limit=None,
    flowlabel=None,
):
    return CommonConfig(
        hop_limit=hop_limit,
        src=src,
        flowlabel=flowlabel,
        payload_size=payload_size,
        timeout=None,
        wait=None,
        quiet=False,
        verbose=False,
        json=False,
        eh_auto_order=eh_auto_order,
        eh_strict=eh_strict,
        eh_chain=eh_chain,
        transport=transport,
    )

#TODO: include more comprehensive testing, test all the possible combinations of extension headers
def test_resolve_address_ipv6():
    dest = Destination(raw="::1", kind="ipv6", value="::1")
    assert resolve_address(dest) == "::1"

def test_resolve_address_hostname():
    dest = Destination(raw="google.com", kind="hostname", value="google.com")
    assert ':' in resolve_address(dest)

def test_build_payload():
    assert _build_payload(mk_cfg(payload_size=None)) == b""
    assert len(_build_payload(mk_cfg(payload_size=5))) == 5
    assert _build_payload(mk_cfg(payload_size=5), override=b"ipv6") == b"ipv6"

def test_build_ipv6_base():
    pkt = build_ipv6_base(mk_cfg(src="2a00:1450:4009:c15::66", hop_limit=64, flowlabel=7), "2a00:1450:4009:c15::66")
    
    assert pkt.haslayer(IPv6)
    assert pkt.dst == "2a00:1450:4009:c15::66"
    assert pkt.src == "2a00:1450:4009:c15::66"
    assert pkt.hlim == 64
    assert pkt.fl == 7

def test_transport_icmp():
    c = mk_cfg(payload_size=3)
    pkt = build_ipv6_base(c, "::1")
    out = apply_transport_layer(c, pkt, transport=Transport.icmp, icmp_id=1, icmp_seq=2)
    
    assert out.haslayer(ICMPv6EchoRequest)
    assert out.haslayer(Raw) and len(out[Raw].load) == 3

def test_transport_udp_port():
    cfg = mk_cfg(payload_size=0)
    pkt = build_ipv6_base(cfg, "::1")
    
    assert int(apply_transport_layer(cfg, pkt, transport=Transport.udp)[UDP].dport) == 33434

def test_transport_tcp_ports():
    cfg = mk_cfg(payload_size=0)
    pkt = build_ipv6_base(cfg, "::1")

    assert int(apply_transport_layer(cfg, pkt, transport=Transport.tcp)[TCP].dport) == 443
    assert int(apply_transport_layer(cfg, pkt, transport=Transport.ssh)[TCP].dport) == 22
    assert int(apply_transport_layer(cfg, pkt, transport=Transport.http)[TCP].dport) == 80
    assert int(apply_transport_layer(cfg, pkt, transport=Transport.https)[TCP].dport) == 443

def test_transport_dns_():
    cfg = mk_cfg(payload_size=999)
    pkt = build_ipv6_base(cfg, "::1")
    dest = Destination(raw="google.com", kind="hostname", value="google.com")
    
    out = apply_transport_layer(cfg, pkt, transport=Transport.dns, dest=dest)
        
    assert out.haslayer(UDP) and int(out[UDP].dport) == 53
    assert out.haslayer(DNS)
    assert out.getlayer(Raw) is None

def test_transport_dns_hostname():
    cfg = mk_cfg()
    pkt = build_ipv6_base(cfg, "::1")
    dest = Destination(raw="::1", kind="ipv6", value="::1")

    with pytest.raises(ValueError):
        apply_transport_layer(cfg, pkt, transport=Transport.dns, dest=dest)