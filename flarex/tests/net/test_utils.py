from __future__ import annotations

import pytest

from flarex.net.utils import (
    _build_payload,
    build_ipv6_base,
    apply_eh_chain,
    apply_transport_layer,
    interpret_reply,
    resolve_address,
)
from flarex.cli.models import CommonConfig, EHName, Transport, Destination

from scapy.layers.inet import UDP, TCP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
)
from scapy.layers.dns import DNS
from scapy.packet import Raw


def mk_cfg(
    *,
    payload_size=None,
    transport=None,
    eh_chain=None,
    eh_auto_order=False,
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
        eh_auto_order=eh_auto_order,
        eh_chain=eh_chain,
        transport=transport,
    )


class _FakePkt:
    """Minimal Scapy-like packet stub for interpret_reply tests."""
    def __init__(self, *layer_names):
        self._layers = set(layer_names)

    def haslayer(self, layer):
        return layer.__name__ in self._layers

    def __len__(self):
        return 60


# _build_payload

def test_build_payload_no_size_no_default():
    assert _build_payload(mk_cfg()) == b""

def test_build_payload_with_size():
    assert _build_payload(mk_cfg(payload_size=10)) == b"\x00" * 10

def test_build_payload_zero_size():
    assert _build_payload(mk_cfg(payload_size=0)) == b""

def test_build_payload_default_used_when_no_size():
    assert _build_payload(mk_cfg(), default=b"hello") == b"hello"

def test_build_payload_size_overrides_default():
    assert _build_payload(mk_cfg(payload_size=3), default=b"hello") == b"\x00\x00\x00"

def test_build_payload_negative_raises():
    with pytest.raises(ValueError):
        _build_payload(mk_cfg(payload_size=-1))


# build_ipv6_base

def test_build_ipv6_base_sets_dst():
    assert build_ipv6_base(mk_cfg(), "::1")[IPv6].dst == "::1"

def test_build_ipv6_base_default_hlim():
    assert build_ipv6_base(mk_cfg(), "::1")[IPv6].hlim == 64

def test_build_ipv6_base_explicit_hop_limit_param():
    assert build_ipv6_base(mk_cfg(), "::1", hop_limit=5)[IPv6].hlim == 5

def test_build_ipv6_base_cfg_hop_limit():
    assert build_ipv6_base(mk_cfg(hop_limit=10), "::1")[IPv6].hlim == 10

def test_build_ipv6_base_explicit_hop_limit_overrides_cfg():
    assert build_ipv6_base(mk_cfg(hop_limit=10), "::1", hop_limit=3)[IPv6].hlim == 3

def test_build_ipv6_base_src():
    pkt = build_ipv6_base(mk_cfg(src="2001:db8::1"), "::1")
    assert pkt[IPv6].src == "2001:db8::1"

def test_build_ipv6_base_flowlabel():
    assert build_ipv6_base(mk_cfg(flowlabel=0xABCDE), "::1")[IPv6].fl == 0xABCDE


# apply_eh_chain

def test_apply_eh_chain_none_returns_unchanged():
    pkt = IPv6(dst="::1")
    assert apply_eh_chain(mk_cfg(eh_chain=None), pkt) is pkt

def test_apply_eh_chain_empty_returns_unchanged():
    pkt = IPv6(dst="::1")
    assert apply_eh_chain(mk_cfg(eh_chain=[]), pkt) is pkt

def test_apply_eh_chain_hop():
    pkt = apply_eh_chain(mk_cfg(eh_chain=[EHName.hop]), IPv6(dst="::1"))
    assert pkt.haslayer(IPv6ExtHdrHopByHop)

def test_apply_eh_chain_hbh_alias():
    pkt = apply_eh_chain(mk_cfg(eh_chain=[EHName.hbh]), IPv6(dst="::1"))
    assert pkt.haslayer(IPv6ExtHdrHopByHop)

def test_apply_eh_chain_dst():
    pkt = apply_eh_chain(mk_cfg(eh_chain=[EHName.dst]), IPv6(dst="::1"))
    assert pkt.haslayer(IPv6ExtHdrDestOpt)

def test_apply_eh_chain_rt():
    with pytest.raises(ValueError, match="not implemented"):
        apply_eh_chain(mk_cfg(eh_chain=[EHName.rt]), IPv6(dst="::1"))

def test_apply_eh_chain_frag():
    pkt = apply_eh_chain(mk_cfg(eh_chain=[EHName.frag]), IPv6(dst="::1"))
    assert pkt.haslayer(IPv6ExtHdrFragment)

def test_apply_eh_chain_multiple_layers_all_present():
    pkt = apply_eh_chain(mk_cfg(eh_chain=[EHName.hop, EHName.dst, EHName.frag]), IPv6(dst="::1"))
    assert pkt.haslayer(IPv6ExtHdrHopByHop)
    assert pkt.haslayer(IPv6ExtHdrDestOpt)
    assert pkt.haslayer(IPv6ExtHdrFragment)

def test_apply_eh_chain_too_many_raises():
    with pytest.raises(ValueError, match="Cannot chain more than 3"):
        apply_eh_chain(
            mk_cfg(eh_chain=[EHName.hop, EHName.dst, EHName.rt, EHName.frag]),
            IPv6(dst="::1"),
        )

def test_apply_eh_chain_unsupported_raises():
    with pytest.raises(ValueError, match="not implemented"):
        apply_eh_chain(mk_cfg(eh_chain=[EHName.ah]), IPv6(dst="::1"))

def test_apply_eh_chain_auto_order_sorts_hop_before_dst():
    pkt = apply_eh_chain(
        mk_cfg(eh_chain=[EHName.dst, EHName.hop], eh_auto_order=True),
        IPv6(dst="::1"),
    )
    layers = []
    node = pkt
    while node:
        layers.append(type(node).__name__)
        node = node.payload if hasattr(node, "payload") else None
    assert layers.index("IPv6ExtHdrHopByHop") < layers.index("IPv6ExtHdrDestOpt")


# apply_transport_layer

def test_transport_icmp_has_echo_request():
    cfg = mk_cfg()
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.icmp)
    assert out.haslayer(ICMPv6EchoRequest)

def test_transport_icmp_id_and_seq():
    cfg = mk_cfg()
    out = apply_transport_layer(
        cfg, build_ipv6_base(cfg, "::1"),
        transport=Transport.icmp, icmp_id=7, icmp_seq=3,
    )
    assert out[ICMPv6EchoRequest].id == 7
    assert out[ICMPv6EchoRequest].seq == 3

def test_transport_icmp_payload_from_cfg():
    cfg = mk_cfg(payload_size=8)
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.icmp)
    assert out.haslayer(Raw) and len(out[Raw].load) == 8

def test_transport_udp_dport():
    cfg = mk_cfg()
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.udp)
    assert out[UDP].dport == 33434

def test_transport_tcp_dport():
    cfg = mk_cfg()
    assert apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.tcp)[TCP].dport == 443

def test_transport_ssh_dport():
    cfg = mk_cfg()
    assert apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.ssh)[TCP].dport == 22

def test_transport_http_dport():
    cfg = mk_cfg()
    assert apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.http)[TCP].dport == 80

def test_transport_https_dport():
    cfg = mk_cfg()
    assert apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.https)[TCP].dport == 443

def test_transport_dns_has_udp_and_dns_layers():
    cfg = mk_cfg()
    dest = Destination(raw="google.com", kind="hostname", value="google.com")
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.dns, dest=dest)
    assert out.haslayer(UDP) and out[UDP].dport == 53
    assert out.haslayer(DNS)

def test_transport_dns_ignores_payload_size():
    cfg = mk_cfg(payload_size=100)
    dest = Destination(raw="google.com", kind="hostname", value="google.com")
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.dns, dest=dest)
    assert out.getlayer(Raw) is None

def test_transport_dns_requires_hostname():
    cfg = mk_cfg()
    dest = Destination(raw="::1", kind="ipv6", value="::1")
    with pytest.raises(ValueError):
        apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=Transport.dns, dest=dest)

def test_transport_defaults_to_icmp_when_none():
    cfg = mk_cfg(transport=None)
    out = apply_transport_layer(cfg, build_ipv6_base(cfg, "::1"), transport=None)
    assert out.haslayer(ICMPv6EchoRequest)


# interpret_reply

def test_interpret_reply_none_is_timeout():
    assert interpret_reply(None) == "timeout"

def test_interpret_reply_echo_reply():
    assert interpret_reply(_FakePkt("ICMPv6EchoReply")) == "icmp_reply" # type: ignore

def test_interpret_reply_time_exceeded():
    assert interpret_reply(_FakePkt("ICMPv6TimeExceeded")) == "icmp_time_exceeded" # type: ignore

def test_interpret_reply_dest_unreach():
    assert interpret_reply(_FakePkt("ICMPv6DestUnreach")) == "icmp_dest_unreach" # type: ignore

def test_interpret_reply_tcp():
    assert interpret_reply(_FakePkt("TCP")) == "tcp_reply" # type: ignore

def test_interpret_reply_udp():
    assert interpret_reply(_FakePkt("UDP")) == "udp_reply" # type: ignore

def test_interpret_reply_unknown():
    assert interpret_reply(_FakePkt("SomeOtherLayer")) == "unknown_reply" # type: ignore

def test_interpret_reply_echo_reply_takes_priority_over_time_exceeded():
    pkt = _FakePkt("ICMPv6EchoReply", "ICMPv6TimeExceeded")
    assert interpret_reply(pkt) == "icmp_reply" # type: ignore


# resolve_address

def test_resolve_address_ipv6_literal():
    dest = Destination(raw="2001:db8::1", kind="ipv6", value="2001:db8::1")
    assert resolve_address(dest) == "2001:db8::1"

def test_resolve_address_loopback():
    dest = Destination(raw="::1", kind="ipv6", value="::1")
    assert resolve_address(dest) == "::1"

def test_resolve_address_hostname_returns_ipv6():
    dest = Destination(raw="google.com", kind="hostname", value="google.com")
    result = resolve_address(dest)
    assert ":" in result
