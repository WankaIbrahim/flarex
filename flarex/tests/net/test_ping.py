from __future__ import annotations

import pytest

import flarex.net.ping as ping
from flarex.cli.models import CommonConfig, Destination, EHName, Transport


def mk_cfg(
    *,
    payload_size=None,
    transport=None,
    eh_chain=None,
    eh_auto_order=False,
    src=None,
    hop_limit=None,
    flowlabel=None,
    timeout=None,
):
    return CommonConfig(
        hop_limit=hop_limit,
        src=src,
        flowlabel=flowlabel,
        payload_size=payload_size,
        timeout=timeout,
        eh_auto_order=eh_auto_order,
        eh_chain=eh_chain,
        transport=transport,
    )

class _FakeReply:
    """Minimal ICMPv6 echo reply stub."""
    def haslayer(self, layer):
        return layer.__name__ == "ICMPv6EchoReply"

    def __len__(self):
        return 64


class _FakePTBReply:
    """Minimal ICMPv6 Packet Too Big stub."""
    def __init__(self, mtu, router_src=None):
        self._mtu = mtu
        self._router_src = router_src

    def haslayer(self, layer):
        if layer.__name__ == "ICMPv6PacketTooBig":
            return True
        if layer.__name__ == "IPv6":
            return self._router_src is not None
        return False

    def __getitem__(self, layer):
        if layer.__name__ == "ICMPv6PacketTooBig":
            class _MTU:
                mtu = self._mtu
            return _MTU()
        if layer.__name__ == "IPv6":
            class _Src:
                src = self._router_src
            return _Src()
        raise KeyError(layer)

    def __len__(self):
        return 80

DEST = Destination(raw="example.com", kind="hostname", value="example.com")
DEST_IP = "2001:db8::1"

def _mock_network(monkeypatch, replies=None):
    """Patch every network-touching symbol in the ping module."""
    monkeypatch.setattr(ping, "resolve_address", lambda _dest: DEST_IP)
    monkeypatch.setattr(ping, "build_ipv6_base", lambda cfg, dest: object())
    monkeypatch.setattr(ping, "apply_eh_chain", lambda cfg, pkt: pkt)
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: pkt)
    monkeypatch.setattr(ping.time, "sleep", lambda *_: None)

    if replies is not None:
        seq = iter(replies)
        monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: next(seq))
    else:
        monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (None, None))


# Event structure

def test_event_sequence_types(monkeypatch):
    _mock_network(monkeypatch)
    events = list(ping.ping(mk_cfg(), DEST, count=3))
    assert [e["type"] for e in events] == ["start", "probe", "probe", "probe", "summary"]

def test_start_event_resolved_address(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1))[0]
    assert start["destination"]["resolved"] == DEST_IP

def test_start_event_payload_size_from_cfg(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(payload_size=128), DEST, count=1))[0]
    assert start["payload_size"] == 128

def test_start_event_default_payload_size(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1))[0]
    assert start["payload_size"] == 56

def test_probe_seq_numbers_are_sequential(monkeypatch):
    _mock_network(monkeypatch)
    events = list(ping.ping(mk_cfg(), DEST, count=4))
    probes = [e for e in events if e["type"] == "probe"]
    assert [p["seq"] for p in probes] == [1, 2, 3, 4]


# Timeout behaviour

def test_all_timeouts_received_is_zero(monkeypatch):
    _mock_network(monkeypatch)
    summary = list(ping.ping(mk_cfg(), DEST, count=3))[-1]
    assert summary["sent"] == 3
    assert summary["received"] == 0
    assert summary["pkt_loss"] == 100

def test_all_timeouts_rtt_stats_are_none(monkeypatch):
    _mock_network(monkeypatch)
    summary = list(ping.ping(mk_cfg(), DEST, count=2))[-1]
    assert summary["min_ms"] is None
    assert summary["avg_ms"] is None
    assert summary["max_ms"] is None

def test_all_timeouts_probe_status_and_rtt(monkeypatch):
    _mock_network(monkeypatch)
    events = list(ping.ping(mk_cfg(), DEST, count=2))
    for p in [e for e in events if e["type"] == "probe"]:
        assert p["status"] == "timeout"
        assert p["rtt_ms"] is None


# Reply behaviour

def test_replies_increment_received(monkeypatch):
    replies = [(None, None), (_FakeReply(), 12.5), (None, None), (_FakeReply(), 8.0)]
    _mock_network(monkeypatch, replies=replies)
    summary = list(ping.ping(mk_cfg(), DEST, count=4))[-1]
    assert summary["received"] == 2
    assert summary["sent"] == 4
    assert summary["pkt_loss"] == 50

def test_reply_probe_status_is_icmp_reply(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakeReply(), 5.0)])
    events = list(ping.ping(mk_cfg(), DEST, count=1))
    probe = [e for e in events if e["type"] == "probe"][0]
    assert probe["status"] == "icmp_reply"
    assert probe["rtt_ms"] == 5.0

def test_mixed_probe_statuses(monkeypatch):
    replies = [(None, None), (_FakeReply(), 10.0), (None, None)]
    _mock_network(monkeypatch, replies=replies)
    events = list(ping.ping(mk_cfg(), DEST, count=3))
    statuses = [e["status"] for e in events if e["type"] == "probe"]
    assert statuses == ["timeout", "icmp_reply", "timeout"]

def test_rtt_stats_computed_correctly(monkeypatch):
    replies = [(_FakeReply(), 10.0), (_FakeReply(), 20.0), (_FakeReply(), 30.0)]
    _mock_network(monkeypatch, replies=replies)
    summary = list(ping.ping(mk_cfg(), DEST, count=3))[-1]
    assert summary["min_ms"] == 10.0
    assert summary["avg_ms"] == 20.0
    assert summary["max_ms"] == 30.0


# Sleep / interval behaviour

def test_sleep_called_n_minus_1_times(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping(mk_cfg(), DEST, count=4, interval=0.5))
    assert len(calls) == 3

def test_sleep_uses_provided_interval(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping(mk_cfg(), DEST, count=3, interval=0.25))
    assert all(t == 0.25 for t in calls)

def test_sleep_not_called_for_single_probe(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping(mk_cfg(), DEST, count=1, interval=1.0))
    assert calls == []


# Extension header chain

def test_eh_chain_reflected_in_start_event(monkeypatch):
    _mock_network(monkeypatch)
    chain = [EHName.hop, EHName.dst]
    start = list(ping.ping(mk_cfg(eh_chain=chain), DEST, count=1))[0]
    assert start["eh_chain"] == ["hop", "dst"]

def test_no_eh_chain_is_none_in_start_event(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1))[0]
    assert start["eh_chain"] is None


# Default transport

def test_default_transport_is_icmp(monkeypatch):
    _mock_network(monkeypatch)
    transports = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (transports.append(kw["transport"]), (None, None))[-1])
    list(ping.ping(mk_cfg(transport=None), DEST, count=1))
    assert transports[0] == Transport.icmp

def test_explicit_transport_is_passed_through(monkeypatch):
    _mock_network(monkeypatch)
    transports = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (transports.append(kw["transport"]), (None, None))[-1])
    list(ping.ping(mk_cfg(transport=Transport.udp), DEST, count=1))
    assert transports[0] == Transport.udp


# Validation

def test_validate_count_zero_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(), DEST, count=0))

def test_validate_count_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(), DEST, count=-1))

def test_validate_interval_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(), DEST, interval=-0.1))

def test_validate_timeout_zero_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(), DEST, per_probe_timeout=0))

def test_validate_timeout_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(), DEST, per_probe_timeout=-1))

def test_timeout_falls_back_to_cfg_timeout(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping(mk_cfg(timeout=0.0), DEST))


# PMTUD - start event fields

def test_pmtud_default_start_fields(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1))[0]
    assert start["pmtud"] is False
    assert start["pmtu_size"] is None

def test_pmtud_off_start_fields(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=False))[0]
    assert start["pmtud"] is False
    assert start["pmtu_size"] is None

def test_pmtud_on_start_pmtu_size_defaults_to_1500(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True))[0]
    assert start["pmtud"] is True
    assert start["pmtu_size"] == 1500

def test_pmtud_on_start_pmtu_size_uses_provided_value(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True, pmtu_size=1400))[0]
    assert start["pmtu_size"] == 1400


# PMTUD - payload_size in start event

def test_pmtud_on_start_payload_size_derived_from_default_pmtu(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True))[0]
    assert start["payload_size"] == 1500 - 40 - 8  # 1452

def test_pmtud_on_start_payload_size_derived_from_custom_pmtu(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True, pmtu_size=1400))[0]
    assert start["payload_size"] == 1400 - 40 - 8  # 1352

def test_pmtud_off_start_payload_size_unchanged(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping(mk_cfg(), DEST, count=1, pmtud=False))[0]
    assert start["payload_size"] == 56


# PMTUD - send_packet receives pmtud flag

def test_pmtud_on_sends_pmtud_true_to_send_packet(monkeypatch):
    _mock_network(monkeypatch)
    flags = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (flags.append(kw.get("pmtud")), (None, None))[-1])
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True))
    assert flags[0] is True

def test_pmtud_off_sends_pmtud_false_to_send_packet(monkeypatch):
    _mock_network(monkeypatch)
    flags = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (flags.append(kw.get("pmtud")), (None, None))[-1])
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=False))
    assert flags[0] is False

def test_pmtud_none_sends_pmtud_false_to_send_packet(monkeypatch):
    _mock_network(monkeypatch)
    flags = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (flags.append(kw.get("pmtud")), (None, None))[-1])
    list(ping.ping(mk_cfg(), DEST, count=1))
    assert flags[0] is False


# PMTUD - force_payload passed to apply_transport_layer

def test_pmtud_on_force_payload_matches_pmtu_size(monkeypatch):
    _mock_network(monkeypatch)
    payloads = []
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: (payloads.append(kw.get("force_payload")), pkt)[-1])
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True, pmtu_size=1400))
    assert payloads[0] == b"\x00" * (1400 - 40 - 8)

def test_pmtud_off_force_payload_is_none(monkeypatch):
    _mock_network(monkeypatch)
    payloads = []
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: (payloads.append(kw.get("force_payload")), pkt)[-1])
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=False))
    assert payloads[0] is None


# PMTUD - PTB probe event fields

def test_ptb_probe_status_is_icmp_packet_too_big(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakePTBReply(mtu=1400), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["status"] == "icmp_packet_too_big"

def test_ptb_probe_pmtu_field_contains_discovered_mtu(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakePTBReply(mtu=1400), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["pmtu"] == 1400

def test_ptb_probe_reply_src_contains_router_address(monkeypatch):
    router = "2001:db8::ff"
    _mock_network(monkeypatch, replies=[(_FakePTBReply(mtu=1400, router_src=router), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["reply_src"] == router

def test_ptb_probe_reply_src_is_none_when_no_ipv6_layer(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakePTBReply(mtu=1400, router_src=None), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["reply_src"] is None

def test_normal_probe_pmtu_is_none(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakeReply(), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["pmtu"] is None

def test_normal_probe_reply_src_is_none(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakeReply(), 5.0)])
    probe = [e for e in ping.ping(mk_cfg(), DEST, count=1) if e["type"] == "probe"][0]
    assert probe["reply_src"] is None


# PMTUD - PTB not counted as received or in RTT stats

def test_ptb_not_counted_as_received(monkeypatch):
    ptb = _FakePTBReply(mtu=1400)
    _mock_network(monkeypatch, replies=[(ptb, 5.0), (ptb, 5.0), (ptb, 5.0)])
    summary = list(ping.ping(mk_cfg(), DEST, count=3, pmtud=True))[-1]
    assert summary["received"] == 0
    assert summary["pkt_loss"] == 100

def test_ptb_not_in_rtt_stats(monkeypatch):
    ptb = _FakePTBReply(mtu=1400)
    _mock_network(monkeypatch, replies=[(ptb, 5.0), (ptb, 5.0)])
    summary = list(ping.ping(mk_cfg(), DEST, count=2, pmtud=True))[-1]
    assert summary["min_ms"] is None
    assert summary["avg_ms"] is None
    assert summary["max_ms"] is None

def test_ptb_mixed_with_replies_counts_correctly(monkeypatch):
    replies = [(_FakePTBReply(mtu=1400), 5.0), (_FakeReply(), 10.0), (_FakePTBReply(mtu=1300), 5.0)]
    _mock_network(monkeypatch, replies=replies)
    summary = list(ping.ping(mk_cfg(), DEST, count=3, pmtud=True))[-1]
    assert summary["received"] == 1
    assert summary["pkt_loss"] == 67


# PMTUD - adaptive probe resizing after PTB

def test_ptb_reduces_force_payload_for_next_probe(monkeypatch):
    ptb = _FakePTBReply(mtu=1400)
    _mock_network(monkeypatch)
    payloads = []
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: (payloads.append(kw.get("force_payload")), pkt)[-1])
    replies = iter([(ptb, 5.0), (None, None)])
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: next(replies))
    list(ping.ping(mk_cfg(), DEST, count=2, pmtud=True, pmtu_size=1500))
    assert payloads[0] == b"\x00" * (1500 - 40 - 8)
    assert payloads[1] == b"\x00" * (1400 - 40 - 8)

def test_ptb_mtu_clamped_to_1280_minimum(monkeypatch):
    ptb = _FakePTBReply(mtu=600)
    _mock_network(monkeypatch)
    payloads = []
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: (payloads.append(kw.get("force_payload")), pkt)[-1])
    replies = iter([(ptb, 5.0), (None, None)])
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: next(replies))
    list(ping.ping(mk_cfg(), DEST, count=2, pmtud=True, pmtu_size=1500))
    assert payloads[1] == b"\x00" * (1280 - 40 - 8)

def test_ptb_without_pmtud_on_does_not_alter_force_payload(monkeypatch):
    ptb = _FakePTBReply(mtu=1400)
    _mock_network(monkeypatch)
    payloads = []
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: (payloads.append(kw.get("force_payload")), pkt)[-1])
    replies = iter([(ptb, 5.0), (None, None)])
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: next(replies))
    list(ping.ping(mk_cfg(), DEST, count=2))
    assert payloads[0] is None
    assert payloads[1] is None


# PMTUD - validation

def test_pmtu_size_below_1280_raises_when_pmtud_on(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError, match="1280"):
        list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True, pmtu_size=1279))

def test_pmtu_size_at_1280_does_not_raise(monkeypatch):
    _mock_network(monkeypatch)
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=True, pmtu_size=1280))

def test_pmtu_size_below_1280_ignored_when_pmtud_off(monkeypatch):
    _mock_network(monkeypatch)
    list(ping.ping(mk_cfg(), DEST, count=1, pmtud=False, pmtu_size=100))
