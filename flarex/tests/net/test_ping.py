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
    eh_strict=False,
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
        wait=None,
        quiet=False,
        verbose=False,
        json=False,
        eh_auto_order=eh_auto_order,
        eh_strict=eh_strict,
        eh_chain=eh_chain,
        transport=transport,
    )

class _FakeReply:
    """Minimal ICMPv6 echo reply stub."""
    def haslayer(self, layer):
        return layer.__name__ == "ICMPv6EchoReply"

    def __len__(self):
        return 64

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
    events = list(ping.ping_stream(mk_cfg(), DEST, count=3))
    assert [e["type"] for e in events] == ["start", "probe", "probe", "probe", "summary"]

def test_start_event_resolved_address(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping_stream(mk_cfg(), DEST, count=1))[0]
    assert start["destination"]["resolved"] == DEST_IP

def test_start_event_payload_size_from_cfg(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping_stream(mk_cfg(payload_size=128), DEST, count=1))[0]
    assert start["payload_size"] == 128

def test_start_event_default_payload_size(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping_stream(mk_cfg(), DEST, count=1))[0]
    assert start["payload_size"] == 56

def test_probe_seq_numbers_are_sequential(monkeypatch):
    _mock_network(monkeypatch)
    events = list(ping.ping_stream(mk_cfg(), DEST, count=4))
    probes = [e for e in events if e["type"] == "probe"]
    assert [p["seq"] for p in probes] == [1, 2, 3, 4]


# Timeout behaviour

def test_all_timeouts_received_is_zero(monkeypatch):
    _mock_network(monkeypatch)
    summary = list(ping.ping_stream(mk_cfg(), DEST, count=3))[-1]
    assert summary["sent"] == 3
    assert summary["received"] == 0
    assert summary["pkt_loss"] == 100

def test_all_timeouts_rtt_stats_are_none(monkeypatch):
    _mock_network(monkeypatch)
    summary = list(ping.ping_stream(mk_cfg(), DEST, count=2))[-1]
    assert summary["min_ms"] is None
    assert summary["avg_ms"] is None
    assert summary["max_ms"] is None

def test_all_timeouts_probe_status_and_rtt(monkeypatch):
    _mock_network(monkeypatch)
    events = list(ping.ping_stream(mk_cfg(), DEST, count=2))
    for p in [e for e in events if e["type"] == "probe"]:
        assert p["status"] == "timeout"
        assert p["rtt_ms"] is None


# Reply behaviour

def test_replies_increment_received(monkeypatch):
    replies = [(None, None), (_FakeReply(), 12.5), (None, None), (_FakeReply(), 8.0)]
    _mock_network(monkeypatch, replies=replies)
    summary = list(ping.ping_stream(mk_cfg(), DEST, count=4))[-1]
    assert summary["received"] == 2
    assert summary["sent"] == 4
    assert summary["pkt_loss"] == 50

def test_reply_probe_status_is_icmp_reply(monkeypatch):
    _mock_network(monkeypatch, replies=[(_FakeReply(), 5.0)])
    events = list(ping.ping_stream(mk_cfg(), DEST, count=1))
    probe = [e for e in events if e["type"] == "probe"][0]
    assert probe["status"] == "icmp_reply"
    assert probe["rtt_ms"] == 5.0

def test_mixed_probe_statuses(monkeypatch):
    replies = [(None, None), (_FakeReply(), 10.0), (None, None)]
    _mock_network(monkeypatch, replies=replies)
    events = list(ping.ping_stream(mk_cfg(), DEST, count=3))
    statuses = [e["status"] for e in events if e["type"] == "probe"]
    assert statuses == ["timeout", "icmp_reply", "timeout"]

def test_rtt_stats_computed_correctly(monkeypatch):
    replies = [(_FakeReply(), 10.0), (_FakeReply(), 20.0), (_FakeReply(), 30.0)]
    _mock_network(monkeypatch, replies=replies)
    summary = list(ping.ping_stream(mk_cfg(), DEST, count=3))[-1]
    assert summary["min_ms"] == 10.0
    assert summary["avg_ms"] == 20.0
    assert summary["max_ms"] == 30.0


# Sleep / interval behaviour

def test_sleep_called_n_minus_1_times(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping_stream(mk_cfg(), DEST, count=4, interval=0.5))
    assert len(calls) == 3

def test_sleep_uses_provided_interval(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping_stream(mk_cfg(), DEST, count=3, interval=0.25))
    assert all(t == 0.25 for t in calls)

def test_sleep_not_called_for_single_probe(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(ping.time, "sleep", lambda t: calls.append(t))
    list(ping.ping_stream(mk_cfg(), DEST, count=1, interval=1.0))
    assert calls == []


# Extension header chain

def test_eh_chain_reflected_in_start_event(monkeypatch):
    _mock_network(monkeypatch)
    chain = [EHName.hop, EHName.dst]
    start = list(ping.ping_stream(mk_cfg(eh_chain=chain), DEST, count=1))[0]
    assert start["eh_chain"] == ["hop", "dst"]

def test_no_eh_chain_is_none_in_start_event(monkeypatch):
    _mock_network(monkeypatch)
    start = list(ping.ping_stream(mk_cfg(), DEST, count=1))[0]
    assert start["eh_chain"] is None


# Default transport

def test_default_transport_is_icmp(monkeypatch):
    _mock_network(monkeypatch)
    transports = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (transports.append(kw["transport"]), (None, None))[-1])
    list(ping.ping_stream(mk_cfg(transport=None), DEST, count=1))
    assert transports[0] == Transport.icmp

def test_explicit_transport_is_passed_through(monkeypatch):
    _mock_network(monkeypatch)
    transports = []
    monkeypatch.setattr(ping, "send_packet", lambda pkt, **kw: (transports.append(kw["transport"]), (None, None))[-1])
    list(ping.ping_stream(mk_cfg(transport=Transport.udp), DEST, count=1))
    assert transports[0] == Transport.udp


# Validation

def test_validate_count_zero_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(), DEST, count=0))

def test_validate_count_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(), DEST, count=-1))

def test_validate_interval_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(), DEST, interval=-0.1))

def test_validate_timeout_zero_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(), DEST, per_probe_timeout=0))

def test_validate_timeout_negative_raises(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(), DEST, per_probe_timeout=-1))

def test_timeout_falls_back_to_cfg_timeout(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda _: "::1")
    with pytest.raises(ValueError):
        list(ping.ping_stream(mk_cfg(timeout=0.0), DEST))
