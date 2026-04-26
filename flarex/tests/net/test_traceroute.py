from __future__ import annotations

import pytest

import flarex.net.traceroute as tr
from flarex.cli.models import CommonConfig, Destination, EHName, Transport


TARGET = "2001:db8::ff"
DEST = Destination(raw="example.com", kind="hostname", value="example.com")


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
        eh_auto_order=eh_auto_order,
        eh_strict=eh_strict,
        eh_chain=eh_chain,
        transport=transport,
    )

class _FakeHop:
    """ICMPv6 Time Exceeded from an intermediate router."""
    def __init__(self, src: str):
        self._src = src

    def haslayer(self, layer):
        return layer.__name__ in ("ICMPv6TimeExceeded", "IPv6")

    def __getitem__(self, layer):
        if layer.__name__ == "IPv6":
            return type("_IP", (), {"src": self._src})()

    def __len__(self):
        return 80

class _FakeTarget:
    """ICMPv6 Echo Reply from the final target."""
    def __init__(self, src: str):
        self._src = src

    def haslayer(self, layer):
        return layer.__name__ in ("ICMPv6EchoReply", "IPv6")

    def __getitem__(self, layer):
        if layer.__name__ == "IPv6":
            return type("_IP", (), {"src": self._src})()

    def __len__(self):
        return 64

def _mock_network(monkeypatch, *, target=TARGET, reply_fn=None):
    """Patch all network I/O in the traceroute module."""
    monkeypatch.setattr(tr, "resolve_address",
        lambda dest: target if dest.kind == "hostname" else dest.value)
    monkeypatch.setattr(tr, "build_ipv6_base", lambda cfg, dest, **kw: object())
    monkeypatch.setattr(tr, "apply_eh_chain", lambda cfg, pkt: pkt)
    monkeypatch.setattr(tr, "apply_transport_layer", lambda cfg, pkt, **kw: pkt)
    monkeypatch.setattr(tr, "parse_destination", lambda s: Destination(s, "ipv6", s))
    monkeypatch.setattr(tr.time, "sleep", lambda *_: None)

    if reply_fn is not None:
        monkeypatch.setattr(tr, "send_packet", reply_fn)
    else:
        monkeypatch.setattr(tr, "send_packet", lambda pkt, **kw: (None, None))


# Event structure

def test_event_sequence_start_hops_done(monkeypatch):
    _mock_network(monkeypatch)
    events = list(tr.traceroute(mk_cfg(), DEST, max_hop=3, probes=1))
    assert events[0]["type"] == "start"
    assert events[-1]["type"] == "done"
    hop_types = [e["type"] for e in events[1:-1]]
    assert hop_types == ["hop", "hop", "hop"]

def test_start_event_fields(monkeypatch):
    _mock_network(monkeypatch)
    start = list(tr.traceroute(mk_cfg(payload_size=60), DEST, max_hop=1, probes=1))[0]
    assert start["max_hops"] == 1
    assert start["payload_size"] == 60
    assert start["destination"]["resolved"] == TARGET
    assert start["loop_threshold"] == 3

def test_hop_event_has_required_keys(monkeypatch):
    _mock_network(monkeypatch)
    events = list(tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=1))
    hop = [e for e in events if e["type"] == "hop"][0]
    assert "hop" in hop
    assert "source" in hop
    assert "rtts" in hop
    assert "destination" in hop


# Target reached

def test_stops_when_target_reached(monkeypatch):
    call_count = [0]

    def reply_fn(pkt, **kw):
        call_count[0] += 1
        if call_count[0] == 3:
            return (_FakeTarget(TARGET), 5.0)
        return (_FakeHop(f"2001:db8::{call_count[0]}"), 10.0)

    _mock_network(monkeypatch, reply_fn=reply_fn)
    events = list(tr.traceroute(mk_cfg(), DEST, max_hop=10, probes=1))
    assert events[-1]["reached"] is True
    assert len([e for e in events if e["type"] == "hop"]) == 3

def test_done_reached_false_when_max_hops_exhausted(monkeypatch):
    _mock_network(monkeypatch)
    done = list(tr.traceroute(mk_cfg(), DEST, max_hop=3, probes=1))[-1]
    assert done["reached"] is False
    assert done["loop_detected"] is False


# Timeout / reply recording

def test_all_timeout_probes_produce_star_rtts(monkeypatch):
    _mock_network(monkeypatch)
    hop = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=3)
           if e["type"] == "hop"][0]
    assert hop["rtts"] == ["*", "*", "*"]
    assert hop["source"]["raw"] is None

def test_reply_rtt_is_recorded(monkeypatch):
    _mock_network(monkeypatch, reply_fn=lambda pkt, **kw: (_FakeHop("2001:db8::1"), 15.0))
    hop = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=3)
           if e["type"] == "hop"][0]
    assert all(isinstance(r, float) for r in hop["rtts"])
    assert hop["rtts"] == [15.0, 15.0, 15.0]

def test_hop_source_set_from_first_reply(monkeypatch):
    _mock_network(monkeypatch, reply_fn=lambda pkt, **kw: (_FakeHop("2001:db8::router"), 10.0))
    hop = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=1)
           if e["type"] == "hop"][0]
    assert hop["source"]["raw"] == "2001:db8::router"

def test_mixed_timeout_and_reply_rtts(monkeypatch):
    responses = iter([
        (None, None),
        (_FakeHop("2001:db8::1"), 20.0),
        (None, None),
    ])
    _mock_network(monkeypatch, reply_fn=lambda pkt, **kw: next(responses))
    hop = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=3)
           if e["type"] == "hop"][0]
    assert hop["rtts"] == ["*", 20.0, "*"]


# Loop detection

def test_loop_detected_after_threshold_repeats(monkeypatch):
    _mock_network(monkeypatch,
        reply_fn=lambda pkt, **kw: (_FakeHop("2001:db8::loop"), 5.0))
    done = list(tr.traceroute(mk_cfg(), DEST, max_hop=20, probes=1, loop_threshold=3))[-1]
    assert done["loop_detected"] is True

def test_loop_not_triggered_for_unique_sources(monkeypatch):
    counter = [0]

    def reply_fn(pkt, **kw):
        counter[0] += 1
        return (_FakeHop(f"2001:db8::{counter[0]}"), 5.0)

    _mock_network(monkeypatch, reply_fn=reply_fn)
    done = list(tr.traceroute(mk_cfg(), DEST, max_hop=5, probes=1, loop_threshold=3))[-1]
    assert done["loop_detected"] is False

def test_loop_threshold_respected(monkeypatch):
    """A threshold of 2 means loop fires sooner than the default 3."""
    _mock_network(monkeypatch,
        reply_fn=lambda pkt, **kw: (_FakeHop("2001:db8::loop"), 5.0))
    events = list(tr.traceroute(mk_cfg(), DEST, max_hop=20, probes=1, loop_threshold=2))
    done = events[-1]
    assert done["loop_detected"] is True
    hops_with_threshold_2 = len([e for e in events if e["type"] == "hop"])

    _mock_network(monkeypatch,
        reply_fn=lambda pkt, **kw: (_FakeHop("2001:db8::loop"), 5.0))
    events3 = list(tr.traceroute(mk_cfg(), DEST, max_hop=20, probes=1, loop_threshold=3))
    hops_with_threshold_3 = len([e for e in events3 if e["type"] == "hop"])

    assert hops_with_threshold_2 < hops_with_threshold_3


# Parameter behaviour

def test_probes_count_per_hop(monkeypatch):
    _mock_network(monkeypatch)
    hop = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=5)
           if e["type"] == "hop"][0]
    assert len(hop["rtts"]) == 5

def test_first_hop_sets_starting_hop_number(monkeypatch):
    _mock_network(monkeypatch)
    hops = [e for e in tr.traceroute(mk_cfg(), DEST, first_hop=3, max_hop=5, probes=1)
            if e["type"] == "hop"]
    assert hops[0]["hop"] == 3
    assert hops[-1]["hop"] == 5

def test_max_hop_limits_total_hops(monkeypatch):
    _mock_network(monkeypatch)
    hops = [e for e in tr.traceroute(mk_cfg(), DEST, max_hop=4, probes=1)
            if e["type"] == "hop"]
    assert len(hops) == 4

def test_wait_probe_sleep_called_between_probes(monkeypatch):
    _mock_network(monkeypatch)
    calls = []
    monkeypatch.setattr(tr.time, "sleep", lambda t: calls.append(t))
    list(tr.traceroute(mk_cfg(), DEST, max_hop=1, probes=3, wait_probe=0.2))
    assert len(calls) == 2
    assert all(t == 0.2 for t in calls)

def test_no_dns_overrides_dns_transport(monkeypatch):
    transports = []

    def fake_send(pkt, **kw):
        transports.append(kw["transport"])
        return (None, None)

    _mock_network(monkeypatch, reply_fn=fake_send)
    list(tr.traceroute(
        mk_cfg(transport=Transport.dns), DEST,
        max_hop=1, probes=1, no_dns=True,
    ))
    assert all(t == Transport.udp for t in transports)

def test_eh_chain_reflected_in_start_event(monkeypatch):
    _mock_network(monkeypatch)
    chain = [EHName.hop, EHName.dst]
    start = list(tr.traceroute(mk_cfg(eh_chain=chain), DEST, max_hop=1, probes=1))[0]
    assert start["eh_chain"] == ["hop", "dst"]

def test_default_transport_is_udp(monkeypatch):
    transports = []

    def fake_send(pkt, **kw):
        transports.append(kw["transport"])
        return (None, None)

    _mock_network(monkeypatch, reply_fn=fake_send)
    list(tr.traceroute(mk_cfg(transport=None), DEST, max_hop=1, probes=1))
    assert transports[0] == Transport.udp


# Validation

def test_validate_first_hop_zero_raises(monkeypatch):
    monkeypatch.setattr(tr, "resolve_address", lambda d: "::1")
    with pytest.raises(ValueError):
        list(tr.traceroute(mk_cfg(), Destination("::1", "ipv6", "::1"), first_hop=0))

def test_validate_max_hop_zero_raises(monkeypatch):
    monkeypatch.setattr(tr, "resolve_address", lambda d: "::1")
    with pytest.raises(ValueError):
        list(tr.traceroute(mk_cfg(), Destination("::1", "ipv6", "::1"), max_hop=0))

def test_validate_probes_zero_raises(monkeypatch):
    monkeypatch.setattr(tr, "resolve_address", lambda d: "::1")
    with pytest.raises(ValueError):
        list(tr.traceroute(mk_cfg(), Destination("::1", "ipv6", "::1"), probes=0))

def test_validate_wait_probe_negative_raises(monkeypatch):
    monkeypatch.setattr(tr, "resolve_address", lambda d: "::1")
    with pytest.raises(ValueError):
        list(tr.traceroute(mk_cfg(), Destination("::1", "ipv6", "::1"), wait_probe=-1))

def test_validate_timeout_zero_raises(monkeypatch):
    monkeypatch.setattr(tr, "resolve_address", lambda d: "::1")
    with pytest.raises(ValueError):
        list(tr.traceroute(mk_cfg(timeout=0.0), Destination("::1", "ipv6", "::1")))
