from __future__ import annotations

import pytest

import flarex.net.ping as ping

from flarex.cli.models import CommonConfig, Destination, Transport

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


def test_ping_emits_start_probe_summary_all_timeouts(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda dest: "2001:db8::1")
    monkeypatch.setattr(ping, "build_ipv6_base", lambda cfg, dest: object())
    monkeypatch.setattr(ping, "apply_eh_chain", lambda cfg, pkt: pkt)
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: pkt)
    monkeypatch.setattr(ping, "sr1", lambda pkt, timeout, verbose: None)
    monkeypatch.setattr(ping.time, "sleep", lambda *_: None)

    cfg = mk_cfg(transport=Transport.icmp)
    dest = Destination(raw="example.com", kind="hostname", value="example.com")

    events = list(ping.ping(cfg, dest, count=3, interval=0, per_probe_timeout=0.01))

    assert events[0]["type"] == "start"
    assert events[0]["destination"]["resolved"] == "2001:db8::1"
    assert events[0]["count"] == 3

    probes = [e for e in events if e["type"] == "probe"]
    assert len(probes) == 3
    assert all(p["status"] == "timeout" for p in probes)
    assert all(p["rtt_ms"] is None for p in probes)

    summary = events[-1]
    assert summary["type"] == "summary"
    assert summary["summary"]["sent"] == 3
    assert summary["summary"]["received"] == 0
    assert summary["summary"]["loss_pct"] == 100.0


def test_ping_counts_received_when_reply_present(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda dest: "2001:db8::1")
    monkeypatch.setattr(ping, "build_ipv6_base", lambda cfg, dest: object())
    monkeypatch.setattr(ping, "apply_eh_chain", lambda cfg, pkt: pkt)
    monkeypatch.setattr(ping, "apply_transport_layer", lambda cfg, pkt, **kw: pkt)
    monkeypatch.setattr(ping.time, "sleep", lambda *_: None)

    class FakeEchoReply:
        def haslayer(self, layer):
            return layer.__name__ == "ICMPv6EchoReply"

    replies = [None, FakeEchoReply(), None]

    def fake_sr1(pkt, timeout, verbose):
        return replies.pop(0)

    monkeypatch.setattr(ping, "sr1", fake_sr1)

    cfg = mk_cfg(transport=Transport.icmp)
    dest = Destination(raw="example.com", kind="hostname", value="example.com")

    events = list(ping.ping(cfg, dest, count=3, interval=0, per_probe_timeout=0.01))

    probes = [e for e in events if e["type"] == "probe"]
    assert [p["status"] for p in probes] == ["timeout", "reply", "timeout"]

    assert probes[0]["rtt_ms"] is None
    assert isinstance(probes[1]["rtt_ms"], float)
    assert probes[2]["rtt_ms"] is None

    summary = events[-1]["summary"]
    assert summary["sent"] == 3
    assert summary["received"] == 1
    assert summary["loss_pct"] == pytest.approx((1 - 1 / 3) * 100.0)


def test_ping_validates_args(monkeypatch):
    monkeypatch.setattr(ping, "resolve_address", lambda dest: "2001:db8::1")

    cfg = mk_cfg()
    dest = Destination(raw="::1", kind="ipv6", value="::1")

    with pytest.raises(ValueError):
        list(ping.ping(cfg, dest, count=0))

    with pytest.raises(ValueError):
        list(ping.ping(cfg, dest, interval=-1))

    with pytest.raises(ValueError):
        list(ping.ping(cfg, dest, per_probe_timeout=0))