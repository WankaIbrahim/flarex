from __future__ import annotations

import pytest

import flarex.net.diagnose as diagnose
from flarex.cli.models import CommonConfig, Destination, DiagnoseMethod, Transport


DEST = Destination(raw="example.com", kind="hostname", value="example.com")
TARGET = "2001:db8::ff"
HOP_A = "2001:db8::1"
HOP_B = "2001:db8::2"
HOP_C = "2001:db8::3"


def mk_cfg(
    *,
    transport=None,
    eh_chain=None,
    eh_auto_order=False,
    eh_strict=False,
    timeout=None,
    src=None,
    hop_limit=None,
    flowlabel=None,
    payload_size=None,
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


def _ping_events(received: int = 4) -> list:
    """Return a minimal ping event stream with the given number of received replies."""
    events = [{"type": "start", "destination": {}}]
    for i in range(1, 5):
        events.append({"type": "probe", "seq": i, "status": "icmp_reply" if i <= received else "timeout"})
    events.append({
        "type": "summary",
        "sent": 4,
        "received": received,
        "pkt_loss": (4 - received) * 25,
        "min_ms": 1.0,
        "avg_ms": 1.0,
        "max_ms": 1.0,
    })
    return events


def _trace_events(hops: list) -> list:
    """Return a minimal traceroute event stream for the given list of hop IPs."""
    events = [{"type": "start", "destination": {}}]
    for i, ip in enumerate(hops, start=1):
        events.append({
            "type": "hop",
            "hop": i,
            "source": {"raw": ip, "resolved": ip},
            "destination": {"raw": DEST.raw, "kind": DEST.kind, "value": DEST.value, "resolved": TARGET},
            "rtts": [5.0],
        })
    events.append({"type": "done", "reached": True, "loop_detected": False})
    return events


def _mock_network(monkeypatch, *, ping_received=4, hops=None, probe_seq=None):
    """
    Patch all I/O in the diagnose module.

    probe_seq: iterable of bool values returned by successive _probe calls.
               If None, all probes return True.
    """
    hops = hops if hops is not None else [HOP_A, HOP_B, HOP_C]

    monkeypatch.setattr(diagnose, "resolve_address", lambda _dest: TARGET)
    monkeypatch.setattr(diagnose, "ping_stream", lambda cfg, dest, **kw: iter(_ping_events(ping_received)))
    monkeypatch.setattr(diagnose, "traceroute", lambda cfg, dest, **kw: iter(_trace_events(hops)))

    if probe_seq is not None:
        seq = iter(probe_seq)
        monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: next(seq))
    else:
        monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: True)


# _hop_count

def test_hop_count_empty():
    assert diagnose._hop_count([]) == {}

def test_hop_count_single_unfiltered():
    assert diagnose._hop_count([(HOP_A, True)]) == {HOP_A: [1, 0]}

def test_hop_count_single_filtered():
    assert diagnose._hop_count([(HOP_A, False)]) == {HOP_A: [0, 1]}

def test_hop_count_accumulates_same_ip():
    data = [(HOP_A, True), (HOP_A, True), (HOP_A, False)]
    assert diagnose._hop_count(data) == {HOP_A: [2, 1]}

def test_hop_count_multiple_ips():
    data = [(HOP_A, True), (HOP_B, False), (HOP_A, False)]
    counts = diagnose._hop_count(data)
    assert counts[HOP_A] == [1, 1]
    assert counts[HOP_B] == [0, 1]


# _find_filtering_hop

def test_find_filtering_hop_empty():
    assert diagnose._find_filtering_hop({}) is None

def test_find_filtering_hop_clean_candidate():
    counts = {HOP_A: [3, 0], HOP_B: [0, 3]}
    assert diagnose._find_filtering_hop(counts) == HOP_B

def test_find_filtering_hop_all_unfiltered_returns_none():
    counts = {HOP_A: [5, 0], HOP_B: [3, 0]}
    assert diagnose._find_filtering_hop(counts) is None

def test_find_filtering_hop_prefers_clean_over_ratio():
    counts = {HOP_A: [1, 9], HOP_B: [0, 5]}
    assert diagnose._find_filtering_hop(counts) == HOP_B

def test_find_filtering_hop_fallback_to_ratio_above_half():
    counts = {HOP_A: [1, 3]}
    assert diagnose._find_filtering_hop(counts) == HOP_A

def test_find_filtering_hop_ratio_at_half_returns_none():
    counts = {HOP_A: [2, 2]}
    assert diagnose._find_filtering_hop(counts) is None

def test_find_filtering_hop_ratio_below_half_returns_none():
    counts = {HOP_A: [3, 1]}
    assert diagnose._find_filtering_hop(counts) is None

def test_find_filtering_hop_picks_highest_ratio():
    counts = {HOP_A: [2, 3], HOP_B: [1, 4]}
    assert diagnose._find_filtering_hop(counts) == HOP_B


# diagnose

def test_diagnose_first_event_is_start(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    assert events[0]["type"] == "start"

def test_diagnose_start_event_has_destination_fields(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    start = list(diagnose.diagnose(mk_cfg(), DEST))[0]
    assert start["destination"]["resolved"] == TARGET
    assert "method" in start
    assert "transport" in start

def test_diagnose_early_exit_on_no_loss(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    types = [e["type"] for e in events]
    assert "result" in types
    assert "trace_hop" not in types
    assert "probe" not in types

def test_diagnose_early_exit_result_has_no_filtered_hop(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    result = next(e for e in diagnose.diagnose(mk_cfg(), DEST) if e["type"] == "result")
    assert result["filtered_hop"] is None
    assert result["reason"] == "no_loss"

def test_diagnose_early_exit_ends_with_done(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    assert events[-1]["type"] == "done"

def test_diagnose_ping_events_are_wrapped(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    ping_results = [e for e in events if e["type"] == "ping_result"]
    assert len(ping_results) == 6

def test_diagnose_with_loss_emits_trace_hops(monkeypatch):
    _mock_network(monkeypatch, ping_received=2, hops=[HOP_A, HOP_B])
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    trace_hops = [e for e in events if e["type"] == "trace_hop"]
    assert len(trace_hops) == 2

def test_diagnose_default_method_is_confirm_last(monkeypatch):
    _mock_network(monkeypatch, ping_received=2, hops=[HOP_A, HOP_B])
    result = next(e for e in diagnose.diagnose(mk_cfg(), DEST) if e["type"] == "result")
    assert result["method"] == DiagnoseMethod.confirm_last.value

def test_diagnose_dispatches_to_hop_scan(monkeypatch):
    _mock_network(monkeypatch, ping_received=2, hops=[HOP_A, HOP_B])
    result = next(
        e for e in diagnose.diagnose(mk_cfg(), DEST, method=DiagnoseMethod.hop_scan)
        if e["type"] == "result"
    )
    assert result["method"] == DiagnoseMethod.hop_scan.value

def test_diagnose_max_steps_truncates_hops(monkeypatch):
    _mock_network(monkeypatch, ping_received=2, hops=[HOP_A, HOP_B, HOP_C])
    events = list(diagnose.diagnose(mk_cfg(), DEST, max_steps=1))
    probes = [e for e in events if e["type"] == "probe"]
    assert all(p["ttl"] == 1 for p in probes)

def test_diagnose_default_transport_is_icmp(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    start = list(diagnose.diagnose(mk_cfg(transport=None), DEST))[0]
    assert start["transport"] == Transport.icmp.value

def test_diagnose_transport_override_reflected_in_start(monkeypatch):
    _mock_network(monkeypatch, ping_received=4)
    start = list(diagnose.diagnose(mk_cfg(), DEST, transport=Transport.udp))[0]
    assert start["transport"] == Transport.udp.value

def test_diagnose_ends_with_done_when_loss(monkeypatch):
    _mock_network(monkeypatch, ping_received=0, hops=[HOP_A])
    events = list(diagnose.diagnose(mk_cfg(), DEST))
    assert events[-1]["type"] == "done"


# _confirm_last

def _run_confirm_last(monkeypatch, hops, probe_seq):
    seq = iter(probe_seq)
    monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: next(seq))
    return list(diagnose._confirm_last(mk_cfg(), TARGET, DEST, hops, Transport.icmp, 2.0, 1))


def test_confirm_last_all_pass_no_boundary(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    result = _run_confirm_last(monkeypatch, hops, [True] * 6)
    r = next(e for e in result if e["type"] == "result")
    assert r["filtered_hop"] is None
    assert r["ttl"] is None

def test_confirm_last_finds_boundary_at_first_filtered_ttl(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    probe_seq = [True, True,
                 True, False,
                 True, True]
    result = _run_confirm_last(monkeypatch, hops, probe_seq)
    r = next(e for e in result if e["type"] == "result")
    assert r["ttl"] == 2
    assert r["filtered_hop"] == HOP_B

def test_confirm_last_boundary_shifts_back_on_contradiction(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    probe_seq = [True, True,
                 True, False,
                 True, False]
    result = _run_confirm_last(monkeypatch, hops, probe_seq)
    r = next(e for e in result if e["type"] == "result")
    assert r["ttl"] == 1
    assert r["filtered_hop"] == HOP_A

def test_confirm_last_boundary_at_ttl1_no_confirmation_probe(monkeypatch):
    hops = [HOP_A, HOP_B]
    probe_seq = [True, False]
    calls = []
    monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: (calls.append(kw.get("baseline")), probe_seq.pop(0))[1])
    result = list(diagnose._confirm_last(mk_cfg(), TARGET, DEST, hops, Transport.icmp, 2.0, 1)) # type: ignore
    r = next(e for e in result if e["type"] == "result")
    assert r["ttl"] == 1
    assert r["filtered_hop"] == HOP_A

def test_confirm_last_emits_probe_events(monkeypatch):
    hops = [HOP_A, HOP_B]
    probe_seq = [True, True, True, False, True, True]
    result = _run_confirm_last(monkeypatch, hops, probe_seq)
    probe_events = [e for e in result if e["type"] == "probe"]
    assert len(probe_events) >= 2

def test_confirm_last_confirmation_probe_has_confirmation_key(monkeypatch):
    hops = [HOP_A, HOP_B]
    probe_seq = [True, True,
                 True, False,
                 True, True]
    result = _run_confirm_last(monkeypatch, hops, probe_seq)
    confirmation_probes = [e for e in result if e.get("confirmation") is True]
    assert len(confirmation_probes) == 1

def test_confirm_last_stops_at_first_boundary(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    called_ttls = []
    seq = iter([True, True, True, False, True, True])

    def fake_probe(cfg, target, dest, ttl, transport, timeout, ident, seq_n, *, baseline):
        called_ttls.append(ttl)
        return next(seq)

    monkeypatch.setattr(diagnose, "_probe", fake_probe)
    list(diagnose._confirm_last(mk_cfg(), TARGET, DEST, hops, Transport.icmp, 2.0, 1)) # type: ignore
    assert 3 not in called_ttls

def test_confirm_last_empty_hops(monkeypatch):
    monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: True)
    result = list(diagnose._confirm_last(mk_cfg(), TARGET, DEST, [], Transport.icmp, 2.0, 1))
    r = next(e for e in result if e["type"] == "result")
    assert r["filtered_hop"] is None


# _hop_scan

def _run_hop_scan(monkeypatch, hops, probe_seq):
    seq = iter(probe_seq)
    monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: next(seq))
    return list(diagnose._hop_scan(mk_cfg(), TARGET, DEST, hops, Transport.icmp, 2.0, 1))


def test_hop_scan_all_pass_no_filtering(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    result = _run_hop_scan(monkeypatch, hops, [True] * 6)
    r = next(e for e in result if e["type"] == "result")
    assert r["filtered_hop"] is None

def test_hop_scan_identifies_filtering_hop(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    probe_seq = [True, True,
                 True, False,
                 True, False]
    result = _run_hop_scan(monkeypatch, hops, probe_seq)
    r = next(e for e in result if e["type"] == "result")
    assert r["filtered_hop"] == HOP_B

def test_hop_scan_emits_probe_per_hop(monkeypatch):
    hops = [HOP_A, HOP_B]
    result = _run_hop_scan(monkeypatch, hops, [True] * 4)
    probe_events = [e for e in result if e["type"] == "probe"]
    assert len(probe_events) == 2

def test_hop_scan_probe_events_have_correct_ttls(monkeypatch):
    hops = [HOP_A, HOP_B, HOP_C]
    result = _run_hop_scan(monkeypatch, hops, [True] * 6)
    ttls = [e["ttl"] for e in result if e["type"] == "probe"]
    assert ttls == [1, 2, 3]

def test_hop_scan_result_includes_counts(monkeypatch):
    hops = [HOP_A, HOP_B]
    result = _run_hop_scan(monkeypatch, hops, [True, True, True, False])
    r = next(e for e in result if e["type"] == "result")
    assert "counts" in r
    assert HOP_A in r["counts"]
    assert HOP_B in r["counts"]

def test_hop_scan_skips_none_hops_in_classification(monkeypatch):
    hops = [HOP_A, None, HOP_C]
    probe_seq = [True, True, True, True, True, True]
    result = _run_hop_scan(monkeypatch, hops, probe_seq)
    r = next(e for e in result if e["type"] == "result")
    assert None not in r["counts"]

def test_hop_scan_empty_hops(monkeypatch):
    monkeypatch.setattr(diagnose, "_probe", lambda *a, **kw: True)
    result = list(diagnose._hop_scan(mk_cfg(), TARGET, DEST, [], Transport.icmp, 2.0, 1))
    r = next(e for e in result if e["type"] == "result")
    assert r["filtered_hop"] is None
    assert r["counts"] == {}

def test_hop_scan_result_method_field(monkeypatch):
    result = _run_hop_scan(monkeypatch, [HOP_A], [True, True])
    r = next(e for e in result if e["type"] == "result")
    assert r["method"] == DiagnoseMethod.hop_scan.value

def test_hop_scan_probe_baseline_and_test_called_per_hop(monkeypatch):
    baseline_calls = []
    test_calls = []

    def fake_probe(*a, baseline, **kw):
        (baseline_calls if baseline else test_calls).append(a[3])
        return True

    monkeypatch.setattr(diagnose, "_probe", fake_probe)
    list(diagnose._hop_scan(mk_cfg(), TARGET, DEST, [HOP_A, HOP_B], Transport.icmp, 2.0, 1))
    assert baseline_calls == [1, 2]
    assert test_calls == [1, 2]
