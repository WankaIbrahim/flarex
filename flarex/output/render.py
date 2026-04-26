from __future__ import annotations

from typing import Dict, Any

def render_ping_stream(event: Dict[str, Any]) -> None:
    """
    Render a single ping stream event.

    Consumes the event dictionaries emitted by ``ping_stream`` and prints
    human-readable output for the start banner, each probe result, and the
    final summary statistics.

    Args:
        event: Ping stream event dictionary. Expected ``type`` values are
            ``start``, ``probe``, and ``summary``.
    """
    et = event.get("type")
    
    if et == "start":
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        payload_size = event.get("payload_size")
        pmtud = event.get("pmtud")
        pmtu_size = event.get("pmtu_size")

        eh = event.get("eh_chain")

        out_str = f"FLAREX PING {raw}({resolved}), {payload_size} data bytes"

        if pmtud:
            out_str += f", pmtud=on (probe size={pmtu_size} bytes)"

        if eh:
            out_str += f", eh_chain=[{'/'.join(eh)}]"

        print(out_str)
            
    elif et == "probe":
        status = event.get("status")
        size = event.get("reply_size")
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        seq = event.get("seq")
        rtt = event.get("rtt_ms")

        if status == "timeout":
            print(f"Request timeout: {seq}")
        elif status == "icmp_packet_too_big":
            pmtu = event.get("pmtu")
            router = event.get("reply_src") or "?"
            print(f"Packet Too Big from {router}: seq={seq} mtu={pmtu}")
        else:
            print(f"{size} bytes from {raw} ({resolved}): seq={seq} time={rtt:.3f} ms")
            
    elif et == "summary":
        sent = event.get("sent")
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        received = event.get("received")
        pkt_loss = event.get("pkt_loss")
        total_time = event.get("total_time")
        min = event.get("min_ms")
        avg = event.get("avg_ms")
        max = event.get("max_ms")
        
        print(f"\n--- {raw} ping statistics ---")
        print(f"{sent} packets transmitted, {received} received, {pkt_loss}% packet loss, time {total_time}ms")
        print(f"rtt min/avg/max = {min}/{avg}/{max} ms")

def render_traceroute(event: Dict[str, Any]) -> None:
    et = event.get("type")
    
    if et == "start":
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        max_hops = event.get("max_hops")
        payload_size = event.get("payload_size")

        eh = event.get("eh_chain")

        loop_threshold = event.get("loop_threshold")
        out_str = f"FLAREX TRACEROUTE to {raw}({resolved}), {max_hops} hops max, {payload_size} bytes packets"

        if loop_threshold is not None:
            out_str += f", loop threshold: {loop_threshold}"

        if eh:
            out_str += f", eh_chain=[{'/'.join(eh)}]"

        print(out_str)
        
    elif et == "hop":
        hop = event.get("hop")
        source = event.get("source") or {}
        raw = source.get("raw")
        resolved = source.get("resolved")
        rtts = event.get("rtts") or []

        timings = " ".join(
            f"{rtt:.3f} ms" if isinstance(rtt, (int, float)) else "*"
            for rtt in rtts
        ) or "* * *"

        if raw is None:
            print(f"{hop}  {timings}")
            return

        label = f"{raw} ({resolved})" if resolved and resolved != raw else raw
        print(f"{hop}  {label}  {timings}")

    elif et == "done":
        reached = event.get("reached", False)
        loop_detected = event.get("loop_detected", False)
        if reached:
            print("Traceroute complete.")
        elif loop_detected:
            print("Traceroute complete (routing loop detected).")
        else:
            print("Traceroute complete (max hops reached).")

def render_diagnose(event: Dict[str, Any]) -> None:
    """
    Render a single diagnose stream event.

    Consumes the event dictionaries emitted by ``diagnose`` and prints
    human-readable output for each phase: the start banner, ping results,
    traceroute hops, per-TTL probe outcomes, and the final filtering result.

    Args:
        event: Diagnose stream event dictionary. Expected ``type`` values are
            ``start``, ``ping_result``, ``trace_hop``, ``probe``, ``result``,
            and ``done``.
    """
    et = event.get("type")

    if et == "start":
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        method = event.get("method") or "?"
        transport = event.get("transport") or "?"
        print(f"FLAREX DIAGNOSE {raw}({resolved}), method={method}, transport={transport}")

    elif et == "ping_result":
        render_ping_stream(event.get("event") or {})

    elif et == "trace_hop":
        render_traceroute({**event, "type": "hop"})

    elif et == "probe":
        ttl = event.get("ttl")
        hop = event.get("hop") or "*"
        baseline = "ok" if event.get("baseline") else "drop"
        test = "ok" if event.get("test") else "drop"
        tag = " [confirm]" if event.get("confirmation") else ""
        print(f"  TTL {ttl:>2}  {hop}  baseline={baseline}  test={test}{tag}")

    elif et == "result":
        filtering_hop = event.get("filtered_hop")
        reason = event.get("reason")
        if reason == "no_loss":
            print("\nResult: no packet loss detected.")
        elif filtering_hop:
            method = event.get("method") or "?"
            print(f"\nResult [{method}]: filtering hop identified - {filtering_hop}")
        else:
            print("\nResult: no filtering hop identified.")

    elif et == "done":
        print("Diagnose complete.")
