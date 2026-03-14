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

        eh = event.get("eh_chain") 
        eh_str = f" [eh={'/'.join(eh)}]" if eh else None

        out_str = f"FLAREX PING {raw}({resolved}), {payload_size} data bytes"
        
        if eh_str is not None:
            out_str += f", eh_chain: {eh_str}"
        
        print(out_str)
            
    elif et == "probe":
        status = event.get("status")
        size = event.get("reply_size")
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        seq = event.get("seq")
        time = event.get("rtt_ms")
        
        if status is not None:
            print(f"{size} bytes from {raw} ({resolved}): seq={seq} time={time} ms")
        else:
            print(f"None")
            
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
        eh_str = f" [eh={'/'.join(eh)}]" if eh else None

        loop_threshold = event.get("loop_threshold")
        out_str = f"FLAREX TRACEROUTE to {raw}({resolved}), {max_hops} hops max, {payload_size} bytes packets"

        if loop_threshold is not None:
            out_str += f", loop threshold: {loop_threshold}"

        if eh_str is not None:
            out_str += f", eh_chain: {eh_str}"
        
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
    