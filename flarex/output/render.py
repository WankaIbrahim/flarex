from __future__ import annotations

from typing import Dict, Any

def render_ping_stream(event: Dict[str, Any]) -> None:
    et = event.get("type")
    
    if et == "start":
        dest = event.get("destination") or {}
        raw = dest.get("raw") or dest.get("value") or "?"
        resolved = dest.get("resolved") or "?"
        payload_size = event.get("payload_size")

        eh = event.get("eh_chain") 
        eh_str = f" [eh={'/'.join(eh)}]" if eh else None

        if eh_str is not None:
            print(f"FLAREX PING {raw}({resolved}), {payload_size} data bytes, eh_chain: {eh_str}")
        else:
            print(f"FLAREX PING {raw}({resolved}), {payload_size} data bytes")
            
    if et == "probe":
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
            
    if et == "summary":
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
        