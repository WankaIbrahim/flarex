from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from flarex.core.models import EHName
import ipaddress

@dataclass(frozen=True)
class Destination:
    raw: str
    kind: str
    value: str

def parse_destination(dest: str) -> Destination:
    s = dest.strip()

    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return Destination(raw=dest, kind="ipv6", value=str(ipaddress.IPv6Address(inner)))

    try:
        return Destination(raw=dest, kind="ipv6", value=str(ipaddress.IPv6Address(s)))
    except ValueError:
        pass

    if not s:
        raise ValueError("Destination cannot be empty.")
    return Destination(raw=dest, kind="hostname", value=s)

def parse_eh_spec(spec: Optional[str]) -> Optional[List[EHName]]:
    if spec is None:
        return None
    s = spec.strip().lower()
    if s == "none":
        return []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    
    if not parts:
        raise ValueError("Invalid --eh value. Use 'none' or a comma-separated chain.")
    chain: List[EHName] = []
    for p in parts:
        try:
            chain.append(EHName(p))
        except ValueError:
            allowed = ", ".join(e.value for e in EHName)
            raise ValueError(f"Unknown EH name '{p}'. Allowed: {allowed}")
    return chain