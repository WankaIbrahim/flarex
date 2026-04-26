from __future__ import annotations

import ipaddress
from typing import List, Optional

from flarex.cli.models import EHName, Destination

def parse_destination(dest: str) -> Destination:
    """
    Parse destination string into a Destination Object.
    
    The destination may be:
    - A plain IPv6 literal
    - A bracketed IPv6 literal
    - A hostname
    
    Args:
        dest: A destination string provided by the user.
        
    Returns:
        A destination object with kind = "ipv6" or "hostname".
    
    Raises:
        ValueError: If the destination string is empty or invalid.
    """
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
    """
    Parse a list of IPv6 extension headers into a list of EHName values
    
    The input may be:
    - None (the user did not provide --eh)
    - "none" (the user requested for no extension headers)
    - A comma-seperated chain of extension headers
    
    Args:
        spec: A list of extension headers string provided by the user.
    
    Return:
        - None if the user did not specify --eh.
        - An empty list if the user specified "none".
        - A list of EHName values if a valid header chain was provided
    
    Raises:
        ValueError: If an unknown extension header name is provided.
    """
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
