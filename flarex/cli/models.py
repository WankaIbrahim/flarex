from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

class Transport(str, Enum):
    icmp = "icmp"
    udp = "udp"
    dns = "dns"
    tcp = "tcp"
    ssh = "ssh"
    http = "http"
    https = "https"
    
class EHName(str, Enum):
    hop = "hop"
    hbh = "hbh"
    dst = "dst"
    rt = "rt"
    frag = "frag"
    ah = "ah"
    esp = "esp"
    mobility = "mobility"
    
class DiagnoseMethod(str, Enum):
    confirm_last = "confirm-last"
    hop_scan = "hop-scan"

@dataclass
class Destination:
    raw: str
    kind: str
    value: str

@dataclass
class CommonConfig:
    hop_limit: Optional[int] = None
    src: Optional[str] = None
    flowlabel: Optional[int] = None
    payload_size: Optional[int] = None
    timeout: Optional[float] = None
    eh_auto_order: bool = False
    eh_chain: Optional[List[EHName]] = None
    transport: Optional[Transport] = None
    