from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

class Command(str, Enum):
    ping = "ping"
    trace = "trace"
    locate = "locate"

class Transport(str, Enum):
    icmp = "icmp"
    udp = "udp"
    dns = "dns"
    tcp = "tcp"
    ssh = "ssh"
    http = "http"
    https = "https"
    
class OnOff(str, Enum):
    on = "on"
    off = "off"
    
class EHName(str, Enum):
    hop = "hop"
    dst = "dst"
    rt = "rt"
    frag = "frag"
    ah = "ah"
    esp = "esp"
    hbh = "hbh"
    mobility = "mobility"
    
class LocateMethod(str, Enum):
    hop_scan = "hop-scan"
    binary_search = "binary-search"
    confirm_last = "confirm-last"
    
class LocateReport(str, Enum):
    summary = "summary"
    detailed = "detailed"
    json = "json"


@dataclass
class CommonConfig:
    hop_limit: Optional[int] = None
    src: Optional[str] = None
    flowlabel: Optional[int] = None
    payload_size: Optional[int] = None
    timeout: Optional[float] = None
    wait: Optional[float] = None
    quiet: bool = False
    verbose: bool = False
    json: bool = False
    eh_auto_order: bool = False
    eh_strict: bool = False

    eh_chain: Optional[List[EHName]] = None

    transport: Optional[Transport] = None
    