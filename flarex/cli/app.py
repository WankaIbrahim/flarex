from __future__ import annotations

import typer
from typing import Optional

from flarex.cli.validators import parse_destination, parse_eh_spec
from flarex.cli.models import DiagnoseMethod, CommonConfig, Transport
from flarex.net.ping import ping as _ping
from flarex.net.traceroute import traceroute
from flarex.net.diagnose import diagnose as _diagnose
from flarex.output.render import render_ping_stream, render_traceroute, render_diagnose


app = typer.Typer(add_completion=False, no_args_is_help=True, pretty_exceptions_enable=False)

@app.callback()
def main(
    ctx: typer.Context,
    hop_limit: Optional[int] = typer.Option(None, "-H", "--hop-limit"),
    src: Optional[str] = typer.Option(None, "-S", "--src"),
    flowlabel: Optional[int] = typer.Option(None, "--flowlabel"),
    payload_size: Optional[int] = typer.Option(None, "--payload-size"),
    timeout: Optional[float] = typer.Option(None, "--timeout"),
    eh: Optional[str] = typer.Option(None, "--eh", help="EH chain like 'hop,dst' or 'none'"),
    eh_auto_order: bool = typer.Option(False, "--eh-auto-order"),
    eh_strict: bool = typer.Option(False, "--eh-strict"),
    transport: Optional[Transport] = typer.Option(None, "-T", "--transport"),
):
    

    cfg = CommonConfig(
        hop_limit=hop_limit,
        src=src,
        flowlabel=flowlabel,
        payload_size=payload_size,
        timeout=timeout,
        eh_auto_order=eh_auto_order,
        eh_strict=eh_strict,
        eh_chain=parse_eh_spec(eh),
        transport=transport,
    )
    ctx.obj = cfg


@app.command()
def ping(
    ctx: typer.Context,
    destination: str = typer.Argument(...),
    count: Optional[int] = typer.Option(None, "-c", "--count"),
    interval: Optional[float] = typer.Option(None, "-i", "--interval"),
    per_probe_timeout: Optional[float] = typer.Option(None, "-W", "--per-probe-timeout"),
    pmtud: bool = typer.Option(False, "--pmtud/--no-pmtud"),
    pmtu_size: Optional[int] = typer.Option(None, "--pmtu-size"),
):
    cfg: CommonConfig = ctx.obj
    dest = parse_destination(destination)

    for event in _ping(
        cfg,
        dest,
        count=count,
        interval=interval,
        per_probe_timeout=per_probe_timeout,
        pmtud=pmtud,
        pmtu_size=pmtu_size):
        render_ping_stream(event)

@app.command()
def trace(
    ctx: typer.Context,
    destination: str = typer.Argument(...),
    first_hop: Optional[int] = typer.Option(None, "-f", "--first-hop"),
    max_hop: Optional[int] = typer.Option(None, "-m", "--max-hop"),
    probes: Optional[int] = typer.Option(None, "-p", "--probes"),
    wait_probe: Optional[float] = typer.Option(None, "-w", "--wait-probe"),
    loop_threshold: Optional[int] = typer.Option(None, "-l", "--loop-threshold"),
    no_dns: bool = typer.Option(False, "-n", "--no-dns"),
):
    cfg = ctx.obj
    dest = parse_destination(destination)
    
    for event in traceroute(
        cfg,
        dest,
        first_hop=first_hop,
        max_hop=max_hop,
        probes=probes,
        wait_probe=wait_probe,
        loop_threshold=loop_threshold,
        no_dns=no_dns):
        render_traceroute(event)

@app.command()
def diagnose(
    ctx: typer.Context,
    destination: str = typer.Argument(...),
    method: Optional[DiagnoseMethod] = typer.Option(None, "--method"),
    max_steps: Optional[int] = typer.Option(None, "--max-steps"),
):
    cfg = ctx.obj
    dest = parse_destination(destination)

    for event in _diagnose(cfg, dest, method=method, max_steps=max_steps):
        render_diagnose(event)
