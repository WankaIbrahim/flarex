from __future__ import annotations

import typer
from typing import Optional

from flarex.cli.validators import parse_destination, parse_eh_spec
from flarex.cli.models import OnOff, LocateMethod, LocateReport, CommonConfig, Transport
from flarex.net.ping import ping_stream
from flarex.net.traceroute import traceroute
from flarex.output.render import render_ping_stream, render_traceroute


app = typer.Typer(add_completion=False, no_args_is_help=True)

@app.callback()
def main(
    ctx: typer.Context,
    hop_limit: Optional[int] = typer.Option(None, "-H", "--hop-limit"),
    src: Optional[str] = typer.Option(None, "-S", "--src"),
    flowlabel: Optional[int] = typer.Option(None, "--flowlabel"),
    payload_size: Optional[int] = typer.Option(None, "--payload-size"),
    timeout: Optional[float] = typer.Option(None, "--timeout"),
    wait: Optional[float] = typer.Option(None, "--wait"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
    json: bool = typer.Option(False, "--json"),
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
    wait=wait,
    quiet=quiet,
    verbose=verbose,
    json=json,
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
    pmtud: Optional[OnOff] = typer.Option(None, "--pmtud"),
    pmtu_size: Optional[int] = typer.Option(None, "--pmtu-size"),
    identify_drop: Optional[OnOff] = typer.Option(None, "--identify-drop"),
):
    cfg: CommonConfig = ctx.obj
    dest = parse_destination(destination)

    for event in ping_stream(
        cfg,
        dest,
        count=count,
        interval=interval,
        per_probe_timeout=per_probe_timeout,
        pmtud=pmtud,
        pmtu_size=pmtu_size,
        identify_drop=identify_drop):
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
    identify_drop: Optional[OnOff] = typer.Option(None, "--identify-drop"),
):
    cfg = ctx.obj
    dest = parse_destination(destination)
    try:
        for event in traceroute(
            cfg,
            dest,
            first_hop=first_hop,
            max_hop=max_hop,
            probes=probes,
            wait_probe=wait_probe,
            loop_threshold=loop_threshold,
            no_dns=no_dns,
            identify_drop=identify_drop,):
            render_traceroute(event)
    except KeyboardInterrupt:
        return



@app.command()
def locate(
    ctx: typer.Context,
    destination: str = typer.Argument(...),
    method: Optional[LocateMethod] = typer.Option(None, "--method"),
    baseline: Optional[str] = typer.Option(None, "--baseline"),
    max_steps: Optional[int] = typer.Option(None, "--max-steps"),
    report: Optional[LocateReport] = typer.Option(None, "--report"),
):
    cfg = ctx.obj
    dest = parse_destination(destination)

    #LOCATE Logic
    #render_result(result, cfg)

    
