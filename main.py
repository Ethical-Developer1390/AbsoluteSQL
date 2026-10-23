#!/usr/bin/env python3
"""
AbsoluteSQL — Main Entry Point
Stunning CLI for automated SQL injection testing.
"""

import sys
import os
import time
import argparse
import threading
from typing import Optional, List, Dict
from urllib.parse import urlparse

# ── Rich imports ──────────────────────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
    MofNCompleteColumn,
)
from rich import box
from rich.markup import escape
from rich.padding import Padding
from rich.style import Style
from rich.tree import Tree
from rich.prompt import Confirm

# ── AbsoluteSQL imports ───────────────────────────────────────────────────────
from absolutesql.config import VERSION, CODENAME, THEME, INJ_TYPE_LABELS
from absolutesql.http_client import HTTPClient
from absolutesql.detector import WAFDetector, DBMSDetector
from absolutesql.scanner import VulnerabilityScanner, ParameterExtractor, ScanResult, Vulnerability
from absolutesql.injector import Injector
from absolutesql.extractor import DataExtractor
from absolutesql.reporter import Reporter
from absolutesql.utils import (
    normalize_url, extract_params, extract_form_params,
    parse_url, base_url, fmt_time, print_info, print_success,
    print_warning, print_error, print_vuln,
)

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# ASCII Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER_ART = r"""
  █████  ██████  ███████  ██████  ██      ██    ██ ████████ ███████  ██████  ██     
 ██   ██ ██   ██ ██      ██    ██ ██      ██    ██    ██    ██      ██    ██ ██     
 ███████ ██████  ███████ ██    ██ ██      ██    ██    ██    █████   ██    ██ ██     
 ██   ██ ██   ██      ██ ██ ▄▄ ██ ██      ██    ██    ██    ██      ██ ▄▄ ██ ██     
 ██   ██ ██████  ███████  ██████  ███████  ██████     ██    ███████  ██████  ███████
"""

def show_banner() -> None:
    """Render the AbsoluteSQL banner with metadata strip."""
    lines = BANNER_ART.strip("\n").splitlines()

    styled = Text()
    colors = ["bright_red", "red", "dark_red", "red", "bright_red"]
    for i, line in enumerate(lines):
        styled.append(line + "\n", style=f"bold {colors[i % len(colors)]}")

    meta = (
        f"[dim]v{VERSION}[/dim]  [dim]·[/dim]  "
        f"[dim]{CODENAME}[/dim]  [dim]·[/dim]  "
        f"[dim]SQL Injection Testing Platform[/dim]"
    )

    console.print()
    console.print(Align(styled, align="center"))
    console.print(Align(meta,   align="center"))
    console.print()
    console.print(Rule(style="bright_red dim"))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "absolutesql",
        description = f"AbsoluteSQL v{VERSION} — SQL Injection Testing Platform",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
examples:
  Scan all GET params:
    python main.py -u "http://target.com/page.php?id=1"

  Scan specific parameter:
    python main.py -u "http://target.com/page.php?id=1&name=test" -p id

  POST form scan:
    python main.py -u "http://target.com/login.php" --method POST --data "user=admin&pass=x"

  Full dump with HTML report:
    python main.py -u "http://target.com/page.php?id=1" --dump --report html

  Custom headers + proxy:
    python main.py -u "http://target.com/vuln.php?id=1" \\
        -H "Authorization: Bearer TOKEN" \\
        --proxy http://127.0.0.1:8080
        """,
    )

    # Target
    tgt = p.add_argument_group("TARGET")
    tgt.add_argument("-u", "--url",    required=True, help="Target URL (include parameters)")
    tgt.add_argument("-p", "--param",  help="Specific parameter to test (default: all)")
    tgt.add_argument("--method",       default="GET", choices=["GET", "POST"], help="HTTP method")
    tgt.add_argument("--data",         help="POST body: 'param1=val1&param2=val2'")
    tgt.add_argument("--dbms",         choices=["MySQL","PostgreSQL","Microsoft SQL Server",
                                                  "Oracle","SQLite","MariaDB"],
                     help="Force DBMS (skip fingerprinting)")

    # Request
    req = p.add_argument_group("REQUEST")
    req.add_argument("--timeout",    type=int,   default=15,    help="Request timeout seconds (default: 15)")
    req.add_argument("--delay",      type=float, default=0.0,   help="Delay between requests in seconds")
    req.add_argument("--retries",    type=int,   default=3,     help="Retry count on failure (default: 3)")
    req.add_argument("--threads",    type=int,   default=1,     help="Threads for param scanning (default: 1)")
    req.add_argument("--proxy",      help="Proxy URL: http://host:port")
    req.add_argument("--cookies",    help="Cookies: 'name=val; name2=val2'")
    req.add_argument("-H", "--header", action="append", dest="headers", metavar="HEADER",
                     help="Extra header (can repeat): 'Name: Value'")
    req.add_argument("--random-agent", action="store_true", help="Randomise User-Agent per request")
    req.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")

    # Detection
    det = p.add_argument_group("DETECTION")
    det.add_argument("--level",    type=int, default=2, choices=[1,2,3],
                     help="Test depth — 1=fast/error, 2=+boolean+union, 3=+time (default: 2)")
    det.add_argument("--time-delay", type=int, default=5,
                     help="Sleep delay for time-based payloads (default: 5)")
    det.add_argument("--no-waf",   action="store_true", help="Skip WAF detection")

    # Extraction
    ext = p.add_argument_group("EXTRACTION")
    ext.add_argument("--dump",      action="store_true", help="Dump database contents after detection")
    ext.add_argument("--dbs",       action="store_true", help="Enumerate databases only")
    ext.add_argument("--tables",    action="store_true", help="Enumerate tables")
    ext.add_argument("--columns",   help="Dump columns for TABLE (requires --table-name)")
    ext.add_argument("--table-name",help="Table name for --columns or targeted --dump")
    ext.add_argument("--db-name",   help="Database name for targeted extraction")
    ext.add_argument("--row-limit", type=int, default=50, help="Max rows to dump per table (default: 50)")

    # Output
    out = p.add_argument_group("OUTPUT")
    out.add_argument("--report",    choices=["html","json","both"], default="both",
                     help="Report format (default: both)")
    out.add_argument("--output",    help="Output file base path (no extension)")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("-q", "--quiet",   action="store_true", help="Minimal output")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Panels / UI Components
# ─────────────────────────────────────────────────────────────────────────────

def render_target_panel(url: str, method: str, params: List[str]) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bright_white")

    parsed = parse_url(url)
    t.add_row("URL",     f"[bright_cyan]{escape(url)}[/bright_cyan]")
    t.add_row("Host",    f"[white]{parsed.netloc}[/white]")
    t.add_row("Path",    f"[white]{parsed.path or '/'}[/white]")
    t.add_row("Method",  f"[yellow]{method}[/yellow]")
    t.add_row("Params",  f"[bright_blue]{', '.join(params) or 'none'}[/bright_blue]")

    return Panel(
        t,
        title="[bold bright_red]◈ TARGET[/bold bright_red]",
        border_style="bright_red dim",
        padding=(1, 2),
    )


def render_vuln_table(vulns: List[Vulnerability]) -> Table:
    t = Table(
        box=box.SIMPLE_HEAD,
        border_style="bright_black",
        header_style="bold dim",
        show_lines=False,
        padding=(0, 1),
    )
    t.add_column("PARAM",      style="bold bright_cyan",  no_wrap=True)
    t.add_column("TYPE",       style="bold red",          no_wrap=True)
    t.add_column("DBMS",       style="cyan",              no_wrap=True)
    t.add_column("METHOD",     style="yellow",            no_wrap=True)
    t.add_column("CONFIDENCE", justify="right")
    t.add_column("EVIDENCE",   style="dim",               max_width=60)

    for v in vulns:
        conf = int(v.confidence * 100)
        conf_color = "bright_green" if conf >= 90 else ("yellow" if conf >= 70 else "red")
        t.add_row(
            v.param,
            v.label(),
            v.dbms or "Unknown",
            v.method,
            f"[{conf_color}]{conf}%[/{conf_color}]",
            v.evidence[:80] if v.evidence else "—",
        )
    return t


def render_db_tree(extraction) -> Tree:
    root = Tree(
        f"[bold bright_red]◈ DATABASES[/bold bright_red]  "
        f"[dim]({len(extraction.databases)} found)[/dim]"
    )

    for db in extraction.databases:
        db_node = root.add(
            f"[bold cyan]🗄  {db.name}[/bold cyan]  "
            f"[dim]({len(db.tables)} tables)[/dim]"
        )
        for tbl in db.tables:
            rc = f"  [dim yellow]{tbl.row_count} rows[/dim yellow]" if tbl.row_count else ""
            tbl_node = db_node.add(
                f"[bright_white]⊞  {tbl.name}[/bright_white]{rc}"
            )
            for col in tbl.columns:
                tbl_node.add(f"[dim]○  {col}[/dim]")
    return root


def render_summary_panel(result: ScanResult, elapsed: float) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bright_white")

    status = (
        "[bold bright_green]✔  CLEAN[/bold bright_green]" if not result.vulnerable
        else f"[bold bright_red]💉 VULNERABLE ({len(result.vulns)} POINT{'S' if len(result.vulns) != 1 else ''})[/bold bright_red]"
    )

    t.add_row("Status",         status)
    t.add_row("WAF",            f"[yellow]{result.waf}[/yellow]" if result.waf else "[dim]None detected[/dim]")
    t.add_row("DBMS",           f"[cyan]{result.dbms}[/cyan]" if result.dbms else "[dim]Unknown[/dim]")
    t.add_row("Params Tested",  str(len(result.params_tested)))
    t.add_row("Requests Sent",  str(result.requests_sent))
    t.add_row("Elapsed",        fmt_time(elapsed))

    return Panel(
        t,
        title="[bold bright_red]◈ SCAN SUMMARY[/bold bright_red]",
        border_style="bright_red dim",
        padding=(1, 2),
    )


def render_extraction_meta(ext) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bright_green")

    rows = [
        ("DBMS",         ext.dbms or "—"),
        ("Version",      ext.version or "—"),
        ("Current User", ext.current_user or "—"),
        ("Current DB",   ext.current_db or "—"),
        ("Hostname",     ext.hostname or "—"),
    ]
    for label, val in rows:
        t.add_row(label, val)

    return Panel(
        t,
        title="[bold bright_red]◈ DATABASE INFO[/bold bright_red]",
        border_style="bright_red dim",
        padding=(1, 2),
    )


def render_data_table(tbl) -> Table:
    if not tbl.columns:
        return Table()

    t = Table(
        title=f"[bold]{tbl.db}[/bold].[bright_red]{tbl.name}[/bright_red]"
              + (f"  [dim]({tbl.row_count} total rows)[/dim]" if tbl.row_count else ""),
        box=box.SIMPLE_HEAD,
        border_style="bright_black",
        header_style="bold bright_cyan",
        show_lines=True,
        padding=(0, 1),
        row_styles=["", "dim"],
    )
    for col in tbl.columns:
        t.add_column(col, max_width=40, overflow="fold")
    for row in tbl.rows:
        t.add_row(*[str(row.get(c, "")) for c in tbl.columns])
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Core scan orchestration
# ─────────────────────────────────────────────────────────────────────────────

def build_client(args) -> HTTPClient:
    extra_headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    return HTTPClient(
        timeout    = args.timeout,
        delay      = args.delay,
        retries    = args.retries,
        proxy      = args.proxy,
        cookies    = args.cookies,
        headers    = extra_headers or None,
        random_ua  = args.random_agent,
        verify_ssl = not args.no_ssl_verify,
    )


def parse_post_data(raw: str) -> Dict[str, str]:
    """Parse 'key=val&key2=val2' into dict."""
    from urllib.parse import parse_qsl
    return dict(parse_qsl(raw))


def run_scan(args, client: HTTPClient) -> ScanResult:
    url    = normalize_url(args.url)
    method = args.method.upper()

    # Collect params to test
    if method == "GET":
        all_params = extract_params(url)
    else:
        all_params = parse_post_data(args.data or "") if args.data else {}

    if args.param:
        if args.param not in all_params:
            all_params[args.param] = ""
        test_params = {args.param: all_params[args.param]}
    else:
        test_params = all_params

    result = ScanResult(
        url    = url,
        method = method,
        params_tested = list(test_params.keys()),
    )

    t_start = time.perf_counter()

    # ── WAF detection ──────────────────────────────────────────────────────
    if not args.no_waf:
        with console.status("[bright_yellow]Probing defenses...[/bright_yellow]", spinner="dots"):
            waf_d = WAFDetector(client)
            result.waf = waf_d.detect(url, method)

        if result.waf:
            console.print(f"  [bold yellow]⚠  WAF detected:[/bold yellow] [yellow]{result.waf}[/yellow]")
        else:
            console.print("  [dim]○  No WAF detected[/dim]")

    # ── DBMS fingerprint ───────────────────────────────────────────────────
    dbms = args.dbms
    if not dbms and test_params:
        first_param  = next(iter(test_params))
        first_value  = test_params[first_param]
        with console.status("[bright_cyan]Fingerprinting DBMS...[/bright_cyan]", spinner="dots"):
            dbms_d = DBMSDetector(client)
            dbms   = dbms_d.probe(url, first_param, first_value, method)

    if dbms:
        result.dbms = dbms
        console.print(f"  [bold cyan]◎  DBMS identified:[/bold cyan] [cyan]{dbms}[/cyan]")
    else:
        console.print("  [dim]○  DBMS not fingerprinted — using generic payloads[/dim]")

    console.print()

    # ── Parameter scanning ─────────────────────────────────────────────────
    scanner = VulnerabilityScanner(client)

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bright_red"),
        TextColumn("[bright_white]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            "[bold]Scanning parameters[/bold]",
            total=len(test_params),
        )

        for param, value in test_params.items():
            progress.update(task, description=f"[bold]Testing [bright_cyan]{param}[/bright_cyan]")

            # Level 1: error only
            # Level 2: error + union + boolean
            # Level 3: + time-based
            vulns = []

            # Error-based (always)
            v = scanner.scan_error_based(url, param, value, method)
            if v:
                v.dbms = v.dbms or dbms
                vulns.append(v)

            if args.level >= 2 and not vulns:
                # Union
                v = scanner.scan_union_based(url, param, value, method)
                if v:
                    v.dbms = v.dbms or dbms
                    vulns.append(v)

                # Boolean
                if not vulns:
                    v = scanner.scan_boolean_based(url, param, value, method)
                    if v:
                        v.dbms = v.dbms or dbms
                        vulns.append(v)

            if args.level >= 3 and not vulns:
                v = scanner.scan_time_based(
                    url, param, value, method,
                    dbms=dbms or "generic",
                    delay=args.time_delay,
                )
                if v:
                    v.dbms = v.dbms or dbms
                    vulns.append(v)

            for v in vulns:
                result.vulns.append(v)

            progress.advance(task)

    result.requests_sent = client.request_count
    result.elapsed       = time.perf_counter() - t_start

    return result


def run_extraction(args, client: HTTPClient, vuln: Vulnerability, dbms: str):
    """Execute the extraction pipeline on a confirmed vulnerability."""
    injector   = Injector(client, vuln, dbms)
    extractor  = DataExtractor(injector, dbms)

    target_dbs    = [args.db_name]    if args.db_name    else None
    target_tables = [args.table_name] if args.table_name else None

    dump_rows = args.dump
    if args.dbs:
        dump_rows = False
    if args.tables:
        dump_rows = False

    with Progress(
        SpinnerColumn(spinner_name="bouncingBar", style="bright_red"),
        TextColumn("[bright_white]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[bold]Extracting data[/bold]", total=None)

        progress.update(task, description="[bold]Reading server metadata...[/bold]")
        ext = extractor.run(
            target_dbs    = target_dbs,
            target_tables = target_tables,
            dump_rows     = dump_rows,
            row_limit     = args.row_limit,
        )

    return ext


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.quiet:
        show_banner()

    # ── Validate URL ──────────────────────────────────────────────────────────
    url = normalize_url(args.url)
    try:
        parsed = urlparse(url)
        assert parsed.netloc
    except Exception:
        print_error(f"Invalid URL: {args.url}")
        return 1

    # ── Parse POST data ────────────────────────────────────────────────────────
    post_params = {}
    if args.method == "POST" and args.data:
        post_params = parse_post_data(args.data)

    params = list(extract_params(url).keys()) if args.method == "GET" else list(post_params.keys())
    if args.param and args.param not in params:
        params = [args.param]

    if not params:
        print_warning("No parameters detected. Specify -p or include params in the URL.")
        return 1

    # ── Show target panel ──────────────────────────────────────────────────────
    if not args.quiet:
        console.print(render_target_panel(url, args.method, params))
        console.print()

    # ── Build client ──────────────────────────────────────────────────────────
    client = build_client(args)

    # ── Run scan ──────────────────────────────────────────────────────────────
    if not args.quiet:
        console.print(Rule("[bold bright_red]SCANNING[/bold bright_red]", style="bright_red dim"))
        console.print()

    try:
        result = run_scan(args, client)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠  Scan interrupted by user[/bold yellow]")
        return 130

    # ── Display results ────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_red]RESULTS[/bold bright_red]", style="bright_red dim"))
    console.print()

    if result.vulnerable:
        for v in result.vulns:
            console.print(
                f"  [bold bright_red]💉 INJECTABLE[/bold bright_red]  "
                f"[bright_cyan]{v.param}[/bright_cyan]  "
                f"[dim]→[/dim]  [red]{v.label()}[/red]"
                + (f"  [dim]({v.dbms})[/dim]" if v.dbms else "")
            )
        console.print()
        console.print(render_vuln_table(result.vulns))
    else:
        console.print("  [bold bright_green]✔  No SQL injection vulnerabilities detected[/bold bright_green]")

    console.print()
    console.print(render_summary_panel(result, result.elapsed))

    # ── Extraction phase ───────────────────────────────────────────────────────
    extraction = None
    if result.vulnerable and (args.dump or args.dbs or args.tables or args.columns):
        best = result.best_vuln()
        dbms = result.dbms or best.dbms or "MySQL"

        console.print()
        console.print(Rule("[bold bright_red]EXTRACTION[/bold bright_red]", style="bright_red dim"))
        console.print()
        console.print(
            f"  [bold]Exploiting[/bold]  [bright_cyan]{best.param}[/bright_cyan]  "
            f"via  [red]{best.label()}[/red]  [dim]({dbms})[/dim]"
        )
        console.print()

        try:
            extraction = run_extraction(args, client, best, dbms)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠  Extraction interrupted[/bold yellow]")

        if extraction:
            console.print()
            console.print(render_extraction_meta(extraction))
            console.print()

            if extraction.databases:
                console.print(render_db_tree(extraction))
                console.print()

            if args.dump:
                for db in extraction.databases:
                    for tbl in db.tables:
                        if tbl.rows:
                            console.print(render_data_table(tbl))
                            console.print()

    # ── Generate reports ───────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold bright_red]REPORTS[/bold bright_red]", style="bright_red dim"))
    console.print()

    reporter = Reporter(result, extraction)

    with console.status("[bright_yellow]Writing reports...[/bright_yellow]", spinner="dots"):
        saved = reporter.save(fmt=args.report, base_path=args.output)

    for path in saved:
        ext_label = os.path.splitext(path)[1].lstrip(".")
        icon = "📄" if ext_label == "json" else "🌐"
        console.print(f"  {icon}  [dim]{ext_label.upper()}:[/dim]  [underline bright_cyan]{path}[/underline bright_cyan]")

    console.print()
    console.print(
        Panel(
            Align(
                f"[dim]Scan complete —[/dim] [bold bright_white]{len(result.vulns)}[/bold bright_white] "
                f"[dim]vuln{'s' if len(result.vulns) != 1 else ''} ·[/dim] "
                f"[bold bright_white]{result.requests_sent}[/bold bright_white] "
                f"[dim]requests ·[/dim] "
                f"[bold bright_white]{fmt_time(result.elapsed)}[/bold bright_white]",
                align="center",
            ),
            border_style="bright_red dim",
            padding=(0, 2),
        )
    )
    console.print()

    return 0 if not result.vulnerable else 1


if __name__ == "__main__":
    sys.exit(main())
