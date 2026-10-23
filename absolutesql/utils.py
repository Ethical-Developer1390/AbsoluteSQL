"""
AbsoluteSQL — Utilities
Logging, URL parsing, colour helpers, misc.
"""

import os
import re
import time
import random
import logging
import hashlib
import urllib.parse
from datetime import datetime
from typing import Optional, Dict, List, Tuple

from rich.console import Console
from rich.text import Text

from .config import LOGS_DIR, USER_AGENTS, THEME

console = Console()

# ── Logging setup ─────────────────────────────────────────────────────────────
def get_logger(name: str = "absolutesql") -> logging.Logger:
    log_file = os.path.join(LOGS_DIR, f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger

# Global logger
log = get_logger()

# ── Console helpers ───────────────────────────────────────────────────────────
def print_info(msg: str) -> None:
    console.print(f"  [bold bright_cyan]ℹ[/bold bright_cyan]  {msg}")

def print_success(msg: str) -> None:
    console.print(f"  [bold bright_green]✔[/bold bright_green]  {msg}")

def print_warning(msg: str) -> None:
    console.print(f"  [bold bright_yellow]⚠[/bold bright_yellow]  {msg}")

def print_error(msg: str) -> None:
    console.print(f"  [bold bright_red]✘[/bold bright_red]  {msg}")

def print_vuln(msg: str) -> None:
    console.print(f"  [bold red on default]💉 VULNERABLE[/bold red on default]  [bright_white]{msg}[/bright_white]")

def print_dim(msg: str) -> None:
    console.print(f"  [dim]{msg}[/dim]")

def cprint(msg: str, style: str = "") -> None:
    if style:
        console.print(f"[{style}]{msg}[/{style}]")
    else:
        console.print(msg)

# ── URL helpers ───────────────────────────────────────────────────────────────
def parse_url(url: str) -> urllib.parse.ParseResult:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urllib.parse.urlparse(url)

def extract_params(url: str) -> Dict[str, str]:
    """Extract GET parameters from URL as {name: value}."""
    parsed = parse_url(url)
    return dict(urllib.parse.parse_qsl(parsed.query))

def inject_param(url: str, param: str, payload: str) -> str:
    """Replace a single parameter's value with the payload, preserving others."""
    parsed  = parse_url(url)
    params  = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = payload
    new_query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))

def strip_params(url: str) -> str:
    """Return URL without query string."""
    parsed = parse_url(url)
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""
    ))

def base_url(url: str) -> str:
    parsed = parse_url(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

# ── String helpers ────────────────────────────────────────────────────────────
def similarity(a: str, b: str) -> float:
    """Rough similarity ratio between two strings (0–1)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    longer = max(len(a), len(b))
    # Levenshtein approximation using common subsequence ratio
    matches = sum(1 for ca, cb in zip(a, b) if ca == cb)
    return matches / longer

def response_diff(baseline: str, tested: str) -> float:
    """Measure structural difference between two responses (0=identical, 1=totally different)."""
    if baseline == tested:
        return 0.0
    return 1.0 - similarity(baseline, tested)

def strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    return re.sub(r"<[^>]+>", "", text)

def truncate(s: str, n: int = 80, ellipsis: str = "…") -> str:
    s = str(s)
    return s if len(s) <= n else s[:n - len(ellipsis)] + ellipsis

def clean_extracted(raw: str) -> str:
    """Strip control characters from extracted data."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw).strip()

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

# ── Timing helpers ────────────────────────────────────────────────────────────
def timed_call(fn, *args, **kwargs) -> Tuple:
    """Call fn(*args, **kwargs), return (result, elapsed_seconds)."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - t0

# ── Param discovery from raw HTML ─────────────────────────────────────────────
def extract_form_params(html: str) -> List[Dict]:
    """
    Parse <form> elements from HTML and return list of:
      {"action": str, "method": str, "params": {name: value}}
    """
    forms = []
    for form_match in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE):
        form_html = form_match.group(0)
        action = re.search(r'action=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
        method = re.search(r'method=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
        inputs = re.findall(
            r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*(?:value=["\']?([^"\'>\s]*)["\']?)?',
            form_html, re.IGNORECASE
        )
        params = {name: value for name, value in inputs}
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "params": params,
        })
    return forms

def make_report_filename(url: str, ext: str) -> str:
    host = parse_url(url).netloc.replace(".", "_").replace(":", "_")
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(LOGS_DIR if ext == "log" else "reports", f"absolutesql_{host}_{ts}.{ext}")

def fmt_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s"

def bold_color(text: str, color: str) -> Text:
    t = Text(text)
    t.stylize(f"bold {color}")
    return t
