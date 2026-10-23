"""
AbsoluteSQL — Configuration Module
Settings, constants, and defaults.
"""

import os

VERSION   = "1.0.0"
CODENAME  = "SpudBlood"
AUTHOR    = "AbsoluteSQL"

# ── Network ───────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT   = 15
DEFAULT_THREADS   = 5
DEFAULT_DELAY     = 0.0
DEFAULT_RETRIES   = 3
TIME_THRESHOLD    = 5        # seconds — time-based detection
TIME_DELAY        = 5        # sleep delay injected into payloads

# ── Scanning ──────────────────────────────────────────────────────────────────
UNION_MAX_COLS    = 30
MAX_EXTRACT_LEN   = 512
BLIND_CONFIDENCE  = 0.80
BINARY_SEARCH_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789!@#$%^&*()_+-=[]{}|;:,./<>? "
)

# ── Output ────────────────────────────────────────────────────────────────────
REPORTS_DIR        = "reports"
LOGS_DIR           = "logs"
DEFAULT_REPORT_FMT = "html"

# ── User Agents ───────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]

# ── Injection type constants ───────────────────────────────────────────────────
INJ_ERROR   = "error"
INJ_UNION   = "union"
INJ_BOOLEAN = "boolean"
INJ_TIME    = "time"
INJ_STACKED = "stacked"

INJ_TYPE_LABELS = {
    INJ_ERROR:   "Error-Based",
    INJ_UNION:   "Union-Based",
    INJ_BOOLEAN: "Boolean-Based Blind",
    INJ_TIME:    "Time-Based Blind",
    INJ_STACKED: "Stacked Queries",
}

INJ_PRIORITY = [INJ_ERROR, INJ_UNION, INJ_BOOLEAN, INJ_TIME]

# ── DBMS constants ────────────────────────────────────────────────────────────
DBMS_MYSQL   = "MySQL"
DBMS_PG      = "PostgreSQL"
DBMS_MSSQL   = "Microsoft SQL Server"
DBMS_ORACLE  = "Oracle"
DBMS_SQLITE  = "SQLite"
DBMS_MARIADB = "MariaDB"

SUPPORTED_DBMS = [DBMS_MYSQL, DBMS_PG, DBMS_MSSQL, DBMS_ORACLE, DBMS_SQLITE, DBMS_MARIADB]

# ── Rich colour theme ─────────────────────────────────────────────────────────
THEME = {
    "banner":    "bold bright_red",
    "success":   "bold bright_green",
    "warning":   "bold bright_yellow",
    "error":     "bold bright_red",
    "info":      "bold bright_cyan",
    "vuln":      "bold red",
    "safe":      "bold green",
    "dimmed":    "dim white",
    "highlight": "bold magenta",
    "data":      "bright_white",
    "dbms":      "bold cyan",
    "waf":       "bold yellow",
    "param":     "italic bright_blue",
    "url":       "underline bright_cyan",
    "title":     "bold white",
    "subtitle":  "dim cyan",
    "border":    "bright_black",
}

# ensure dirs
for _d in (REPORTS_DIR, LOGS_DIR):
    os.makedirs(_d, exist_ok=True)
