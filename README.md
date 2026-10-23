# AbsoluteSQL — SQL Injection Testing Platform
**v1.0.0 · SpudBlood Edition**

Automated, multi-technique SQL injection testing with a stunning terminal UI.

---

## Install

```bash
pip install -r requirements.txt
```

Python 3.8+ required.

---

## Quick Start

```bash
# Scan all GET parameters
python main.py -u "http://target.com/page.php?id=1"

# Scan a specific parameter
python main.py -u "http://target.com/page.php?id=1&name=test" -p id

# POST form scan
python main.py -u "http://target.com/login.php" --method POST --data "user=admin&pass=x"

# Full dump after detection
python main.py -u "http://target.com/page.php?id=1" --dump

# Enumerate databases only
python main.py -u "http://target.com/page.php?id=1" --dbs

# List tables only
python main.py -u "http://target.com/page.php?id=1" --tables

# Dump a specific table from a specific DB
python main.py -u "http://target.com/page.php?id=1" --dump --db-name mydb --table-name users

# Through a proxy (Burp Suite)
python main.py -u "http://target.com/page.php?id=1" --proxy http://127.0.0.1:8080

# Custom cookies and headers
python main.py -u "http://target.com/page.php?id=1" \
    --cookies "session=abc123; token=xyz" \
    -H "X-Forwarded-For: 127.0.0.1"

# Level 3 scan (includes slow time-based detection)
python main.py -u "http://target.com/page.php?id=1" --level 3

# Force DBMS, randomise User-Agent, HTML report only
python main.py -u "http://target.com/page.php?id=1" \
    --dbms MySQL --random-agent --report html
```

---

## Injection Techniques

| Level | Technique          | Speed   | Description                           |
|-------|--------------------|---------|---------------------------------------|
| 1     | **Error-Based**    | Fast    | Triggers DBMS error messages          |
| 2     | **Union-Based**    | Fast    | Reflects data through UNION SELECT    |
| 2     | **Boolean Blind**  | Medium  | Infers data from true/false responses |
| 3     | **Time-Based**     | Slow    | Detects via response timing delays    |

---

## DBMS Support

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

---

## Options Reference

### Target
| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (required) |
| `-p, --param` | Specific parameter to test |
| `--method` | HTTP method: GET or POST |
| `--data` | POST body: `'param=value&param2=value2'` |
| `--dbms` | Force DBMS (skip fingerprinting) |

### Request
| Flag | Description |
|------|-------------|
| `--timeout` | Request timeout in seconds (default: 15) |
| `--delay` | Delay between requests (default: 0) |
| `--retries` | Retry count on failure (default: 3) |
| `--proxy` | Proxy URL: `http://host:port` |
| `--cookies` | Cookie string: `'name=val; name2=val2'` |
| `-H, --header` | Extra header (repeatable): `'Name: Value'` |
| `--random-agent` | Randomise User-Agent each request |
| `--no-ssl-verify` | Disable SSL certificate verification |

### Detection
| Flag | Description |
|------|-------------|
| `--level` | Depth: 1=error, 2=+union+bool, 3=+time (default: 2) |
| `--time-delay` | Sleep seconds for time-based payloads (default: 5) |
| `--no-waf` | Skip WAF detection probe |

### Extraction
| Flag | Description |
|------|-------------|
| `--dump` | Dump database contents |
| `--dbs` | Enumerate databases |
| `--tables` | Enumerate tables |
| `--db-name` | Target specific database |
| `--table-name` | Target specific table |
| `--row-limit` | Max rows to dump per table (default: 50) |

### Output
| Flag | Description |
|------|-------------|
| `--report` | Report format: html, json, or both (default: both) |
| `--output` | Base path for report files |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Minimal output |

---

## Output

Reports are saved to the `reports/` directory:
- `reports/absolutesql_<host>_<timestamp>.html` — Visual HTML report
- `reports/absolutesql_<host>_<timestamp>.json` — Machine-readable JSON

Logs are saved to the `logs/` directory.

---

## File Structure

```
AbsoluteSQL/
├── main.py                  Entry point & CLI
├── requirements.txt         Dependencies
├── README.md
└── absolutesql/
    ├── __init__.py
    ├── config.py            Constants & settings
    ├── payloads.py          Payload library (all techniques + DBMS)
    ├── utils.py             URL helpers, logging, string utils
    ├── http_client.py       HTTP session with retry, proxy, timing
    ├── detector.py          WAF & DBMS fingerprinting
    ├── scanner.py           Vulnerability detection engine
    ├── injector.py          Data extraction via injection channel
    ├── extractor.py         DB enumeration (dbs → tables → cols → rows)
    └── reporter.py          HTML + JSON report generation
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No vulnerabilities found |
| 1    | Vulnerabilities detected |
| 130  | Interrupted by user |

---

*For authorized penetration testing only.*
