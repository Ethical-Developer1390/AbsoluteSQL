"""
AbsoluteSQL — HTTP Client
Session management, retry logic, proxy, cookies, timing.
"""

import time
import random
import urllib.parse
from typing import Optional, Dict, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import (
    DEFAULT_TIMEOUT, DEFAULT_RETRIES, DEFAULT_DELAY,
    USER_AGENTS, TIME_THRESHOLD
)
from .utils import log, random_user_agent


class HTTPClient:
    """
    Managed HTTP session for SQL injection testing.

    All injection requests flow through here — handles retries,
    delays, proxy routing, cookie jar, and timing measurements.
    """

    def __init__(
        self,
        timeout:    int            = DEFAULT_TIMEOUT,
        delay:      float          = DEFAULT_DELAY,
        retries:    int            = DEFAULT_RETRIES,
        proxy:      Optional[str]  = None,
        cookies:    Optional[str]  = None,
        headers:    Optional[Dict] = None,
        user_agent: Optional[str]  = None,
        random_ua:  bool           = False,
        verify_ssl: bool           = False,
    ) -> None:
        self.timeout    = timeout
        self.delay      = delay
        self.proxy      = proxy
        self.random_ua  = random_ua
        self.verify_ssl = verify_ssl
        self._req_count = 0

        self.session = requests.Session()

        # Retry adapter
        retry = Retry(
            total            = retries,
            backoff_factor   = 0.3,
            status_forcelist = [429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

        # Default headers
        ua = user_agent or random_user_agent()
        self.session.headers.update({
            "User-Agent":      ua,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "keep-alive",
        })

        # Extra headers supplied by user
        if headers:
            self.session.headers.update(headers)

        # Proxy
        if proxy:
            self.session.proxies = {
                "http":  proxy,
                "https": proxy,
            }

        # Cookies from "name=value; name2=value2" string
        if cookies:
            for pair in cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    # ── Core request ──────────────────────────────────────────────────────────
    def _request(
        self,
        method:  str,
        url:     str,
        params:  Optional[Dict] = None,
        data:    Optional[Dict] = None,
        timeout: Optional[int]  = None,
    ) -> Optional[requests.Response]:
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, self.delay * 0.2))

        if self.random_ua:
            self.session.headers["User-Agent"] = random_user_agent()

        timeout = timeout or self.timeout

        try:
            resp = self.session.request(
                method  = method.upper(),
                url     = url,
                params  = params,
                data    = data,
                timeout = timeout,
                verify  = self.verify_ssl,
                allow_redirects = True,
            )
            self._req_count += 1
            log.debug(f"{method.upper()} {url} → {resp.status_code} ({len(resp.content)}B)")
            return resp
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            log.warning(f"ConnectionError: {url} — {e}")
            return None
        except requests.exceptions.RequestException as e:
            log.warning(f"RequestException: {url} — {e}")
            return None

    # ── Public GET / POST ─────────────────────────────────────────────────────
    def get(
        self,
        url:    str,
        params: Optional[Dict] = None,
    ) -> Optional[requests.Response]:
        return self._request("GET", url, params=params)

    def post(
        self,
        url:  str,
        data: Optional[Dict] = None,
    ) -> Optional[requests.Response]:
        return self._request("POST", url, data=data)

    # ── Timed request (for time-based blind) ──────────────────────────────────
    def timed_get(
        self,
        url:    str,
        params: Optional[Dict] = None,
        forced_timeout: int    = 30,
    ) -> Tuple[Optional[requests.Response], float]:
        """
        Send GET request and return (response, elapsed_seconds).
        Uses forced_timeout to wait longer than usual for time-based payloads.
        """
        if self.random_ua:
            self.session.headers["User-Agent"] = random_user_agent()

        t0 = time.perf_counter()
        try:
            resp = self.session.get(
                url,
                params  = params,
                timeout = forced_timeout,
                verify  = self.verify_ssl,
                allow_redirects = True,
            )
            self._req_count += 1
            elapsed = time.perf_counter() - t0
            log.debug(f"TIMED GET {url} → {resp.status_code} ({elapsed:.2f}s)")
            return resp, elapsed
        except requests.exceptions.Timeout:
            elapsed = time.perf_counter() - t0
            log.debug(f"TIMED GET {url} → TIMEOUT ({elapsed:.2f}s)")
            return None, elapsed
        except requests.exceptions.RequestException as e:
            log.warning(f"Timed GET failed: {e}")
            return None, 0.0

    def timed_post(
        self,
        url:  str,
        data: Optional[Dict] = None,
        forced_timeout: int  = 30,
    ) -> Tuple[Optional[requests.Response], float]:
        if self.random_ua:
            self.session.headers["User-Agent"] = random_user_agent()

        t0 = time.perf_counter()
        try:
            resp = self.session.post(
                url,
                data    = data,
                timeout = forced_timeout,
                verify  = self.verify_ssl,
                allow_redirects = True,
            )
            self._req_count += 1
            elapsed = time.perf_counter() - t0
            return resp, elapsed
        except requests.exceptions.Timeout:
            return None, time.perf_counter() - t0
        except requests.exceptions.RequestException as e:
            log.warning(f"Timed POST failed: {e}")
            return None, 0.0

    # ── Baseline ──────────────────────────────────────────────────────────────
    def baseline(
        self,
        url:    str,
        params: Optional[Dict] = None,
        method: str            = "GET",
        n:      int            = 2,
    ) -> Optional[str]:
        """
        Fetch n baseline responses and return body of the last one.
        Sends n requests and returns the body that appeared most consistently.
        """
        bodies = []
        for _ in range(n):
            r = self._request(method, url, params=params)
            if r is not None:
                bodies.append(r.text)
        if not bodies:
            return None
        # Return the most common body
        return max(set(bodies), key=bodies.count)

    # ── Convenience ───────────────────────────────────────────────────────────
    @property
    def request_count(self) -> int:
        return self._req_count

    def close(self) -> None:
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
