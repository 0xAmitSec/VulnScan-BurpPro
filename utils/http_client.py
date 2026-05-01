"""
VulnScan - Async HTTP Client
Supports: proxy, custom headers, rate limiting, retries, SSL ignore
"""
import asyncio
import httpx
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse


class HTTPClient:
    def __init__(self, config=None):
        self.config = config
        self.timeout = getattr(config, "timeout", 10)
        self.proxy = getattr(config, "proxy", None)
        self.verify_ssl = getattr(config, "verify_ssl", False)
        self.delay = getattr(config, "delay", 0.2)
        self.max_redirects = getattr(config, "max_redirects", 5)
        self.user_agent = getattr(config, "user_agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
        self.custom_headers = getattr(config, "custom_headers", {})
        self._last_request_time = 0
        self._session: Optional[httpx.AsyncClient] = None

    def _build_headers(self, extra: dict = None) -> dict:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        headers.update(self.custom_headers)
        if extra:
            headers.update(extra)
        return headers

    async def _get_session(self) -> httpx.AsyncClient:
        if self._session is None or self._session.is_closed:
            proxies = {"http://": self.proxy, "https://": self.proxy} if self.proxy else None
            self._session = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects,
                proxies=proxies,
                headers=self._build_headers(),
            )
        return self._session

    async def _rate_limit(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        self._last_request_time = time.time()

    async def get(self, url: str, headers: dict = None, params: dict = None,
                  retries: int = 2) -> Optional[httpx.Response]:
        await self._rate_limit()
        session = await self._get_session()
        for attempt in range(retries + 1):
            try:
                resp = await session.get(url, headers=headers, params=params)
                return resp
            except httpx.TimeoutException:
                if attempt == retries:
                    return None
                await asyncio.sleep(1)
            except Exception:
                return None

    async def post(self, url: str, data: dict = None, json: dict = None,
                   headers: dict = None, retries: int = 2) -> Optional[httpx.Response]:
        await self._rate_limit()
        session = await self._get_session()
        for attempt in range(retries + 1):
            try:
                resp = await session.post(url, data=data, json=json, headers=headers)
                return resp
            except httpx.TimeoutException:
                if attempt == retries:
                    return None
                await asyncio.sleep(1)
            except Exception:
                return None

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        await self._rate_limit()
        session = await self._get_session()
        try:
            return await session.request(method, url, **kwargs)
        except Exception:
            return None

    async def head(self, url: str, headers: dict = None) -> Optional[httpx.Response]:
        await self._rate_limit()
        session = await self._get_session()
        try:
            return await session.head(url, headers=headers)
        except Exception:
            return None

    async def options(self, url: str, headers: dict = None) -> Optional[httpx.Response]:
        await self._rate_limit()
        session = await self._get_session()
        try:
            return await session.options(url, headers=headers)
        except Exception:
            return None

    async def close(self):
        if self._session and not self._session.is_closed:
            await self._session.aclose()

    def is_in_scope(self, url: str, scope_domains: list) -> bool:
        if not scope_domains:
            return True
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        for domain in scope_domains:
            domain = domain.lower().lstrip("*.")
            if host == domain or host.endswith("." + domain):
                return True
        return False
