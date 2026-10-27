"""
High-performance asynchronous scanning engine for username profile checks.
"""

import asyncio
import html
import re
import time
from typing import Callable, Dict, List, Optional
import httpx

from core.models import SiteDefinition, ScanResult, ScanStatus

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}


def extract_html_metadata(content_text: str) -> Dict[str, Optional[str]]:
    """Extract OpenGraph and meta tags (title, bio/description, avatar)."""
    meta: Dict[str, Optional[str]] = {"title": None, "bio": None, "avatar_url": None}
    if not content_text:
        return meta

    # Extract title
    title_match = re.search(r'<meta\s+property=["\']og:title["\']\s+content=["\'](.*?)["\']', content_text, re.I) or \
                  re.search(r'<title>(.*?)</title>', content_text, re.I)
    if title_match:
        meta["title"] = html.unescape(title_match.group(1).strip())

    # Extract bio / description
    desc_match = re.search(r'<meta\s+property=["\']og:description["\']\s+content=["\'](.*?)["\']', content_text, re.I) or \
                 re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', content_text, re.I)
    if desc_match:
        bio = html.unescape(desc_match.group(1).strip())
        if bio and len(bio) > 200:
            bio = bio[:197] + "..."
        meta["bio"] = bio

    # Extract avatar / og:image
    img_match = re.search(r'<meta\s+property=["\']og:image["\']\s+content=["\'](.*?)["\']', content_text, re.I)
    if img_match:
        meta["avatar_url"] = img_match.group(1).strip()

    return meta


class UsernameScanner:
    def __init__(
        self,
        sites: List[SiteDefinition],
        concurrency: int = 25,
        timeout: float = 8.0,
        proxy: Optional[str] = None
    ):
        self.sites = sites
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _check_single_site(
        self,
        client: httpx.AsyncClient,
        site: SiteDefinition,
        username: str
    ) -> ScanResult:
        check_url = site.get_check_url(username)
        display_url = site.get_pretty_url(username)
        start_time = time.monotonic()

        headers = {**DEFAULT_HEADERS, **site.headers}

        async with self.semaphore:
            try:
                response = await client.get(
                    check_url,
                    headers=headers,
                    follow_redirects=True,
                    timeout=self.timeout
                )
                elapsed = time.monotonic() - start_time
                status_code = response.status_code
                content_text = response.text

                # Check for rate limiting / Cloudflare blocks
                if status_code in (429,):
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.RATE_LIMITED,
                        http_status=status_code,
                        response_time=elapsed,
                        error_message="Rate limited by target"
                    )

                # Check if missing string is present in page content
                if site.m_string and site.m_string.lower() in content_text.lower():
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.NOT_FOUND,
                        http_status=status_code,
                        response_time=elapsed
                    )

                # Check if expected string is required and missing
                if site.e_string and site.e_string.lower() not in content_text.lower():
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.NOT_FOUND,
                        http_status=status_code,
                        response_time=elapsed
                    )

                # Check status code matching
                if status_code == site.e_code:
                    meta = extract_html_metadata(content_text)
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.FOUND,
                        http_status=status_code,
                        response_time=elapsed,
                        details="Profile found",
                        title=meta.get("title"),
                        bio=meta.get("bio"),
                        avatar_url=meta.get("avatar_url")
                    )
                elif status_code == site.m_code or status_code in (404, 410):
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.NOT_FOUND,
                        http_status=status_code,
                        response_time=elapsed
                    )
                else:
                    return ScanResult(
                        site=site,
                        url=display_url,
                        status=ScanStatus.NOT_FOUND,
                        http_status=status_code,
                        response_time=elapsed
                    )

            except httpx.TimeoutException:
                elapsed = time.monotonic() - start_time
                return ScanResult(
                    site=site,
                    url=display_url,
                    status=ScanStatus.ERROR,
                    response_time=elapsed,
                    error_message="Connection timed out"
                )
            except httpx.HTTPError as exc:
                elapsed = time.monotonic() - start_time
                return ScanResult(
                    site=site,
                    url=display_url,
                    status=ScanStatus.ERROR,
                    response_time=elapsed,
                    error_message=f"HTTP Error: {type(exc).__name__}"
                )
            except Exception as exc:
                elapsed = time.monotonic() - start_time
                return ScanResult(
                    site=site,
                    url=display_url,
                    status=ScanStatus.ERROR,
                    response_time=elapsed,
                    error_message=str(exc)
                )

    async def scan(
        self,
        username: str,
        on_result: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan all configured sites for the given username.
        Triggers `on_result` callback in real-time as each site finishes.
        """
        results: List[ScanResult] = []

        limits = httpx.Limits(max_keepalive_connections=self.concurrency, max_connections=self.concurrency * 2)
        async with httpx.AsyncClient(limits=limits, proxy=self.proxy, verify=False) as client:
            async def worker(site: SiteDefinition):
                res = await self._check_single_site(client, site, username)
                results.append(res)
                if on_result:
                    if asyncio.iscoroutinefunction(on_result):
                        await on_result(res)
                    else:
                        on_result(res)

            tasks = [worker(site) for site in self.sites]
            await asyncio.gather(*tasks)

        return results
