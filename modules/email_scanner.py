"""
Email OSINT Scanner:
- Multi-Source Avatar Resolution (Gravatar, Libravatar, Unavatar, GitHub)
- Connected GitHub Accounts (via commits & user search API)
- Mail Provider / MX Infrastructure (Google Workspace, Microsoft 365, ProtonMail, etc.)
- Data Breach Presence (XposedOrNot & HaveIBeenPwned)
- PGP Cryptographic Keys (Ubuntu Keyserver)
- Automated Username Derivation
"""

from dataclasses import dataclass, field
import hashlib
from typing import Dict, List, Optional
import urllib.parse
import httpx


@dataclass
class GitHubAccount:
    found: bool = False
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    profile_url: Optional[str] = None
    source: str = ""


@dataclass
class MailProviderInfo:
    domain: str
    provider: str = "Unknown"
    mx_records: List[str] = field(default_factory=list)


@dataclass
class GravatarProfile:
    exists: bool = False
    hash: str = ""
    avatar_url: str = ""
    display_name: Optional[str] = None
    preferred_username: Optional[str] = None
    profile_url: Optional[str] = None
    about_me: Optional[str] = None
    location: Optional[str] = None
    urls: List[Dict[str, str]] = field(default_factory=list)
    verified_accounts: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class PGPKeyInfo:
    key_id: str
    created_date: str
    algo: str
    user_id: str


@dataclass
class BreachReport:
    checked: bool = True
    pwned: bool = False
    count: int = 0
    breaches: List[str] = field(default_factory=list)
    hibp_url: str = ""


@dataclass
class EmailReport:
    email: str
    prefix: str
    domain: str
    provider_info: MailProviderInfo
    github: GitHubAccount
    gravatar: GravatarProfile
    breach: BreachReport
    resolved_avatar_url: Optional[str] = None
    avatar_source: Optional[str] = None
    pgp_keys: List[PGPKeyInfo] = field(default_factory=list)
    suggested_usernames: List[str] = field(default_factory=list)


class EmailScanner:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*"
        }

    async def scan(self, email: str) -> EmailReport:
        clean_email = email.strip().lower()
        parts = clean_email.split("@")
        prefix = parts[0] if parts else ""
        domain = parts[-1] if len(parts) > 1 else ""
        md5_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()

        import asyncio

        # Concurrently perform all OSINT checks
        gravatar_task = self._check_gravatar(md5_hash)
        pgp_task = self._check_pgp_keys(clean_email)
        breach_task = self._check_breaches(clean_email)
        github_task = self._check_github_by_email(clean_email)
        provider_task = self._check_mail_provider(domain)
        unavatar_task = self._check_unavatar(clean_email)
        libravatar_task = self._check_libravatar(md5_hash)

        gravatar_res, pgp_res, breach_res, github_res, provider_res, unavatar_res, libravatar_res = await asyncio.gather(
            gravatar_task, pgp_task, breach_task, github_task, provider_task, unavatar_task, libravatar_task
        )

        # Prioritize resolved avatar photo
        resolved_avatar = None
        avatar_source = None

        if gravatar_res.exists and gravatar_res.avatar_url:
            resolved_avatar = gravatar_res.avatar_url
            avatar_source = "Gravatar"
        elif github_res.found and github_res.avatar_url:
            resolved_avatar = github_res.avatar_url
            avatar_source = "GitHub"
        elif unavatar_res:
            resolved_avatar = unavatar_res
            avatar_source = "Unavatar Multi-Source"
        elif libravatar_res:
            resolved_avatar = libravatar_res
            avatar_source = "Libravatar"

        suggested = [prefix] if prefix else []
        if github_res.found and github_res.username and github_res.username not in suggested:
            suggested.append(github_res.username)
        if gravatar_res.exists and gravatar_res.preferred_username and gravatar_res.preferred_username not in suggested:
            suggested.append(gravatar_res.preferred_username)

        return EmailReport(
            email=clean_email,
            prefix=prefix,
            domain=domain,
            provider_info=provider_res,
            github=github_res,
            gravatar=gravatar_res,
            breach=breach_res,
            resolved_avatar_url=resolved_avatar,
            avatar_source=avatar_source,
            pgp_keys=pgp_res,
            suggested_usernames=suggested
        )

    async def _check_unavatar(self, email: str) -> Optional[str]:
        """Check unavatar.io aggregator which queries multiple public identity providers."""
        url = f"https://unavatar.io/{email}?json=true&fallback=false"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json()
                    img_url = data.get("url")
                    if img_url:
                        return img_url
        except Exception:
            pass
        return None

    async def _check_libravatar(self, md5_hash: str) -> Optional[str]:
        """Check open-source federated Libravatar network."""
        url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?d=404"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.head(url, headers=self.headers)
                if resp.status_code == 200:
                    return str(resp.url)
        except Exception:
            pass
        return None

    async def _check_mail_provider(self, domain: str) -> MailProviderInfo:
        if not domain:
            return MailProviderInfo(domain="", provider="Unknown")

        doh_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"
        headers = {"Accept": "application/dns-json", **self.headers}

        mx_records = []
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(doh_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        mx_records.append(ans.get("data", ""))
        except Exception:
            pass

        mx_text = " ".join(mx_records).lower()
        provider = "Custom / Private Mail Server"

        if "google.com" in mx_text or "googlemail.com" in mx_text or domain == "gmail.com":
            provider = "Google Workspace / Gmail"
        elif "outlook.com" in mx_text or "microsoft.com" in mx_text or domain in ("hotmail.com", "outlook.com"):
            provider = "Microsoft 365 / Outlook"
        elif "protonmail.ch" in mx_text or "proton.me" in mx_text:
            provider = "ProtonMail (Encrypted)"
        elif "yandex.net" in mx_text or "yandex.ru" in mx_text:
            provider = "Yandex Mail"
        elif "icloud.com" in mx_text:
            provider = "Apple iCloud Mail"
        elif "pphosted.com" in mx_text:
            provider = "Proofpoint Enterprise"
        elif "mimecast.com" in mx_text:
            provider = "Mimecast Enterprise"

        return MailProviderInfo(domain=domain, provider=provider, mx_records=mx_records)

    async def _check_github_by_email(self, email: str) -> GitHubAccount:
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # 1. Check commit author API
                commit_url = f"https://api.github.com/search/commits?q=author-email:{email}&per_page=1"
                resp = await client.get(commit_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    if items and "author" in items[0] and items[0]["author"]:
                        author = items[0]["author"]
                        return GitHubAccount(
                            found=True,
                            username=author.get("login"),
                            avatar_url=author.get("avatar_url"),
                            profile_url=author.get("html_url"),
                            source="GitHub Public Commits"
                        )

                # 2. Check public user email search
                user_url = f"https://api.github.com/search/users?q={email}+in:email&per_page=1"
                resp_u = await client.get(user_url, headers=headers)
                if resp_u.status_code == 200:
                    data_u = resp_u.json()
                    items_u = data_u.get("items", [])
                    if items_u:
                        user = items_u[0]
                        return GitHubAccount(
                            found=True,
                            username=user.get("login"),
                            avatar_url=user.get("avatar_url"),
                            profile_url=user.get("html_url"),
                            source="GitHub User Profile"
                        )
        except Exception:
            pass

        return GitHubAccount(found=False)

    async def _check_gravatar(self, md5_hash: str) -> GravatarProfile:
        url = f"https://en.gravatar.com/{md5_hash}.json"
        avatar_url = f"https://en.gravatar.com/avatar/{md5_hash}?s=400&d=404"

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json()
                    entry = data.get("entry", [{}])[0]

                    urls = [{"title": u.get("title", ""), "value": u.get("value", "")} for u in entry.get("urls", [])]
                    accounts = [{"shortname": a.get("shortname", ""), "url": a.get("url", "")} for a in entry.get("accounts", [])]

                    return GravatarProfile(
                        exists=True,
                        hash=md5_hash,
                        avatar_url=f"https://en.gravatar.com/avatar/{md5_hash}?s=400",
                        display_name=entry.get("displayName"),
                        preferred_username=entry.get("preferredUsername"),
                        profile_url=entry.get("profileUrl"),
                        about_me=entry.get("aboutMe"),
                        location=entry.get("currentLocation"),
                        urls=urls,
                        verified_accounts=accounts
                    )
                else:
                    img_resp = await client.head(avatar_url, headers=self.headers)
                    if img_resp.status_code == 200:
                        return GravatarProfile(
                            exists=True,
                            hash=md5_hash,
                            avatar_url=avatar_url
                        )
        except Exception:
            pass

        return GravatarProfile(exists=False, hash=md5_hash)

    async def _check_breaches(self, email: str) -> BreachReport:
        hibp_url = f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"
        url = f"https://api.xposedornot.com/v1/check-email/{email}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if "breaches" in data and isinstance(data["breaches"], list) and len(data["breaches"]) > 0:
                        raw_breaches = data["breaches"][0]
                        if isinstance(raw_breaches, list):
                            return BreachReport(
                                checked=True,
                                pwned=True,
                                count=len(raw_breaches),
                                breaches=raw_breaches,
                                hibp_url=hibp_url
                            )
                    elif data.get("Error") == "Not found":
                        return BreachReport(
                            checked=True,
                            pwned=False,
                            count=0,
                            breaches=[],
                            hibp_url=hibp_url
                        )
        except Exception:
            pass

        return BreachReport(checked=False, pwned=False, count=0, breaches=[], hibp_url=hibp_url)

    async def _check_pgp_keys(self, email: str) -> List[PGPKeyInfo]:
        keys: List[PGPKeyInfo] = []
        url = f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&options=mr"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 200 and "pub:" in resp.text:
                    lines = resp.text.splitlines()
                    current_pub = None
                    for line in lines:
                        if line.startswith("pub:"):
                            parts = line.split(":")
                            key_id = parts[1] if len(parts) > 1 else ""
                            algo = parts[2] if len(parts) > 2 else ""
                            created = parts[4] if len(parts) > 4 else ""
                            current_pub = (key_id, algo, created)
                        elif line.startswith("uid:") and current_pub:
                            uid = line[4:].strip()
                            keys.append(PGPKeyInfo(
                                key_id=current_pub[0],
                                algo=current_pub[1],
                                created_date=current_pub[2],
                                user_id=uid
                            ))
                            current_pub = None
        except Exception:
            pass

        return keys
