"""
Data models for the OSINT username scanner engine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class ScanStatus(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"


@dataclass
class SiteDefinition:
    name: str
    category: str
    uri_check: str
    uri_pretty: Optional[str] = None
    e_code: int = 200
    m_code: int = 404
    e_string: str = ""
    m_string: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    def get_check_url(self, account: str) -> str:
        """Substitute the username / account into uri_check template for HTTP probing."""
        return self.uri_check.replace("{account}", account).replace("{username}", account)

    def get_pretty_url(self, account: str) -> str:
        """Get the user-friendly profile URL (e.g. x.com/user instead of api.x.com/...)."""
        template = self.uri_pretty if self.uri_pretty else self.uri_check
        return template.replace("{account}", account).replace("{username}", account)


@dataclass
class ScanResult:
    site: SiteDefinition
    url: str
    status: ScanStatus
    http_status: Optional[int] = None
    response_time: float = 0.0
    error_message: Optional[str] = None
    details: str = ""
    title: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
