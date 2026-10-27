"""
Database loader and manager for OSINT site signatures.
Supports local JSON database and updating from WhatsMyName repository.
"""

import json
from pathlib import Path
from typing import List, Optional
import httpx

from core.models import SiteDefinition

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sites.json"
WMN_REMOTE_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"


class SiteDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.sites: List[SiteDefinition] = []

    def load(self, category_filter: Optional[str] = None) -> List[SiteDefinition]:
        """Load site definitions from JSON file."""
        if not self.db_path.exists():
            raise FileNotFoundError(f"Site database not found at {self.db_path}")

        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_sites = data.get("sites", [])
        self.sites = []

        for item in raw_sites:
            site = SiteDefinition(
                name=item.get("name", "Unknown"),
                category=item.get("cat", item.get("category", "general")),
                uri_check=item.get("uri_check", item.get("url", "")),
                uri_pretty=item.get("uri_pretty"),
                e_code=int(item.get("e_code", 200)),
                m_code=int(item.get("m_code", 404)),
                e_string=item.get("e_string", ""),
                m_string=item.get("m_string", ""),
                headers=item.get("headers", {})
            )

            if category_filter:
                if site.category.lower() == category_filter.lower():
                    self.sites.append(site)
            else:
                self.sites.append(site)

        return self.sites

    async def update_from_remote(self, timeout: float = 15.0) -> int:
        """Download latest site database from WhatsMyName repository."""
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(WMN_REMOTE_URL)
            resp.raise_for_status()
            data = resp.json()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return len(data.get("sites", []))
