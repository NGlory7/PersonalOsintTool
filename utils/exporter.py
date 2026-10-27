"""
Export scan results to various formats (JSON, CSV, HTML).
"""

import csv
import json
from pathlib import Path
from typing import List

from core.models import ScanResult, ScanStatus


class ResultsExporter:
    @staticmethod
    def to_json(results: List[ScanResult], username: str, output_path: Path):
        """Export results to formatted JSON file."""
        found = [
            {
                "site": r.site.name,
                "category": r.site.category,
                "url": r.url,
                "http_status": r.http_status,
                "response_time_ms": round(r.response_time * 1000, 2),
                "title": r.title,
                "bio": r.bio,
                "avatar_url": r.avatar_url
            }
            for r in results if r.status == ScanStatus.FOUND
        ]

        data = {
            "target": username,
            "total_scanned": len(results),
            "found_count": len(found),
            "matches": found
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def to_csv(results: List[ScanResult], username: str, output_path: Path):
        """Export results to CSV file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Site", "Category", "Status", "URL", "HTTP Status", "Response Time (s)", "Title", "Bio", "Avatar URL"])
            for r in results:
                writer.writerow([
                    username,
                    r.site.name,
                    r.site.category,
                    r.status.value,
                    r.url,
                    r.http_status or "",
                    f"{r.response_time:.3f}",
                    r.title or "",
                    r.bio or "",
                    r.avatar_url or ""
                ])
