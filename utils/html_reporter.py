"""
Self-contained, modern HTML report generator for OSINT investigations.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.models import ScanResult, ScanStatus
from modules.email_scanner import EmailReport
from modules.phone_scanner import PhoneReport


class HTMLReporter:
    @staticmethod
    def generate(
        username: Optional[str] = None,
        results: Optional[List[ScanResult]] = None,
        email_report: Optional[EmailReport] = None,
        phone_report: Optional[PhoneReport] = None,
        output_path: Optional[Path] = None
    ) -> Path:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_name = username or (email_report.email if email_report else "Target")

        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path("reports") / f"osint_report_{target_name}_{timestamp}.html"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        found_results = [r for r in (results or []) if r.status == ScanStatus.FOUND]

        # Resolve primary target avatar
        target_avatar = None
        avatar_source = None
        if email_report and email_report.resolved_avatar_url:
            target_avatar = email_report.resolved_avatar_url
            avatar_source = email_report.avatar_source
        else:
            for r in found_results:
                if r.avatar_url:
                    target_avatar = r.avatar_url
                    avatar_source = f"{r.site.name} Profile"
                    break

        header_avatar_html = ""
        if target_avatar:
            header_avatar_html = f"""
            <div style="display:flex; align-items:center; gap:16px;">
                <img src="{target_avatar}" style="width:72px; height:72px; border-radius:50%; border:3px solid var(--primary); object-fit:cover;" />
                <div>
                    <h1>🕵️ OSINT Footprint Report</h1>
                    <div class="header-meta">Target: <strong>{target_name}</strong> | Generated: {now_str}</div>
                    <span class="chip" style="font-size:11px; margin-top:4px;">📸 Photo Source: {avatar_source}</span>
                </div>
            </div>
            """
        else:
            header_avatar_html = f"""
            <div>
                <h1>🕵️ OSINT Footprint Report</h1>
                <div class="header-meta">Target: <strong>{target_name}</strong> | Generated: {now_str}</div>
            </div>
            """

        # Generate HTML rows for discovered profiles
        profile_rows = ""
        for r in sorted(found_results, key=lambda x: (x.site.category, x.site.name)):
            avatar_html = f'<img src="{r.avatar_url}" class="avatar" />' if r.avatar_url else '<div class="avatar-placeholder">🌐</div>'
            bio_html = f'<p class="bio">{r.bio}</p>' if r.bio else '<span class="empty-bio">No bio available</span>'
            title_html = f'<span class="page-title">{r.title}</span>' if r.title else ''

            profile_rows += f"""
            <tr class="profile-row">
                <td class="platform-cell">
                    {avatar_html}
                    <div>
                        <strong>{r.site.name}</strong>
                        {title_html}
                    </div>
                </td>
                <td><span class="badge badge-{r.site.category}">{r.site.category}</span></td>
                <td><a href="{r.url}" target="_blank" class="url-link">{r.url}</a></td>
                <td class="bio-cell">{bio_html}</td>
                <td class="latency">{round(r.response_time * 1000)} ms</td>
            </tr>
            """

        # Email section HTML
        email_html = ""
        if email_report:
            g = email_report.gravatar
            b = email_report.breach

            # Breach Card
            if b.pwned:
                breach_chips = "".join([f'<span class="chip chip-breach">🚨 {br}</span> ' for br in b.breaches[:20]])
                more_tag = f'<span class="dim"> +{len(b.breaches) - 20} more</span>' if len(b.breaches) > 20 else ''
                breach_card = f"""
                <div class="card card-pwned">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h4 style="color: #ef4444; margin: 0;">⚠️ Data Breach Detected ({b.count} Breaches)</h4>
                        <a href="{b.hibp_url}" target="_blank" class="chip chip-hibp">HaveIBeenPwned ↗</a>
                    </div>
                    <p style="font-size: 13px; color: #cbd5e1; margin-bottom: 10px;">This email was found exposed in public security incidents & database leaks:</p>
                    <div class="chips-container">{breach_chips}{more_tag}</div>
                </div>
                """
            else:
                breach_card = f"""
                <div class="card card-clean">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h4 style="color: #10b981; margin: 0;">✅ No Public Breaches Found</h4>
                        <a href="{b.hibp_url}" target="_blank" class="chip chip-hibp">HaveIBeenPwned ↗</a>
                    </div>
                    <p style="font-size: 13px; color: var(--text-muted); margin-top: 8px;">No records of this email address in public data breaches.</p>
                </div>
                """

            gravatar_card = ""
            if g.exists:
                avatar_img = f'<img src="{g.avatar_url}" class="gravatar-img" />' if g.avatar_url else ''
                links_html = "".join([f'<a href="{u["value"]}" target="_blank" class="chip">{u["title"] or u["value"]}</a> ' for u in g.urls])
                accounts_html = "".join([f'<a href="{a["url"]}" target="_blank" class="chip chip-social">{a["shortname"]}</a> ' for a in g.verified_accounts])

                gravatar_card = f"""
                <div class="card gravatar-card">
                    <div class="gravatar-header">
                        {avatar_img}
                        <div>
                            <h3>{g.display_name or g.preferred_username or "Gravatar Profile"}</h3>
                            <p class="location">📍 {g.location or "Location not specified"}</p>
                            <p class="about">{g.about_me or ""}</p>
                        </div>
                    </div>
                    {f'<div class="chips-container"><strong>Websites:</strong> {links_html}</div>' if links_html else ''}
                    {f'<div class="chips-container"><strong>Verified Accounts:</strong> {accounts_html}</div>' if accounts_html else ''}
                </div>
                """
            else:
                gravatar_card = '<div class="card"><p class="dim">No public Gravatar footprint found.</p></div>'

            pgp_rows = ""
            for k in email_report.pgp_keys:
                pgp_rows += f"<tr><td><code>{k.key_id}</code></td><td>{k.user_id}</td><td>{k.created_date}</td></tr>"

            pgp_table = f"""
            <div class="card">
                <h4>🔑 PGP Public Keys Found ({len(email_report.pgp_keys)})</h4>
                <table class="subtable">
                    <thead><tr><th>Key ID</th><th>User ID</th><th>Created</th></tr></thead>
                    <tbody>{pgp_rows}</tbody>
                </table>
            </div>
            """ if email_report.pgp_keys else ''

            # GitHub Connected Account Card
            github_card = ""
            if email_report.github.found:
                github_card = f"""
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <h4 style="color: #38bdf8; margin: 0;">🐙 Connected GitHub Account</h4>
                        <span class="chip" style="font-size: 11px;">{email_report.github.source}</span>
                    </div>
                    <div style="display: flex; gap: 14px; align-items: center;">
                        <img src="{email_report.github.avatar_url}" style="width: 52px; height: 52px; border-radius: 50%; border: 2px solid #38bdf8;" />
                        <div>
                            <div style="font-size: 16px; font-weight: 700;">{email_report.github.username}</div>
                            <a href="{email_report.github.profile_url}" target="_blank" class="url-link">{email_report.github.profile_url} ↗</a>
                        </div>
                    </div>
                </div>
                """

            # Mail Provider / Infrastructure Card
            provider_card = f"""
            <div class="card">
                <h4 style="margin-bottom: 8px;">🏢 Mail Infrastructure</h4>
                <div style="font-size: 14px; line-height: 1.6;">
                    <div>Domain: <strong>{email_report.domain}</strong></div>
                    <div>Provider: <strong style="color: #38bdf8;">{email_report.provider_info.provider}</strong></div>
                    {f'<div class="dim" style="font-size: 12px; margin-top: 4px;">MX: {email_report.provider_info.mx_records[0]}</div>' if email_report.provider_info.mx_records else ''}
                </div>
            </div>
            """

            email_html = f"""
            <section class="section">
                <h2>📧 Email Intelligence ({email_report.email})</h2>
                <div class="grid-2">
                    {breach_card}
                    {gravatar_card}
                    {github_card}
                    {provider_card}
                </div>
                {f'<div style="margin-top: 16px;">{pgp_table}</div>' if pgp_table else ''}
            </section>
            """

        # Phone section HTML
        phone_html = ""
        if phone_report and phone_report.is_valid:
            dork_chips = "".join([f'<a href="{d["url"]}" target="_blank" class="chip chip-dork">🔍 {d["title"]}</a> ' for d in phone_report.dork_links])
            chat_chips = "".join([f'<a href="{c["url"]}" target="_blank" class="chip chip-chat">💬 {c["name"]}</a> ' for c in phone_report.chat_links])

            phone_html = f"""
            <section class="section">
                <h2>📱 Phone Intelligence ({phone_report.international_format})</h2>
                <div class="grid-2">
                    <div class="card">
                        <table class="info-table">
                            <tr><th>Country:</th><td>{phone_report.country_name} ({phone_report.country_code})</td></tr>
                            <tr><th>Location:</th><td>{phone_report.location or "N/A"}</td></tr>
                            <tr><th>Carrier:</th><td><strong>{phone_report.carrier_name or "N/A"}</strong></td></tr>
                            <tr><th>Line Type:</th><td>{phone_report.line_type}</td></tr>
                            <tr><th>E.164:</th><td><code>{phone_report.e164_format}</code></td></tr>
                            <tr><th>Timezones:</th><td>{", ".join(phone_report.timezones)}</td></tr>
                        </table>
                    </div>
                    <div class="card">
                        <h4>Direct Actions & Chat</h4>
                        <div class="chips-container" style="margin-bottom: 15px;">{chat_chips}</div>
                        <h4>OSINT Dorks & Directories</h4>
                        <div class="chips-container">{dork_chips}</div>
                    </div>
                </div>
            </section>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Investigation Report - {target_name}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --primary: #38bdf8;
            --accent: #10b981;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{ font-size: 24px; color: var(--primary); margin-bottom: 6px; }}
        h2 {{ font-size: 20px; color: var(--text); margin-bottom: 16px; border-left: 4px solid var(--primary); padding-left: 10px; }}
        h3 {{ font-size: 18px; margin-bottom: 4px; }}
        h4 {{ font-size: 14px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 10px; }}
        .header-meta {{ color: var(--text-dim); font-size: 14px; }}
        .badge-count {{
            background-color: var(--accent);
            color: #000;
            font-weight: bold;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 16px;
        }}
        .section {{ margin-bottom: 35px; }}
        .card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media (max-width: 768px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--surface);
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: #0b1120; color: var(--text-dim); font-size: 13px; text-transform: uppercase; }}
        tr:hover {{ background-color: var(--surface-hover); }}
        .avatar {{ width: 36px; height: 36px; border-radius: 50%; object-fit: cover; margin-right: 12px; vertical-align: middle; }}
        .avatar-placeholder {{ width: 36px; height: 36px; border-radius: 50%; background: #334155; display: inline-flex; align-items: center; justify-content: center; margin-right: 12px; }}
        .platform-cell {{ display: flex; align-items: center; }}
        .page-title {{ display: block; font-size: 12px; color: var(--text-dim); }}
        .bio {{ font-size: 13px; color: #cbd5e1; max-width: 380px; }}
        .empty-bio {{ font-size: 12px; color: #64748b; font-style: italic; }}
        .url-link {{ color: var(--primary); text-decoration: none; word-break: break-all; font-size: 13px; }}
        .url-link:hover {{ text-decoration: underline; }}
        .latency {{ font-size: 12px; color: var(--text-dim); text-align: right; }}
        .badge {{ padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-coding {{ background: #0284c7; color: white; }}
        .badge-social {{ background: #059669; color: white; }}
        .badge-gaming {{ background: #7c3aed; color: white; }}
        .badge-tech {{ background: #d97706; color: white; }}
        .badge-music {{ background: #db2777; color: white; }}
        .badge-general {{ background: #475569; color: white; }}
        .gravatar-header {{ display: flex; gap: 16px; align-items: center; margin-bottom: 16px; }}
        .gravatar-img {{ width: 72px; height: 72px; border-radius: 50%; border: 2px solid var(--primary); }}
        .chip {{ display: inline-block; padding: 5px 10px; background: #334155; color: var(--text); border-radius: 6px; text-decoration: none; font-size: 12px; margin: 3px; }}
        .chip:hover {{ background: var(--primary); color: #000; }}
        .chip-dork {{ background: #1e3a8a; color: #93c5fd; }}
        .chip-chat {{ background: #065f46; color: #a7f3d0; }}
        .chip-breach {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .chip-hibp {{ background: #0284c7; color: #fff; font-weight: bold; text-decoration: none; }}
        .card-pwned {{ border-left: 4px solid #ef4444; background: rgba(239, 68, 68, 0.05); }}
        .card-clean {{ border-left: 4px solid #10b981; background: rgba(16, 185, 129, 0.05); }}
        .info-table td, .info-table th {{ padding: 6px 10px; border-bottom: 1px solid #293548; }}
        .info-table th {{ width: 120px; }}
        .dim {{ color: var(--text-dim); font-size: 14px; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            {header_avatar_html}
            {f'<div class="badge-count">{len(found_results)} Profiles Found</div>' if results else ''}
        </header>

        {email_html}
        {phone_html}

        {f'''
        <section class="section">
            <h2>🌐 Discovered Public Profiles ({len(found_results)} hits)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Platform</th>
                        <th>Category</th>
                        <th>Profile URL</th>
                        <th>Extracted Bio / Summary</th>
                        <th style="text-align: right;">Latency</th>
                    </tr>
                </thead>
                <tbody>
                    {profile_rows}
                </tbody>
            </table>
        </section>
        ''' if results else ''}
    </div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
