"""
OSINT Detective - Multi-Vector Digital Footprint & Username Hunter.
Supports Usernames, Emails, and Phone Numbers with HTML reporting.
"""

import argparse
import asyncio
from datetime import datetime
from pathlib import Path
import sys

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from core import SiteDatabase, UsernameScanner, ScanStatus, ScanResult
from modules import EmailScanner, EmailReport, PhoneScanner, PhoneReport
from utils import ResultsExporter, HTMLReporter

console = Console(legacy_windows=False)

BANNER = r"""[bold cyan]
   ____  _____ _____ _   _ _____   _   _ _   _ _   _ _____ _____ ____  
  / __ \/ ____|_   _| \ | |_   _| | | | | | | | \ | |_   _| ____|  _ \ 
 | |  | \__ \   | | |  \| | | |   | |_| | | | |  \| | | | |  _| | |_) |
 | |  | |___) | | | | |\  | | |   |  _  | |_| | |\  | | | | |___|  _ < 
  \____/|____/  |_| |_| \_| |_|   |_| |_|\___/|_| \_| |_| |_____|_| \_\
[/bold cyan]
[dim]Multi-Vector OSINT Reconnaissance: Usernames, Social, Emails & Phone Numbers[/dim]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="osint-hunter",
        description="Multi-Vector OSINT Reconnaissance: Usernames, Social, Emails & Phone Numbers"
    )
    parser.add_argument("-u", "--username", type=str, help="Target username to investigate")
    parser.add_argument("-e", "--email", type=str, help="Target email address for Gravatar/PGP lookup")
    parser.add_argument("-p", "--phone", type=str, help="Target phone number (e.g. +905321234567)")
    parser.add_argument("-c", "--category", type=str, help="Filter search by category (e.g. social, coding, gaming)")
    parser.add_argument("--concurrency", type=int, default=25, help="Concurrent HTTP requests (default: 25)")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout per site in seconds (default: 8.0)")
    parser.add_argument("-o", "--output", type=str, help="Custom export path prefix")
    parser.add_argument("--proxy", type=str, help="Optional HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--guide", action="store_true", help="Display full OSINT methodology guide & tips")
    parser.add_argument("--update-db", action="store_true", help="Download latest site list from WhatsMyName repo")
    parser.add_argument("--list-categories", action="store_true", help="List available site categories")
    return parser.parse_args()


async def _investigate_email(email: str) -> EmailReport:
    scanner = EmailScanner()
    return await scanner.scan(email)


def run_email_investigation(email: str) -> EmailReport:
    console.print(f"\n[bold yellow][*] Investigating email footprint for '{email}'...[/bold yellow]")
    report = asyncio.run(_investigate_email(email))

    # 1. Provider
    if report.provider_info.provider != "Unknown":
        console.print(f"[bold cyan][+] Mail Infrastructure:[/bold cyan] [bold white]{report.provider_info.provider}[/bold white] (Domain: {report.domain})")

    # 2. GitHub Connected Account
    if report.github.found:
        console.print(f"[bold green][+] Connected GitHub Account Detected![/bold green]")
        console.print(f"    • Username: [bold white]{report.github.username}[/bold white]")
        console.print(f"    • Profile URL: [cyan]{report.github.profile_url}[/cyan]")
        console.print(f"    • Source: [dim]{report.github.source}[/dim]")

    # 3. Gravatar Profile
    g = report.gravatar
    if g.exists:
        console.print("[bold green][+] Gravatar Profile Detected![/bold green]")
        if g.display_name:
            console.print(f"    • Display Name: [bold white]{g.display_name}[/bold white]")
        if g.preferred_username:
            console.print(f"    • Preferred Username: [cyan]{g.preferred_username}[/cyan]")
        if g.location:
            console.print(f"    • Location: [magenta]{g.location}[/magenta]")
        if g.about_me:
            console.print(f"    • Bio: [italic]{g.about_me}[/italic]")
        if g.avatar_url:
            console.print(f"    • Avatar: [dim]{g.avatar_url}[/dim]")
        for u in g.urls:
            console.print(f"    • Linked Site: [cyan]{u['title'] or u['value']}[/cyan] ({u['value']})")
        for a in g.verified_accounts:
            console.print(f"    • Verified Account: [magenta]{a['shortname']}[/magenta] -> {a['url']}")
    else:
        console.print("[dim][-] No public Gravatar profile found.[/dim]")

    # 4. Data Breaches
    b = report.breach
    if b.pwned:
        console.print(f"[bold red][!] DATA BREACH DETECTED: Leaked in {b.count} public security incidents![/bold red]")
        breach_sample = ", ".join(b.breaches[:8])
        if len(b.breaches) > 8:
            breach_sample += f" ... (+{len(b.breaches)-8} more)"
        console.print(f"    • Breaches: [yellow]{breach_sample}[/yellow]")
        console.print(f"    • Verify: [dim]{b.hibp_url}[/dim]")
    else:
        console.print("[bold green][✓] No public data breach records found for this email.[/bold green]")

    # 5. PGP Keys
    if report.pgp_keys:
        console.print(f"[bold green][+] Found {len(report.pgp_keys)} PGP Public Keys![/bold green]")
        for k in report.pgp_keys:
            console.print(f"    • Key ID: [cyan]{k.key_id}[/cyan] | User: [white]{k.user_id}[/white]")
    else:
        console.print("[dim][-] No public PGP keys registered on Ubuntu Keyserver.[/dim]")

    return report


def run_phone_investigation(phone: str) -> PhoneReport:
    console.print(f"\n[bold yellow][*] Analyzing phone number: '{phone}'...[/bold yellow]")
    scanner = PhoneScanner()
    report = scanner.analyze(phone)

    if not report.is_valid:
        console.print("[bold red][!] Invalid phone number format or unrecognized country code.[/bold red]")
        return report

    table = Table(title="Phone Number Intelligence", show_header=False, border_style="cyan")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Country", f"{report.country_name} (+{report.country_code})")
    table.add_row("Location", report.location or "N/A")
    table.add_row("Carrier", f"[bold green]{report.carrier_name or 'N/A'}[/bold green]")
    table.add_row("Line Type", report.line_type)
    table.add_row("E.164 Format", report.e164_format)
    table.add_row("Timezone(s)", ", ".join(report.timezones))

    console.print(table)

    console.print("[bold white]Direct Chat / Profiling Links:[/bold white]")
    for chat in report.chat_links:
        console.print(f"  • {chat['name']:<18}: [cyan]{chat['url']}[/cyan]")

    console.print("[bold white]Useful Google Dork Links:[/bold white]")
    for dork in report.dork_links[:3]:
        console.print(f"  • {dork['title']:<22}: [dim]{dork['url']}[/dim]")

    return report


async def _run_username_scan(args, username: str):
    db = SiteDatabase()

    try:
        sites = db.load(category_filter=args.category)
    except Exception as e:
        console.print(f"[bold red][!] Error loading site database: {e}[/bold red]")
        return []

    console.print(Panel(
        f"[bold white]Target Username:[/bold white] [bold green]{username}[/bold green]\n"
        f"[bold white]Target Sites:[/bold white] [cyan]{len(sites)} sites[/cyan]\n"
        f"[bold white]Concurrency:[/bold white] [magenta]{args.concurrency}[/magenta] workers\n"
        f"[bold white]Timeout:[/bold white] [magenta]{args.timeout}s[/magenta]",
        title="[bold cyan]Username Reconnaissance[/bold cyan]",
        border_style="cyan"
    ))

    scanner = UsernameScanner(
        sites=sites,
        concurrency=args.concurrency,
        timeout=args.timeout,
        proxy=args.proxy
    )

    found_results = []
    total_sites = len(sites)

    console.print("\n[bold cyan][*] Scanning platforms in parallel...[/bold cyan]\n")

    disable_progress = not console.is_terminal

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
        disable=disable_progress,
        transient=False
    ) as progress:
        scan_task = progress.add_task(f"[cyan]Scanning {total_sites} platforms...", total=total_sites)

        def handle_result(result: ScanResult):
            progress.advance(scan_task)
            if result.status == ScanStatus.FOUND:
                found_results.append(result)
                bio_snippet = f" - [italic dim]{result.bio[:60]}...[/italic dim]" if result.bio else ""
                console.print(
                    f"[bold green][+][/bold green] [bold white]{result.site.name:<16}[/bold white] "
                    f"([dim]{result.site.category}[/dim]) [cyan]{result.url}[/cyan] "
                    f"[dim]({result.response_time * 1000:.0f}ms)[/dim]{bio_snippet}"
                )

        all_results = await scanner.scan(username=username, on_result=handle_result)

    # Print summary
    console.print("\n")
    if found_results:
        summary_table = Table(
            title=f"Scan Summary for '{username}' ({len(found_results)} profiles found)",
            show_header=True,
            header_style="bold green"
        )
        summary_table.add_column("Platform", style="white", no_wrap=True)
        summary_table.add_column("Category", style="magenta")
        summary_table.add_column("Profile URL", style="cyan")
        summary_table.add_column("Extracted Bio / Summary", style="dim")
        summary_table.add_column("Latency", justify="right", style="dim")

        for res in sorted(found_results, key=lambda x: (x.site.category, x.site.name)):
            summary_table.add_row(
                res.site.name,
                res.site.category,
                res.url,
                (res.bio[:50] + "...") if res.bio else (res.title or "-"),
                f"{res.response_time * 1000:.0f} ms"
            )

        console.print(summary_table)
    else:
        console.print(f"[yellow][!] No public profiles found for '{username}'.[/yellow]")

    return all_results


def show_guide():
    console.print(Panel(
        "[bold white]OSINT DETECTIVE - METODOLOJİ VE KULLANIM REHBERİ[/bold white]\n\n"
        "[bold cyan]1. Kullanıcı Adı (Nickname) Taraması:[/bold cyan]\n"
        "   • WhatsMyName ve Sherlock imza tabanını kullanır. 692 sitede profil varlığını HTTP istekleriyle doğrular.\n"
        "   • Sayfa başlığı, Bio ve Avatar URL'lerini (OpenGraph) otomatik ayıklar.\n"
        "   • Yanlış pozitifleri önlemek için durum kodu ve m_string (bulunamadı metni) kontrol edilir.\n\n"
        "[bold cyan]2. E-posta Ayak İzi Analizi:[/bold cyan]\n"
        "   • E-postanın MD5 hash'i üretilerek Gravatar veritabanına sorulur.\n"
        "   • Varsa profil fotoğrafı, isim, konum, biyografi ve bağlı siteler çekilir.\n"
        "   • Ubuntu PGP Keyserver üzerinde kayıtlı açık anahtarlar listelenir.\n\n"
        "[bold cyan]3. Telefon Numarası İstihbaratı:[/bold cyan]\n"
        "   • Google phonenumbers ile ülke, operatör (Turkcell, Vodafone vb.) ve hat tipi belirlenir.\n"
        "   • WhatsApp ve Telegram direct profiling linkleri üretilir.\n"
        "   • Sızdırılmış verileri aramak için otomatik Google Dork URL'leri hazırlanır.\n\n"
        "[bold cyan]4. Raporlama:[/bold cyan]\n"
        "   • Her tarama sonrasında reports/ klasörüne JSON, CSV ve görsel HTML raporu kaydedilir.\n\n"
        "[bold yellow]Örnek Kullanımlar:[/bold yellow]\n"
        "   [dim]python main.py -u torvalds -c coding[/dim]\n"
        "   [dim]python main.py -u elonmusk -c social[/dim]\n"
        "   [dim]python main.py -u hedef -e hedef@mail.com -p +905321234567[/dim]\n"
        "   [dim]python web_app.py[/dim] (Web kontrol paneli)",
        title="[bold green]📖 OSINT Guide & Manual[/bold green]",
        border_style="green"
    ))


def main():
    args = parse_args()
    console.print(BANNER)

    if args.guide:
        show_guide()
        return

    # Handle database update
    if args.update_db:
        console.print("[yellow][*] Downloading latest signatures from WhatsMyName repository...[/yellow]")
        db = SiteDatabase()
        try:
            count = asyncio.run(db.update_from_remote())
            console.print(f"[bold green][+] Database updated successfully with {count} sites![/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Failed to update database: {e}[/bold red]")
        return

    # Handle list-categories
    if args.list_categories:
        db = SiteDatabase()
        categories = {}
        for s in db.load():
            categories[s.category] = categories.get(s.category, 0) + 1

        table = Table(title="Available Site Categories", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Site Count", justify="right", style="green")

        for cat, cnt in sorted(categories.items()):
            table.add_row(cat, str(cnt))

        console.print(table)
        return

    username = args.username
    email = args.email
    phone = args.phone

    # Interactive input if no flags provided
    if not any([username, email, phone]):
        if not sys.stdin.isatty():
            console.print("[bold red][!] Please specify at least one target: -u <username>, -e <email>, or -p <phone>[/bold red]")
            return

        console.print("[bold cyan]Investigation Targets (leave blank to skip):[/bold cyan]")
        try:
            username = console.input("[yellow]Target Username:[/yellow] ").strip() or None
            email = console.input("[yellow]Target Email:   [/yellow] ").strip() or None
            phone = console.input("[yellow]Target Phone:   [/yellow] ").strip() or None
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Aborted by user.[/dim]")
            return

    if not any([username, email, phone]):
        console.print("[bold red][!] No target specified. Exiting.[/bold red]")
        return

    email_report = None
    phone_report = None
    scan_results = []

    # 1. Run Phone Analysis if provided
    if phone:
        phone_report = run_phone_investigation(phone)

    # 2. Run Email Analysis if provided
    if email:
        email_report = run_email_investigation(email)
        # Auto-derive username if user didn't specify one!
        if not username and email_report.suggested_usernames:
            username = email_report.suggested_usernames[0]
            console.print(f"\n[bold cyan][*] Auto-derived Nickname from Email: '[bold green]{username}[/bold green]'[/bold cyan]")
            console.print("[dim]    Scanning 690+ platforms for accounts matching this handle...[/dim]\n")

    # 3. Run Username Scan if provided (or auto-derived)
    if username:
        scan_results = asyncio.run(_run_username_scan(args, username))

    # Save reports
    target_tag = username or (email.split('@')[0] if email else "target")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    base_name = args.output or f"reports/{target_tag}_{timestamp}"
    json_path = Path(f"{base_name}.json")
    csv_path = Path(f"{base_name}.csv")
    html_path = Path(f"{base_name}.html")

    if scan_results:
        ResultsExporter.to_json(scan_results, target_tag, json_path)
        ResultsExporter.to_csv(scan_results, target_tag, csv_path)

    # Always generate HTML report
    HTMLReporter.generate(
        username=username,
        results=scan_results,
        email_report=email_report,
        phone_report=phone_report,
        output_path=html_path
    )

    console.print(f"\n[bold green][+] Reports saved successfully:[/bold green]")
    if scan_results:
        console.print(f"    • JSON: [cyan]{json_path}[/cyan]")
        console.print(f"    • CSV:  [cyan]{csv_path}[/cyan]")
    console.print(f"    • HTML: [bold green]{html_path}[/bold green] (Open in browser)\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Investigation aborted by user.[/yellow]")
