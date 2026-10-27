# OSINT Detective - Multi-Vector Footprint & Reconnaissance Suite

Fast, asynchronous OSINT reconnaissance engine inspired by WhatsMyName and HaveIBeenPwned. Built with Python 3, `httpx`, `asyncio`, `rich`, `phonenumbers`, and `beautifulsoup4`.

---

## 🚀 Features

- **Blazing Fast Username Scanner**: Asynchronously inspects **690+ platforms** (including 196 social media networks like X, TikTok, Pinterest, Telegram, Reddit, Snapchat, Linktree) in seconds.
- **Profile Metadata & Bio Harvester**: Extracts OpenGraph meta tags (`og:title`, `og:description` / bio, and `og:image` / avatar) from discovered profiles.
- **Data Breach Intelligence (HaveIBeenPwned & XposedOrNot)**:
  - Checks if an email address was leaked in major public database breaches and security incidents.
  - Returns breach names, counts, and verification links.
- **Email Identity (Gravatar & PGP)**:
  - **Gravatar Footprint**: Derives MD5 hash, discovers display name, preferred username, bio, location, linked personal websites, and avatars.
  - **PGP Keyservers**: Discovers public cryptographic identity keys registered on Ubuntu/MIT keyservers.
- **Phone Number Analysis**:
  - Carrier identification (Turkcell, Vodafone, AT&T, etc.) and line type (Mobile, Fixed Line, VOIP).
  - Country, region, and international E.164 formats.
  - One-click direct chat links (WhatsApp, Telegram) and pre-built Google OSINT dorks.
- **Multi-Format Reporting**:
  - Standalone **Visual HTML Report** (dark mode, interactive, embedded cards and tables).
  - Formatted **JSON** and **CSV** exports.
- **Multi-Threaded Web Dashboard**:
  - Built-in, interactive web UI at `http://127.0.0.1:8080` (`python web_app.py` or double-clicking `start_web.bat`).
  - Zero external server dependencies required.

---

## 📦 Installation

Ensure Python 3.10+ is installed:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage Examples

### 1. Interactive Mode
Run without arguments to enter target information interactively:
```bash
python main.py
```

### 2. Multi-Vector Investigation (Username + Email + Phone)
```bash
python main.py -u torvalds -e torvalds@linux-foundation.org -p +905321234567
```

### 3. Data Breach & Email Intelligence Only
```bash
python main.py -e test@example.com
```

### 4. Targeted Category Scan (e.g. Social Media Only)
```bash
python main.py -u elonmusk -c social
```

### 5. Phone Number Analysis Only
```bash
python main.py -p +905321234567
```

### 6. Launch Web Dashboard
Double click `start_web.bat` or run:
```bash
python web_app.py
```

### 7. Update Signature Database
Fetch the latest 690+ website signatures directly from the WhatsMyName repository:
```bash
python main.py --update-db
```

---

## 📂 Project Architecture

```
osint/
├── core/
│   ├── models.py       # Data classes (SiteDefinition, ScanResult, ScanStatus)
│   ├── database.py     # Signature loader & remote WhatsMyName updater
│   └── scanner.py      # Async HTTP scanning engine & metadata extractor
├── modules/
│   ├── email_scanner.py # Gravatar MD5, PGP keys, & XposedOrNot/HIBP breach analyzer
│   └── phone_scanner.py # Phone carrier, geocoder, chat & dork generator
├── utils/
│   ├── exporter.py     # JSON and CSV export utility
│   └── html_reporter.py # Standalone dark-mode HTML report generator
├── data/
│   └── sites.json      # 692 site signatures with category tags
├── reports/            # Generated HTML, JSON, and CSV reports (git-ignored)
├── main.py             # Rich CLI entrypoint
├── web_app.py          # Interactive web UI (http://127.0.0.1:8080)
├── start_cli.bat       # 1-Click CLI launcher
├── start_web.bat       # 1-Click Web dashboard launcher
├── requirements.txt    # Project dependencies
└── README.md
```
