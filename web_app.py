"""
Modern Web Dashboard for OSINT Detective.
Runs a local, interactive web UI at http://127.0.0.1:8080 (or next free port).
Uses multi-threaded ThreadingHTTPServer so scans never lock or freeze connections.
"""

import asyncio
from datetime import datetime
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import socket
import sys
import threading
import urllib.parse
import webbrowser

from core import SiteDatabase, UsernameScanner, ScanStatus
from modules import EmailScanner, PhoneScanner
from utils import HTMLReporter, ResultsExporter

DEFAULT_PORT = 8080

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Detective - Reconnaissance Suite</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --border: #374151;
            --border-focus: #38bdf8;
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.15);
            --accent: #10b981;
            --accent-glow: rgba(16, 185, 129, 0.15);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.12);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .logo-area { display: flex; align-items: center; gap: 14px; }
        .logo-icon {
            font-size: 28px;
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--border);
            padding: 10px;
            border-radius: 12px;
        }
        h1 { font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
        .subtitle { font-size: 13px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .header-actions { display: flex; align-items: center; gap: 12px; }
        .badge-live {
            background: var(--accent-glow);
            color: var(--accent);
            border: 1px solid var(--accent);
            font-size: 12px;
            font-weight: 600;
            padding: 6px 14px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .pulse { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 8px var(--accent); }
        .btn-help {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }
        .btn-help:hover { border-color: var(--primary); color: var(--primary); }
        .search-panel {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 28px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }
        .inputs-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
            margin-bottom: 18px;
        }
        .input-group label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .input-group input, .input-group select {
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: #fff;
            padding: 12px 14px;
            border-radius: 10px;
            font-size: 14px;
            outline: none;
            transition: all 0.2s;
            font-family: inherit;
        }
        .input-group input:focus, .input-group select:focus {
            border-color: var(--border-focus);
            box-shadow: 0 0 0 3px var(--primary-glow);
        }
        .btn-scan {
            width: 100%;
            background: linear-gradient(135deg, #0284c7, #0369a1);
            color: #fff;
            border: none;
            padding: 14px;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .btn-scan:hover { background: linear-gradient(135deg, #0369a1, #075985); }
        .btn-scan:disabled { opacity: 0.5; cursor: not-allowed; }
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 28px;
        }
        @media (max-width: 768px) { .stats-bar { grid-template-columns: 1fr 1fr; } }
        .stat-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            padding: 16px 20px;
            border-radius: 12px;
        }
        .stat-val { font-size: 26px; font-weight: 700; color: var(--primary); font-family: 'JetBrains Mono', monospace; }
        .stat-lbl { font-size: 12px; color: var(--text-muted); text-transform: uppercase; margin-top: 2px; }
        .results-section { display: none; margin-bottom: 40px; }
        .intel-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }
        @media (max-width: 900px) { .intel-grid { grid-template-columns: 1fr; } }
        .intel-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }
        .intel-card-breach { border-left: 4px solid var(--danger); background: var(--danger-bg); }
        .intel-card-clean { border-left: 4px solid var(--accent); background: rgba(16, 185, 129, 0.08); }
        .intel-title { font-size: 16px; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
        .profiles-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 16px;
        }
        .profile-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: transform 0.2s, border-color 0.2s;
        }
        .profile-card:hover { transform: translateY(-2px); border-color: var(--primary); }
        .profile-top { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
        .profile-avatar { width: 44px; height: 44px; border-radius: 50%; object-fit: cover; background: #374151; }
        .platform-name { font-weight: 700; font-size: 15px; color: #fff; }
        .cat-badge {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 12px;
            background: #374151;
            color: var(--primary);
            text-transform: uppercase;
            font-weight: 600;
        }
        .profile-bio { font-size: 13px; color: var(--text-muted); line-height: 1.4; margin-bottom: 12px; flex-grow: 1; }
        .profile-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.06);
        }
        .profile-link {
            color: var(--primary);
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .profile-link:hover { text-decoration: underline; }
        .latency-tag { font-size: 11px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .progress-bar-wrap {
            height: 6px;
            background: var(--bg-card);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 14px;
            display: none;
        }
        .progress-bar { height: 100%; width: 0%; background: linear-gradient(90deg, #38bdf8, #10b981); transition: width 0.3s; }
        .downloads-bar {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            align-items: center;
            flex-wrap: wrap;
        }
        .btn-download {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: #fff;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
        }
        .btn-download:hover { border-color: var(--primary); background: #374151; }
        .chip { display: inline-block; padding: 4px 8px; background: #1f2937; color: #fff; border-radius: 6px; text-decoration: none; font-size: 12px; margin: 2px; }
        .chip:hover { background: var(--primary); color: #000; }
        .chip-breach { background: rgba(239, 68, 68, 0.25); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
        .chip-hibp { background: #0284c7; color: #fff; font-weight: 600; }

        /* Modal Styles */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .modal-box {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            max-width: 800px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            display: flex;
            flex-direction: column;
        }
        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-title { font-size: 18px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
        .btn-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
            padding: 4px;
        }
        .btn-close:hover { color: #fff; }
        .modal-body { padding: 24px; font-size: 14px; line-height: 1.6; }
        .modal-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            flex-wrap: wrap;
        }
        .modal-tab {
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 6px 14px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.2s;
        }
        .modal-tab.active { background: var(--bg-card); color: var(--primary); }
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        .guide-step { margin-bottom: 18px; }
        .guide-step h4 { color: var(--primary); margin-bottom: 4px; font-size: 15px; }
        .guide-code {
            background: #080c14;
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #38bdf8;
            margin: 6px 0;
            display: block;
        }
        .tip-box {
            background: rgba(56, 189, 248, 0.08);
            border-left: 3px solid var(--primary);
            padding: 10px 14px;
            border-radius: 4px;
            margin: 12px 0;
            font-size: 13px;
        }
        .warning-box {
            background: rgba(239, 68, 68, 0.08);
            border-left: 3px solid var(--danger);
            padding: 10px 14px;
            border-radius: 4px;
            margin: 12px 0;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <div class="logo-icon">🕵️</div>
                <div>
                    <h1>OSINT Detective</h1>
                    <div class="subtitle">Multi-Vector Digital Reconnaissance Suite</div>
                </div>
            </div>
            <div class="header-actions">
                <button type="button" class="btn-help" onclick="openHelpModal()">
                    <span>📖 Yardım & Rehber</span>
                </button>
                <div class="badge-live">
                    <span class="pulse"></span>
                    <span>Ready • 692 Sites Indexed</span>
                </div>
            </div>
        </header>

        <section class="search-panel">
            <form id="scanForm" onsubmit="handleScan(event)">
                <div class="inputs-grid">
                    <div class="input-group">
                        <label>Target Username / Nickname</label>
                        <input type="text" id="username" placeholder="e.g. torvalds, elonmusk" />
                    </div>
                    <div class="input-group">
                        <label>Target Email Address</label>
                        <input type="email" id="email" placeholder="e.g. user@example.com" />
                    </div>
                    <div class="input-group">
                        <label>Target Phone Number</label>
                        <input type="text" id="phone" placeholder="e.g. +905321234567" />
                    </div>
                    <div class="input-group">
                        <label>Category Filter</label>
                        <select id="category">
                            <option value="">All Categories (690+ Sites)</option>
                            <option value="social">Social Media (196 Sites - X, TikTok, IG, Pinterest)</option>
                            <option value="coding">Coding & Tech (46 Sites - GitHub, GitLab, Docker)</option>
                            <option value="gaming">Gaming Platforms (69 Sites - Steam, Twitch, Chess)</option>
                            <option value="music">Music & Audio (23 Sites - Spotify, SoundCloud)</option>
                            <option value="finance">Finance & Crypto (26 Sites)</option>
                            <option value="art">Design & Art (13 Sites - Behance, Dribbble)</option>
                        </select>
                    </div>
                </div>
                <button type="submit" id="btnSubmit" class="btn-scan">
                    <span>⚡ Launch Parallel Reconnaissance</span>
                </button>
                <div class="progress-bar-wrap" id="progWrap">
                    <div class="progress-bar" id="progBar"></div>
                </div>
            </form>
        </section>

        <div class="stats-bar" id="statsBar" style="display: none;">
            <div class="stat-card">
                <div class="stat-val" id="statHits">0</div>
                <div class="stat-lbl">Profiles Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" id="statScanned">0</div>
                <div class="stat-lbl">Platforms Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" id="statBreach">Clean</div>
                <div class="stat-lbl">Data Breach (HIBP)</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" id="statPhone">-</div>
                <div class="stat-lbl">Carrier / Country</div>
            </div>
        </div>

        <section class="results-section" id="resultsSection">
            <!-- Target Identity Banner -->
            <div id="targetBanner" style="display:flex; align-items:center; gap:20px; background:var(--bg-surface); border:1px solid var(--border); border-radius:14px; padding:20px; margin-bottom:24px;">
                <img id="targetAvatarImg" style="width:80px; height:80px; border-radius:50%; object-fit:cover; border:3px solid var(--primary); background:#1e293b;" />
                <div>
                    <h2 id="targetTitle" style="font-size:20px; font-weight:700; color:#fff;"></h2>
                    <div id="targetSubtitle" style="font-size:13px; color:var(--text-muted); margin-top:2px;"></div>
                    <div id="targetBadge" style="margin-top:8px;"></div>
                </div>
            </div>

            <div class="downloads-bar">
                <strong style="font-size: 14px; margin-right: 8px;">Export Reports:</strong>
                <a id="btnHtml" target="_blank" class="btn-download">📄 View Full HTML Report</a>
                <a id="btnJson" target="_blank" class="btn-download">💾 Download JSON</a>
            </div>

            <div class="intel-grid" id="intelGrid">
                <!-- Injected dynamically: Breach card, Gravatar card & Phone card -->
            </div>

            <h2 style="font-size: 18px; margin-bottom: 16px;">🌐 Discovered Public Profiles</h2>
            <div class="profiles-grid" id="profilesGrid"></div>
        </section>
    </div>

    <!-- Help & Guide Modal -->
    <div class="modal-overlay" id="helpModal" onclick="closeHelpOnBackdrop(event)">
        <div class="modal-box">
            <div class="modal-header">
                <div class="modal-title">📖 OSINT Detective Kullanım Rehberi & Yardım</div>
                <button type="button" class="btn-close" onclick="closeHelpModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-tabs">
                    <button class="modal-tab active" onclick="switchTab('tab-start', this)">🚀 Başlarken</button>
                    <button class="modal-tab" onclick="switchTab('tab-features', this)">🔍 Nasıl Çalışır?</button>
                    <button class="modal-tab" onclick="switchTab('tab-breach', this)">⚠️ Veri İhlali (HIBP)</button>
                    <button class="modal-tab" onclick="switchTab('tab-cli', this)">💻 Terminal / CLI</button>
                    <button class="modal-tab" onclick="switchTab('tab-tips', this)">💡 Arama İpuçları</button>
                    <button class="modal-tab" onclick="switchTab('tab-legal', this)">⚖️ Etik & Yasal</button>
                </div>

                <!-- Tab 1: Başlarken -->
                <div class="tab-pane active" id="tab-start">
                    <div class="guide-step">
                        <h4>1. Arama Formu Kullanımı</h4>
                        <p>Kullanıcı adı, e-posta veya telefon numarası alanlarından birini veya hepsini doldurabilirsiniz.</p>
                    </div>
                    <div class="guide-step">
                        <h4>2. Kategori Filtresi ile Hız Kazanın</h4>
                        <p>Sadece sosyal medya sitelerini aramak istiyorsanız Kategori açılır menüsünden <strong>Social Media</strong> seçeneğini belirleyebilirsiniz.</p>
                    </div>
                </div>

                <!-- Tab 2: Nasıl Çalışır? -->
                <div class="tab-pane" id="tab-features">
                    <div class="guide-step">
                        <h4>🌐 Asenkron İmza Taraması</h4>
                        <p>WhatsMyName açık veri tabanını kullanarak 690'dan fazla sitede profil varlığını kontrol eder.</p>
                    </div>
                    <div class="guide-step">
                        <h4>📧 Gravatar ve PGP Açık Anahtarları</h4>
                        <p>E-postanın MD5 hash'i ile Gravatar'daki genel profil, avatar ve Ubuntu Keyserver üzerindeki açık PGP anahtarları çekilir.</p>
                    </div>
                </div>

                <!-- Tab 3: Veri İhlali -->
                <div class="tab-pane" id="tab-breach">
                    <div class="guide-step">
                        <h4>⚠️ Veri İhlali (HaveIBeenPwned & XposedOrNot) Tespiti</h4>
                        <p>Bir e-posta adresi girildiğinde, sistem ücretsiz XposedOrNot ve HaveIBeenPwned veritabanları üzerinden e-postanın geçmişteki büyük veri sızıntılarında (LinkedIn, Adobe, Canva, Zynga vb.) yer alıp almadığını kontrol eder.</p>
                    </div>
                </div>

                <!-- Tab 4: CLI -->
                <div class="tab-pane" id="tab-cli">
                    <p>Terminal üzerinden doğrudan çalıştırmak için:</p>
                    <span class="guide-code">python main.py -u hedef_kullanici</span>
                    <span class="guide-code">python main.py -e hedef@example.com</span>
                    <span class="guide-code">python main.py -p +905321234567</span>
                </div>

                <!-- Tab 5: İpuçları -->
                <div class="tab-pane" id="tab-tips">
                    <p>Hedef kullanıcının farklı platformlarda kullanabileceği nokta (<code>.</code>) veya alt tire (<code>_</code>) içeren varyasyonlarını ayrı ayrı deneyebilirsiniz.</p>
                </div>

                <!-- Tab 6: Yasal Uyarı -->
                <div class="tab-pane" id="tab-legal">
                    <div class="warning-box">
                        <strong>Yasal & Etik Sorumluluk Reddi:</strong><br>
                        Bu araç yalnızca açık kaynaklı ve kamuya açık genel web verilerini (OSINT) güvenlik araştırmaları, dijital ayak izi analizi ve eğitim amaçlarıyla derlemek için tasarlanmıştır. Kullanıcı gerçekleştirdiği tüm işlemlerden kendisi sorumludur.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function openHelpModal() {
            document.getElementById('helpModal').style.display = 'flex';
        }
        function closeHelpModal() {
            document.getElementById('helpModal').style.display = 'none';
        }
        function closeHelpOnBackdrop(e) {
            if (e.target.id === 'helpModal') closeHelpModal();
        }
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.modal-tab').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        async function handleScan(e) {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const phone = document.getElementById('phone').value.trim();
            const category = document.getElementById('category').value;

            if (!username && !email && !phone) {
                alert('Please enter at least a username, email, or phone number!');
                return;
            }

            const btn = document.getElementById('btnSubmit');
            const progWrap = document.getElementById('progWrap');
            const progBar = document.getElementById('progBar');
            const statsBar = document.getElementById('statsBar');
            const resultsSection = document.getElementById('resultsSection');
            const profilesGrid = document.getElementById('profilesGrid');
            const intelGrid = document.getElementById('intelGrid');

            btn.disabled = true;
            btn.innerHTML = '<span>⏳ Scanning Platforms in Parallel...</span>';
            progWrap.style.display = 'block';
            progBar.style.width = '35%';

            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, phone, category })
                });

                if (!resp.ok) {
                    throw new Error(`Server returned status ${resp.status}`);
                }

                progBar.style.width = '80%';
                const data = await resp.json();
                progBar.style.width = '100%';

                // Render Stats
                statsBar.style.display = 'grid';
                document.getElementById('statHits').textContent = data.found_count || 0;
                document.getElementById('statScanned').textContent = data.total_scanned || 0;

                const breachFound = (data.email_report && data.email_report.breach && data.email_report.breach.pwned);
                const statBreachEl = document.getElementById('statBreach');
                if (breachFound) {
                    statBreachEl.textContent = `${data.email_report.breach.count} Breaches`;
                    statBreachEl.style.color = '#ef4444';
                } else if (data.email_report) {
                    statBreachEl.textContent = 'Clean';
                    statBreachEl.style.color = '#10b981';
                } else {
                    statBreachEl.textContent = '-';
                    statBreachEl.style.color = 'var(--primary)';
                }

                document.getElementById('statPhone').textContent = (data.phone_report && data.phone_report.carrier_name) ? data.phone_report.carrier_name : (data.phone_report ? data.phone_report.country_name : '-');

                // Render Target Banner
                const targetTitle = document.getElementById('targetTitle');
                const targetSubtitle = document.getElementById('targetSubtitle');
                const targetAvatarImg = document.getElementById('targetAvatarImg');
                const targetBadge = document.getElementById('targetBadge');

                targetTitle.textContent = data.target || 'Target';
                let subText = [];
                if (data.email_report) subText.push(`Email: ${data.email_report.email}`);
                if (data.phone_report && data.phone_report.international_format) subText.push(`Phone: ${data.phone_report.international_format}`);
                targetSubtitle.textContent = subText.join(' • ') || 'Reconnaissance Target';

                if (data.target_avatar) {
                    targetAvatarImg.src = data.target_avatar;
                    targetBadge.innerHTML = `<span class="chip" style="background:#0284c7; color:#fff; font-size:11px;">📸 Photo Source: ${data.avatar_source}</span>`;
                } else {
                    targetAvatarImg.src = `https://ui-avatars.com/api/?name=${encodeURIComponent(data.target || 'Target')}&background=1e293b&color=38bdf8&size=160`;
                    targetBadge.innerHTML = `<span class="chip" style="background:#1f2937; color:#94a3b8; font-size:11px;">No public photo found on Gravatar, GitHub, or social profiles</span>`;
                }

                // Render Downloads
                if (data.report_files) {
                    document.getElementById('btnHtml').href = data.report_files.html;
                    document.getElementById('btnJson').href = data.report_files.json;
                }

                // Render Intel Cards
                intelGrid.innerHTML = '';

                // Data Breach Card
                if (data.email_report && data.email_report.breach) {
                    const b = data.email_report.breach;
                    if (b.pwned) {
                        const breachChips = (b.breaches || []).slice(0, 15).map(br => `<span class="chip chip-breach">🚨 ${br}</span>`).join('');
                        const moreTxt = (b.breaches && b.breaches.length > 15) ? `<span style="color:var(--text-muted);font-size:12px;"> +${b.breaches.length - 15} more</span>` : '';

                        intelGrid.innerHTML += `
                            <div class="intel-card intel-card-breach">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                                    <div class="intel-title" style="color: #ef4444; margin:0;">⚠️ Data Breach Detected (${b.count} Incidents)</div>
                                    <a href="${b.hibp_url}" target="_blank" class="chip chip-hibp">HaveIBeenPwned ↗</a>
                                </div>
                                <p style="font-size:13px; color:#cbd5e1; margin-bottom:10px;">This email was found exposed in public security incidents and database leaks:</p>
                                <div>${breachChips}${moreTxt}</div>
                            </div>
                        `;
                    } else {
                        intelGrid.innerHTML += `
                            <div class="intel-card intel-card-clean">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <div class="intel-title" style="color: #10b981; margin:0;">✅ No Public Data Breaches Found</div>
                                    <a href="${b.hibp_url}" target="_blank" class="chip chip-hibp">HaveIBeenPwned ↗</a>
                                </div>
                                <p style="font-size:13px; color:var(--text-muted); margin-top:8px;">No public security breach records detected for this email.</p>
                            </div>
                        `;
                    }
                }

                // Gravatar Card
                if (data.email_report && data.email_report.gravatar && data.email_report.gravatar.exists) {
                    const g = data.email_report.gravatar;
                    const links = (g.urls || []).map(u => `<a href="${u.value}" target="_blank" class="chip">${u.title || u.value}</a>`).join('');
                    const accs = (g.verified_accounts || []).map(a => `<a href="${a.url}" target="_blank" class="chip">${a.shortname}</a>`).join('');

                    intelGrid.innerHTML += `
                        <div class="intel-card">
                            <div class="intel-title">📧 Gravatar Identity Profile</div>
                            <div style="display: flex; gap: 14px; align-items: center; margin-bottom: 12px;">
                                <img src="${g.avatar_url}" style="width: 56px; height: 56px; border-radius: 50%;" />
                                <div>
                                    <div style="font-weight: 700; font-size: 16px;">${g.display_name || g.preferred_username || 'Profile'}</div>
                                    <div style="font-size: 13px; color: var(--text-muted);">📍 ${g.location || 'Location unlisted'}</div>
                                </div>
                            </div>
                            ${g.about_me ? `<p style="font-size: 13px; color: var(--text-muted); margin-bottom: 10px;">${g.about_me}</p>` : ''}
                            ${links ? `<div style="margin-top: 8px;"><strong>Sites:</strong> ${links}</div>` : ''}
                            ${accs ? `<div style="margin-top: 8px;"><strong>Linked:</strong> ${accs}</div>` : ''}
                        </div>
                    `;
                }

                // Connected GitHub Account Card
                if (data.email_report && data.email_report.github && data.email_report.github.found) {
                    const gh = data.email_report.github;
                    intelGrid.innerHTML += `
                        <div class="intel-card">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                                <div class="intel-title" style="color: #38bdf8; margin:0;">🐙 Connected GitHub Account</div>
                                <span class="chip" style="font-size:11px;">${gh.source}</span>
                            </div>
                            <div style="display:flex; gap:14px; align-items:center;">
                                <img src="${gh.avatar_url}" style="width:52px; height:52px; border-radius:50%; border:2px solid #38bdf8;" />
                                <div>
                                    <div style="font-weight:700; font-size:16px;">${gh.username}</div>
                                    <a href="${gh.profile_url}" target="_blank" class="profile-link">Visit GitHub Profile ↗</a>
                                </div>
                            </div>
                        </div>
                    `;
                }

                // Mail Infrastructure Card
                if (data.email_report && data.email_report.provider && data.email_report.provider !== "Unknown") {
                    intelGrid.innerHTML += `
                        <div class="intel-card">
                            <div class="intel-title">🏢 Mail Infrastructure</div>
                            <div style="font-size:14px; line-height:1.6;">
                                <div>Domain: <strong>${data.email_report.domain}</strong></div>
                                <div>Provider: <strong style="color: #38bdf8;">${data.email_report.provider}</strong></div>
                                ${data.email_report.mx_records && data.email_report.mx_records.length ? `<div style="font-size:12px; color:var(--text-muted); margin-top:4px;">MX: ${data.email_report.mx_records[0]}</div>` : ''}
                            </div>
                        </div>
                    `;
                }

                // Phone Card
                if (data.phone_report && data.phone_report.is_valid) {
                    const p = data.phone_report;
                    const dorks = (p.dork_links || []).slice(0, 3).map(d => `<a href="${d.url}" target="_blank" class="chip">🔍 ${d.title}</a>`).join('');
                    const chats = (p.chat_links || []).map(c => `<a href="${c.url}" target="_blank" class="chip">💬 ${c.name}</a>`).join('');

                    intelGrid.innerHTML += `
                        <div class="intel-card">
                            <div class="intel-title">📱 Phone Line Intelligence</div>
                            <div style="font-size: 14px; margin-bottom: 10px;">
                                <div>Country: <strong>${p.country_name} (+${p.country_code})</strong></div>
                                <div>Carrier: <strong>${p.carrier_name || 'Unknown'}</strong> (${p.line_type})</div>
                                <div>Format: <code>${p.international_format}</code></div>
                            </div>
                            <div style="margin-top: 10px;"><strong>Direct Chat:</strong> ${chats}</div>
                            <div style="margin-top: 10px;"><strong>Dorks:</strong> ${dorks}</div>
                        </div>
                    `;
                }

                // Render Profile Cards
                profilesGrid.innerHTML = '';
                if (data.matches && data.matches.length > 0) {
                    data.matches.forEach(m => {
                        const avatarHtml = m.avatar_url ? `<img src="${m.avatar_url}" class="profile-avatar" />` : `<div class="profile-avatar" style="display:flex;align-items:center;justify-content:center;font-size:20px;">🌐</div>`;
                        const bioHtml = m.bio ? `<p class="profile-bio">${m.bio}</p>` : `<p class="profile-bio" style="font-style:italic;">No bio available</p>`;

                        profilesGrid.innerHTML += `
                            <div class="profile-card">
                                <div>
                                    <div class="profile-top">
                                        ${avatarHtml}
                                        <div>
                                            <div class="platform-name">${m.site}</div>
                                            <span class="cat-badge">${m.category}</span>
                                        </div>
                                    </div>
                                    ${bioHtml}
                                </div>
                                <div class="profile-footer">
                                    <a href="${m.url}" target="_blank" class="profile-link">Visit Profile ↗</a>
                                    <span class="latency-tag">${m.response_time_ms} ms</span>
                                </div>
                            </div>
                        `;
                    });
                } else if (username) {
                    profilesGrid.innerHTML = '<p style="color: var(--text-muted); font-style: italic;">No public profiles found for this query.</p>';
                } else {
                    profilesGrid.innerHTML = '';
                }

                resultsSection.style.display = 'block';

            } catch (err) {
                alert('Scan error: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<span>⚡ Launch Parallel Reconnaissance</span>';
                progWrap.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""


class OSINTRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]} {args[1]}\n")

    def do_GET(self):
        url_path = urllib.parse.urlparse(self.path).path

        if url_path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
            return

        if url_path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # Serve static reports
        if url_path.startswith("/reports/"):
            filename = url_path.replace("/reports/", "")
            file_path = Path("reports") / filename
            if file_path.exists() and file_path.is_file():
                content_type = "text/html; charset=utf-8" if filename.endswith(".html") else "application/json"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        if self.path == "/api/scan":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8")
                data = json.loads(body)

                username = data.get("username", "").strip() or None
                email = data.get("email", "").strip() or None
                phone = data.get("phone", "").strip() or None
                category = data.get("category", "").strip() or None

                # Execute investigation in a separate event loop
                result_payload = asyncio.run(self._execute_investigation(username, email, phone, category))

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(result_payload, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    async def _execute_investigation(self, username, email, phone, category):
        scan_results = []
        email_report = None
        phone_report = None

        # 1. Phone
        if phone:
            p_scanner = PhoneScanner()
            phone_report = p_scanner.analyze(phone)

        # 2. Email
        if email:
            e_scanner = EmailScanner()
            email_report = await e_scanner.scan(email)
            # Auto-derive username if user didn't specify one!
            if not username and email_report.suggested_usernames:
                username = email_report.suggested_usernames[0]

        # 3. Username
        if username:
            db = SiteDatabase()
            sites = db.load(category_filter=category)
            u_scanner = UsernameScanner(sites=sites, concurrency=30, timeout=7.0)
            scan_results = await u_scanner.scan(username=username)

        # Save reports
        target_tag = username or (email.split('@')[0] if email else "target")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        base_name = f"reports/{target_tag}_{timestamp}"
        json_path = Path(f"{base_name}.json")
        html_path = Path(f"{base_name}.html")

        if scan_results:
            ResultsExporter.to_json(scan_results, target_tag, json_path)

        HTMLReporter.generate(
            username=username,
            results=scan_results,
            email_report=email_report,
            phone_report=phone_report,
            output_path=html_path
        )

        found = [
            {
                "site": r.site.name,
                "category": r.site.category,
                "url": r.url,
                "http_status": r.http_status,
                "response_time_ms": round(r.response_time * 1000),
                "title": r.title,
                "bio": r.bio,
                "avatar_url": r.avatar_url
            }
            for r in scan_results if r.status == ScanStatus.FOUND
        ]

        # Resolve primary target avatar
        target_avatar = None
        avatar_source = None
        if email_report and email_report.resolved_avatar_url:
            target_avatar = email_report.resolved_avatar_url
            avatar_source = email_report.avatar_source
        else:
            for r in scan_results:
                if r.status == ScanStatus.FOUND and r.avatar_url:
                    target_avatar = r.avatar_url
                    avatar_source = f"{r.site.name} Profile"
                    break

        resp = {
            "target": target_tag,
            "target_avatar": target_avatar,
            "avatar_source": avatar_source,
            "total_scanned": len(scan_results),
            "found_count": len(found),
            "matches": found,
            "report_files": {
                "html": f"/reports/{html_path.name}",
                "json": f"/reports/{json_path.name}" if scan_results else None
            }
        }

        if email_report:
            resp["email_report"] = {
                "email": email_report.email,
                "prefix": email_report.prefix,
                "domain": email_report.domain,
                "provider": email_report.provider_info.provider,
                "mx_records": email_report.provider_info.mx_records,
                "github": {
                    "found": email_report.github.found,
                    "username": email_report.github.username,
                    "avatar_url": email_report.github.avatar_url,
                    "profile_url": email_report.github.profile_url,
                    "source": email_report.github.source
                },
                "gravatar": {
                    "exists": email_report.gravatar.exists,
                    "avatar_url": email_report.gravatar.avatar_url,
                    "display_name": email_report.gravatar.display_name,
                    "preferred_username": email_report.gravatar.preferred_username,
                    "location": email_report.gravatar.location,
                    "about_me": email_report.gravatar.about_me,
                    "urls": email_report.gravatar.urls,
                    "verified_accounts": email_report.gravatar.verified_accounts
                },
                "breach": {
                    "pwned": email_report.breach.pwned,
                    "count": email_report.breach.count,
                    "breaches": email_report.breach.breaches,
                    "hibp_url": email_report.breach.hibp_url
                }
            }

        if phone_report:
            resp["phone_report"] = {
                "is_valid": phone_report.is_valid,
                "country_name": phone_report.country_name,
                "country_code": phone_report.country_code,
                "carrier_name": phone_report.carrier_name,
                "line_type": phone_report.line_type,
                "international_format": phone_report.international_format,
                "chat_links": phone_report.chat_links,
                "dork_links": phone_report.dork_links
            }

        return resp


def find_available_port(start_port=8080, max_tries=10):
    for port in range(start_port, start_port + max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start_port


def run_server():
    port = find_available_port(DEFAULT_PORT)
    # Bind to 127.0.0.1 so it is accessible via both 127.0.0.1 and localhost
    server_address = ("127.0.0.1", port)

    httpd = ThreadingHTTPServer(server_address, OSINTRequestHandler)
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print(f"  OSINT DETECTIVE WEB DASHBOARD IS LIVE!")
    print(f"  URL: {url}")
    print("=" * 60)
    print("  Press Ctrl+C to stop the server.\n")

    # Open browser safely after 0.8 seconds
    def open_browser():
        webbrowser.open(url)

    threading.Timer(0.8, open_browser).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Stopping server gracefully...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
