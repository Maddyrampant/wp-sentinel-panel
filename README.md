<div align="center">

# 🛡️ WP-SENTINEL

### WordPress Theme & Plugin Security Analyzer

**170+ security checks · Theme Intelligence · Real-time analysis · Bilingual (EN/FA)**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue.svg)
![React](https://img.shields.io/badge/React-18-61DAFB.svg)
![Version](https://img.shields.io/badge/version-1.1.0-orange.svg)

</div>

---

## Overview

WP-SENTINEL is a self-hosted security analysis platform for WordPress themes and plugins. It scans for obfuscated code, backdoors, malware, nulled theme indicators, external domain connections, and 170+ known security patterns — all from a modern web panel.

**Built for security researchers, WordPress developers, and hosting providers who need fast, offline, and reliable WordPress code auditing.**

---

## Features

### Core Scanning Engine
- **170+ security checks** across 6 categories
- **Obfuscation detection** — base64, hex, ROT13, gzinflate, encoded strings
- **External access monitoring** — HTTP requests, cURL, file_get_contents, fopen
- **Security rule engine** — 30 built-in rules with confidence scoring
- **Custom rules** — YAML import/export, multi-pattern matching, path targeting
- **Risk scoring** — weighted scoring with context modifiers

### Theme Intelligence Module
- **Nulled theme detection** — keyword analysis (nulled, cracked, warez, license bypass)
- **Malware & backdoor scanning** — eval+base64, system/exec, file_put_contents, preg_replace /e
- **External domain extraction** — identifies all outbound connections with suspicious TLD detection
- **Base64 payload decoding** — safe decode with hidden URL extraction
- **Per-theme risk scoring** — aggregated severity with breakdown

### Web Panel
- **React + Tailwind CSS** dark-themed dashboard
- **Real-time scan results** with tabbed category views
- **File-grouped & check-grouped** result views
- **"Why Flagged?"** context panel with ±3 line code context
- **Threat type filtering** (webshell, backdoor, injection, redirect, secrets)
- **Scan history** with trend analysis charts
- **Compare scans** — diff between two scan results
- **PDF report generation** via PDFKit
- **Full bilingual support** — English & Farsi with RTL layout

---

## Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) v20+ (LTS recommended)
- npm v10+

### Installation

```bash
git clone https://github.com/Maddyrampant/wp-sentinel-panel.git
cd wp-sentinel-panel

# Install server dependencies
cd server && npm install

# Install client dependencies
cd ../client && npm install
```

### Build & Run

```bash
# Build server
cd server && npm run build

# Build client
cd ../client && npm run build

# Start the server
cd ../server && npm start
```

The panel is now running at **http://localhost:3001**

### Development Mode

```bash
# Terminal 1 — Server (hot reload)
cd server && npm run dev

# Terminal 2 — Client (Vite dev server)
cd client && npm run dev
```

The Vite dev server proxies `/api` requests to `http://localhost:3001`.

---

## Project Structure

```
wp-sentinel-panel/
├── server/                     # Express + TypeScript backend
│   ├── src/
│   │   ├── index.ts            # Express app entry
│   │   ├── types.ts            # TypeScript interfaces
│   │   ├── db/
│   │   │   └── database.ts     # SQLite (better-sqlite3)
│   │   ├── scanner/
│   │   │   ├── engine.ts       # 170+ check engine
│   │   │   ├── theme-intel.ts  # Theme Intelligence module
│   │   │   ├── pdf-report.ts   # PDF report generation
│   │   │   └── zip-handler.ts  # ZIP upload/extraction
│   │   ├── rules/
│   │   │   ├── rule-loader.ts  # YAML rule parser
│   │   │   ├── scorer.ts       # Risk scoring engine
│   │   │   ├── domain-allowlist.ts  # Safe domain registry
│   │   │   └── wp-compromise-rules.yaml  # 30 built-in rules
│   │   └── routes/
│   │       ├── scan.ts         # Scan API routes
│   │       ├── rules.ts        # Custom rules CRUD
│   │       └── theme-intel.ts  # Theme scan API
│   ├── data/                   # SQLite database (gitignored)
│   └── tsconfig.json
│
├── client/                     # React + Vite + Tailwind frontend
│   ├── src/
│   │   ├── App.tsx             # Routes
│   │   ├── api/client.ts       # Axios API client
│   │   ├── components/
│   │   │   ├── Layout.tsx      # Responsive layout
│   │   │   └── Sidebar.tsx     # Navigation + language switcher
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx   # Overview + trend charts
│   │   │   ├── NewScan.tsx     # Upload / path scan
│   │   │   ├── ScanResult.tsx  # Tabbed results with context
│   │   │   ├── ThemeIntel.tsx  # Theme Intelligence page
│   │   │   ├── History.tsx     # Scan history
│   │   │   ├── Compare.tsx     # Diff two scans
│   │   │   └── CustomRules.tsx # Rule management
│   │   ├── i18n/
│   │   │   ├── en.ts           # English translations
│   │   │   ├── fa.ts           # Farsi translations
│   │   │   ├── checks.ts       # 200+ check translations
│   │   │   └── index.tsx       # i18n context provider
│   │   └── types/
│   │       └── index.ts        # Client-side types
│   ├── dist/                   # Built client (served by Express)
│   └── vite.config.ts
│
└── .gitignore
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Scan a directory by path |
| `POST` | `/api/upload` | Upload ZIP and scan |
| `GET` | `/api/scan/:id` | Get scan results |
| `GET` | `/api/history` | List scan history |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/trend` | Trend data for charts |
| `POST` | `/api/compare` | Compare two scans |
| `GET` | `/api/report/:id/:format` | Download PDF/JSON/CSV report |
| `GET` | `/api/rules` | List all custom rules |
| `POST` | `/api/rules` | Create/update rule |
| `DELETE` | `/api/rules/:id` | Delete rule |
| `GET` | `/api/rules/builtin` | List built-in rules |
| `POST` | `/api/rules/import` | Import rules from YAML |
| `GET` | `/api/rules/export` | Export rules as YAML |
| `POST` | `/api/theme-scan` | Scan themes directory |
| `GET` | `/api/theme-scan/history` | Theme scan history |
| `GET` | `/api/theme-scan/:id` | Get theme scan result |
| `DELETE` | `/api/theme-scan/:id` | Delete theme scan |

---

## Security Checks

| Category | Checks | Description |
|----------|--------|-------------|
| Obfuscation | 20 | Base64, hex, ROT13, gzinflate, eval, encoded strings |
| External Access | 16 | HTTP requests, cURL, fopen, remote includes |
| Security | 85+ | SQL injection, XSS, file upload, auth bypass, privilege escalation |
| Code Patterns | 13 | Dangerous functions, dynamic execution, assertion abuse |
| File Analysis | 15+ | File permissions, suspicious names, hidden files |
| WordPress | 18 | Core file modification, DB credential exposure, plugin/theme vulnerabilities |

---

## Built-in Rules

30 rules across 8 categories seeded from YAML on startup:

- **Backdoor** — remote code execution, file upload backdoors
- **Obfuscation** — eval+base64, hex decode, ROT13
- **Webshell** — command shells, reverse shells, file managers
- **WordPress** — wp-config exposure, xmlrpc abuse, user enumeration
- **Persistence** — cron jobs, scheduled tasks, startup hooks
- **Redirect** — header redirects, meta refresh, JS redirects
- **Secrets** — hardcoded credentials, API keys, tokens
- **Integrity** — core file modification, checksum mismatch

---

## Theme Intelligence

Dedicated module for WordPress theme security analysis:

```
POST /api/theme-scan
{
  "themesPath": "/var/www/html/wp-content/themes",
  "themeName": "flavor"       // optional: scan single theme
}
```

Returns per-theme:
- Risk score (0–100) with severity level
- External domains with suspicious TLD detection
- Nulled/pirated theme indicators
- Malware & backdoor pattern matches
- Base64 decoded payloads with extracted URLs
- Theme metadata from style.css

---

## Internationalization

Full bilingual support with RTL layout:

| Language | Status |
|----------|--------|
| English | ✅ Complete |
| فارسی (Farsi) | ✅ Complete — Full RTL support |

Switch languages from the sidebar. Layout automatically adjusts for RTL direction.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js 20+ |
| Language | TypeScript 5.5 |
| Backend | Express 4 |
| Database | SQLite (better-sqlite3) |
| Frontend | React 18 |
| Styling | Tailwind CSS 3 |
| Build | Vite 6 |
| PDF | PDFKit |
| Charts | Chart.js |
| HTTP | Axios |
| Rules | js-yaml |

---

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `PORT` | `3001` | Server port |

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2026 WP-SENTINEL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**Built with care for the WordPress security community**

[Report Issues](https://github.com/Maddyrampant/wp-sentinel-panel/issues) · [Request Feature](https://github.com/Maddyrampant/wp-sentinel-panel/issues)

</div>
