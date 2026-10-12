# 🔐 URL SAFETY — Complete Project Workflow

> **Purpose of this file:** Full session handoff document.
> If you're a new AI assistant picking this up, read this entire file first before touching any code.

---

## 📌 Project Summary

**Name:** URL SAFETY — Simple Website URL Risk Analyzer
**Type:** Python + Flask web application (beginner/BCA student project)
**Goal:** Analyze a URL for potential phishing/risk signals using transparent URL heuristics plus DNS and HTTPS certificate metadata — without downloading page content or following redirects
**Stack:** Python 3.x · Flask · HTML · CSS · Vanilla JavaScript

---

## 📁 Project Structure

```
Python_Project/
├── app.py                      ← Main Flask backend + all URL analysis logic (695 lines)
├── requirements.txt            ← Only one dependency: flask
├── README.md                   ← User-facing setup guide
├── WORKFLOW.md                 ← This file (AI handoff document)
├── URL_SAFETY_Master_Prompt.md ← Master prompt used to build this project with AI
├── templates/
│   └── index.html              ← Frontend UI (dark cybersecurity theme)
└── static/
    └── style.css               ← All styling (dark theme, animations, responsive)
```

---

## 🧠 Architecture Overview

```
User (Browser)
     │
     │  GET /          → Renders index.html
     │  POST /analyze  → Sends URL via form-data, gets JSON back
     ▼
Flask App (app.py)
     │
     ├── validate_url(url)   → Cleans + validates input URL
    └── analyze_url(url)    → Runs URL rules and network metadata checks, returns dict
                                    │
                                    ├── risk_score  (0–100+)
                                    ├── classification ("Safe" / "Low" / "Medium" / "High" / "Critical")
                                    ├── checks[]    (list of rule results)
                                    └── url_breakdown{}  (parsed URL parts)
```

---

## ⚙️ How the Analysis Engine Works (app.py)

### Core Data Lists (top of file, easy to extend)

| Variable | Purpose |
|---|---|
| URL_SHORTENERS | Known shortener domains (bit.ly, tinyurl, etc.) |
| SUSPICIOUS_KEYWORDS | Phishing keywords (login, verify, password, etc.) |
| RISKY_TLDS | Free/abused TLDs (.tk, .xyz, .top, etc.) |
| WELL_KNOWN_DOMAINS | Trusted domains for display context only |
| REDIRECT_PARAMS | Query params used in redirect attacks |

### Risk Rules (inside analyze_url()) — Each adds points to risk_score

| Rule # | What it Checks | Risk Points |
|---|---|---|
| 1 | HTTPS vs HTTP | +10 for HTTP |
| 2 | URL Length > 100 chars | +10 |
| 3 | IP address as hostname | +15 |
| 4 | @ symbol in URL | +20 |
| 4 | // double-slash in path | +10 |
| 4 | % URL-encoded characters | +10 |
| 5 | Suspicious keywords in URL | +10 per keyword (max 3) |
| 6 | URL shortener domain | +15 |
| 7 | Risky TLD (.tk, .xyz, etc.) | +20 |
| 8 | Excessive subdomains (>3) | +15 |
| 9 | Non-standard port | +10 |
| 10 | Punycode / IDN hostname (xn--) | +20 |
| 11 | Excessive hyphens in domain | +15 |
| 12 | Redirect parameters in query | +15 |
| 13 | URL-encoded IP in path | +20 |
| 14 | Very long hostname (>30 chars) | +10 |
| 15 | Well-known domain check | 0 (info only) |

### Risk Score → Classification Mapping

| Score | Label |
|---|---|
| 0–15 | ✅ Safe |
| 16–35 | 🟡 Low Risk |
| 36–55 | 🟠 Medium Risk |
| 56–75 | 🔴 High Risk |
| 76+ | ☠️ Critical Risk |

### analyze_url() Return Structure

```python
{
  "risk_score": int,
  "classification": str,
  "total_checks": int,
  "flagged_count": int,
  "passed_count": int,
  "checks": [
    {
      "rule": str,
      "status": "pass" or "flag",
      "severity": "info" or "warning" or "danger",
      "message": str
    }
  ],
  "url_breakdown": {
    "scheme": str,
    "hostname": str,
    "main_domain": str,
    "subdomains": str,
    "port": str,
    "path": str,
    "query": str,
    "fragment": str,
    "total_length": int
  },
  "live_verification": {
    "checked_at": str,
    "dns": {"status": str, "addresses": list, "error": str},
    "tls": {"status": str, "subject": str, "expires": str, "error": str}
  }
}
```

---

## 🌐 Flask Routes

| Route | Method | Description |
|---|---|---|
| / | GET | Renders index.html |
| /analyze | POST | Validates + analyzes URL, returns JSON |

- Request: form-data with field `url`
- Success response: `{ "success": true, "data": { ...analysis... } }`
- Error response: `{ "success": false, "error": "Reason string" }`

---

## 🖥️ Frontend (index.html + style.css)

- Dark cybersecurity theme — dark background, cyan/green accents
- Single page — no routing, vanilla JS handles results rendering
- Uses fetch() to POST to /analyze, displays results dynamically
- Shows: risk score, classification, URL breakdown table, all check results
- No external JS libraries (no jQuery, no React)

---

## 🛠️ How to Run the Project

```powershell
# Navigate to project folder
cd "C:\Users\Admin\OneDrive\Desktop\Python_Project"

# Create virtual environment (first time only)
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
# If PowerShell blocks it:
cmd /k "venv\Scripts\activate.bat"

# Install dependencies (first time only)
pip install -r requirements.txt

# Start the app
python app.py

# Open browser at: http://127.0.0.1:5000
```

---

## 📋 Test URLs to Verify Everything Works

| URL | Expected Result |
|---|---|
| https://www.google.com | Safe (score ~0) |
| http://example.com | Low Risk (HTTP warning) |
| http://192.168.1.1/login | High Risk (IP + HTTP + keyword) |
| https://bit.ly/abc123 | Medium Risk (shortener) |
| http://secure-login-verify.xyz/account | Critical Risk (many flags) |
| http://xn--e1afmapc.xn--p1ai | Medium Risk (punycode) |
| https://example.com:8443/page | Low Risk (non-standard port) |

---

## ✏️ How to Add a New Rule

In app.py inside the analyze_url() function, add:

```python
# RULE N: Description
if <your condition>:
    risk_score += <points>
    checks.append({
        "rule": "Display Name",
        "status": "flag",
        "severity": "warning",  # or "danger"
        "message": "Explanation for the user."
    })
else:
    checks.append({
        "rule": "Display Name",
        "status": "pass",
        "severity": "info",
        "message": "Why this looks fine."
    })
```

---

## 🔑 Key Design Decisions

- No external APIs or API keys; DNS and TLS checks use the local machine's network and certificate store
- No database — stateless, each request is independent
- No ML — pure rule-based logic (intentional, for beginner readability)
- validate_url() auto-fixes input — adds https:// if missing, strips whitespace
- Network verification never downloads page content, submits forms, or follows redirects
- Only `flask` is an external dependency — urllib.parse, ipaddress, re are built-ins
- debug=True in development — auto-reloads on code change

---

## 📌 What Was Built in This Session

1. ✅ Full app.py — Flask app with 15+ URL analysis rules plus live DNS/TLS verification
2. ✅ templates/index.html — Dark-themed single-page UI
3. ✅ static/style.css — Complete cybersecurity-style CSS
4. ✅ requirements.txt — Minimal dependency list
5. ✅ README.md — User-facing setup and usage guide
6. ✅ URL_SAFETY_Master_Prompt.md — Master AI prompt used to build the project
7. ✅ WORKFLOW.md — This handoff document

---

## 🤖 Prompt for Next AI

> This is a Python + Flask URL safety analyzer project for a BCA student.
> The project is complete and running. The core logic is in app.py inside the analyze_url() function.
> The frontend is a dark-themed single-page app in templates/index.html and static/style.css.
> All analysis is rule-based — no ML, no APIs, no database.
> Read WORKFLOW.md for full architecture before making any changes.
> To run: activate venv, then run `python app.py`, open browser at http://127.0.0.1:5000

---

*Last updated: October 2026 · BCA Student Project*
