# URL SAFETY — Simple Website URL Risk Analyzer

A beginner-friendly Python + Flask web application that analyzes website URLs for potential risk signals using simple rule-based checks.

> **Important:** This tool combines URL heuristics with live DNS resolution and HTTPS certificate verification. It does not download page content, submit forms, follow redirects, or guarantee that a URL is safe or malicious.

---

## Features

- Analyze any website URL for potential risk signals
- Rule-based scoring system (0–100 risk score)
- Checks for: HTTP vs HTTPS, IP addresses, suspicious keywords, URL shorteners, unusual ports, punycode domains, and more
- Clean, dark-themed cybersecurity dashboard interface
- Downloadable comprehensive PDF report with findings, telemetry, network evidence, and limitations
- Performs evidence-backed DNS and TLS metadata checks without downloading page content
- No API keys or external threat-intelligence service required

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| Python 3.x | Main programming language |
| Flask | Web framework (backend) |
| HTML | User interface structure |
| CSS | Styling and design |
| JavaScript | Simple frontend interactions |

**Python Libraries Used:**
- `flask` — Web framework
- `reportlab` — PDF report generation
- `urllib.parse` — URL parsing (built-in)
- `ipaddress` — IP address detection (built-in)
- `re` — Regular expressions (built-in)
- `socket` and `ssl` — DNS and HTTPS certificate verification (built-in)

---

## Requirements

- **Python 3.8 or higher** (tested with Python 3.10+)
- **pip** (comes with Python)
- A modern web browser (Chrome, Firefox, Edge, etc.)

---

## How to Run (Step by Step)

### Step 1: Open the Project in VS Code

Open VS Code, then go to **File → Open Folder** and select the `Python_Project` folder.

### Step 2: Open a Terminal

In VS Code, press `` Ctrl + ` `` (backtick) to open the integrated terminal. Make sure it is **PowerShell**.

### Step 3: Create a Virtual Environment

Run this command to create a virtual environment:

```powershell
python -m venv venv
```

### Step 4: Activate the Virtual Environment

```powershell
.\venv\Scripts\Activate.ps1
```

> **If PowerShell blocks the activation** with an error like "running scripts is disabled", run this alternative command instead:
>
> ```powershell
> cmd /k "venv\Scripts\activate.bat"
> ```
>
> This opens a `cmd` prompt with the virtual environment activated. You can continue from there.

You should see `(venv)` at the beginning of your terminal prompt.

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Start the Application

```powershell
python app.py
```

You should see output like:

```
==================================================
  URL SAFETY — Simple URL Risk Analyzer
  Open your browser at: http://127.0.0.1:5000
  Press Ctrl+C to stop the server.
==================================================
```

### Step 7: Open in Browser

Open your web browser and go to:

```
http://127.0.0.1:5000
```

### Step 8: Stop the Application

In the terminal, press **Ctrl + C** to stop the Flask server.

---

## Project Folder Structure

```text
Python_Project/
├── app.py              ← Main Flask application + URL analysis logic
├── requirements.txt    ← Python dependencies (just Flask)
├── README.md           ← This file
├── templates/
│   └── index.html      ← HTML interface
└── static/
    └── style.css       ← CSS styling
```

---

## Example Test URLs

| URL | Expected Behavior |
|-----|-------------------|
| `https://www.google.com` | Low risk score |
| `http://example.com` | Warns about HTTP |
| `http://192.168.1.1/login` | IP address + HTTP + keyword warning |
| `http://secure-login-example.invalid/verify` | Multiple keyword warnings |
| `https://bit.ly/abc123` | URL shortener warning |
| `http://xn--e1afmapc.xn--p1ai` | Punycode warning |
| `https://example.com:8443/page` | Non-standard port warning |

---

## Common Errors and Solutions

| Error | Solution |
|-------|----------|
| `python is not recognized` | Make sure Python is installed and added to your PATH |
| `ModuleNotFoundError: No module named 'flask'` | Activate the virtual environment and run `pip install -r requirements.txt` |
| PowerShell blocks `Activate.ps1` | Use `cmd /k "venv\Scripts\activate.bat"` instead |
| `Address already in use` | Another program is using port 5000. Close it or change the port in `app.py` |
| Page shows "Connection Refused" | Make sure the Flask server is running in your terminal |

---

## How Results Work

The score combines URL-structure signals with observations from the current machine. DNS resolution confirms that a hostname resolves; TLS verification checks whether an HTTPS certificate is trusted and matches the hostname. These are useful technical signals, not a reputation verdict.

The analyzer does not claim to know whether a page is malicious. Definitive reputation checking requires a threat-intelligence provider such as Google Safe Browsing or VirusTotal and an API key, which is intentionally not bundled into this local project.

## Limitations

- It does not download page content, execute scripts, follow redirects, or submit data
- DNS and TLS results depend on the network and certificate store available on the machine running Flask
- It uses transparent rule-based checks, not machine learning or a malicious-URL database
- A low score does **not** mean the URL is verified safe
- A high score does **not** definitively prove the URL is malicious
- It cannot detect malware, phishing page content, or server-side threats
- It does not check against any online database of known malicious URLs

---

## Adding New Rules

To add more URL analysis rules, edit the `analyze_url()` function in **`app.py`**. Follow the same pattern as the existing rules:

1. Write a simple `if` check
2. Add points to `risk_score`
3. Append a warning dictionary to the `warnings` list

---

## Author

BCA Student Project — Built with Python & Flask
