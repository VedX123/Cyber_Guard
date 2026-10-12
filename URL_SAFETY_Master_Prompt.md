# MASTER PROMPT: Build URL SAFETY — Python-Based URL Analyzer

## 1. Project Overview

Act as an experienced Python developer who specializes in teaching beginners. Help me build a complete, working Python-based application named **URL SAFETY** that runs locally on my Windows PC.

The purpose of this application is to analyze a website URL and identify whether it appears relatively safe or potentially malicious based on basic URL analysis techniques.

**Important:** This is my beginner-level Python project. Write the code as if it were developed by a beginner who understands Python fundamentals. Keep everything simple, readable, well-commented, and easy to understand.

Do not overengineer the application or use advanced programming techniques unnecessarily.

## 2. Mandatory Technology Stack

Use the following technologies:

- **Python:** Main programming language.
- **Flask:** Mandatory backend framework.
- **HTML:** For the user interface.
- **CSS:** For styling the application.
- **JavaScript:** Only for simple frontend interactions where necessary.

Use Python's built-in libraries whenever possible, including `urllib.parse`, `ipaddress`, and `re`.

Flask is the only mandatory external Python dependency.

Do not use Django, React, Node.js, machine learning, complex databases, or other unnecessary frameworks.

## 3. Application Type

Create a local web application that runs on my Windows PC through Flask.

The application should open in my browser at:

`http://127.0.0.1:5000`

The Flask server must run locally on my computer. It does not need a public domain, hosting service, or cloud deployment.

The application should have a clean, modern, beginner-friendly interface that looks like a small cybersecurity utility.

## 4. Main Functionality

The application should have the following functionality.

### A. URL Input

Create a main screen with:

- Application name: **URL SAFETY**
- Subtitle: "Simple Website URL Risk Analyzer"
- A text input field where the user can enter a website URL.
- A button labeled **Analyze URL**.
- A clear button to reset the input and results.
- A results section that appears after analysis.

Example URLs for testing:

- `https://www.google.com`
- `http://example.com`
- `http://192.168.1.1/login`
- `http://secure-login-example.invalid/verify`

Treat these as test inputs, not as predetermined ground-truth classifications. The analysis logic must determine the result based on the actual URL features.

### B. Input Validation

Before analyzing a URL:

1. Check whether the input is empty.
2. Remove unnecessary leading and trailing spaces.
3. Parse the URL using Python's built-in URL parsing tools.
4. If the user omits the scheme, optionally add `https://` for parsing and display the normalized URL.
5. Reject malformed URLs, unsupported schemes, missing hostnames, and invalid hostnames where appropriate.
6. Accept only `http` and `https` URLs.
7. Display clear and beginner-friendly error messages.

Never crash the application because of empty or malformed input.

## 5. URL Analysis Rules

Implement a simple rule-based risk scoring system using Python.

Create a function named `analyze_url(url)` that examines the URL and returns a risk score, a classification, and a list of reasons.

Use straightforward `if`, `elif`, `else`, loops, strings, lists, and functions.

Do not use machine learning or complicated algorithms.

Analyze these URL characteristics:

### Rule 1: HTTPS Protocol

- Recognize HTTPS URLs.
- Recognize HTTP URLs that do not use encryption for the connection.
- Explain that HTTPS does not guarantee that a website is trustworthy.
- Treat HTTP as a warning signal, not proof of maliciousness.

### Rule 2: URL Length

- Check the total URL length.
- Add a small risk score if the URL is unusually long, such as more than 100 characters.
- Explain that long URLs can sometimes hide suspicious structures, but legitimate URLs can also be long.

### Rule 3: IP Address as Hostname

- Check whether the hostname is an IPv4 or IPv6 address using Python's `ipaddress` library.
- Increase the risk score slightly when the URL uses an IP address instead of a typical domain name.
- Explain why this can be suspicious without claiming that every IP-based URL is malicious.

### Rule 4: Suspicious Characters

Look for URL characteristics such as:

- `@` in the URL authority or other misleading user-information structures.
- Multiple hyphens in the hostname.
- Unusual numbers of dots or subdomains.
- Encoded characters or confusing URL structures.

Implement these checks carefully. Do not automatically mark every URL containing these characters as malicious.

### Rule 5: Suspicious Keywords

Check for potentially suspicious words in the hostname or URL path, such as:

- `login`
- `verify`
- `update`
- `secure`
- `account`
- `password`
- `banking`
- `confirm`

Apply only small risk increases, because these words are common on legitimate websites. Do not classify a URL as malicious merely because it contains one of these words.

### Rule 6: URL Shorteners

Maintain a small list of common URL-shortening domains, such as:

- `bit.ly`
- `tinyurl.com`
- `t.co`

Treat a recognized URL shortener as an uncertainty signal because the destination is not visible in the shortened URL. Do not claim that all shortened URLs are malicious.

### Rule 7: Unusual Ports

Check whether the URL uses a nonstandard port.

Treat unusual ports as a potential warning signal rather than proof of an attack.

### Rule 8: Punycode and Internationalized Domains

Identify hostnames containing the `xn--` prefix.

Explain that such domains can be legitimate but may sometimes be used to create confusing lookalike domains.

### Rule 9: Repeated or Unusual URL Structures

Check for patterns that may indicate a misleading URL, such as repeated encoding or unusually nested path structures, using simple and understandable checks.

Do not create overly aggressive rules that flag normal URLs without a reasonable explanation.

## 6. Risk Score and Classification

Implement a simple scoring system. Each rule may add a small number of points.

Use these suggested thresholds:

- **0–24 points:** Lower apparent risk.
- **25–49 points:** Suspicious — exercise caution.
- **50 points or more:** High risk — potentially malicious.

Adjust the individual rule weights so that the scoring system remains reasonable.

The score must never go below 0 or above 100.

The result should include:

1. The risk score out of 100.
2. A clear risk classification.
3. A list of detected warning signals.
4. A short explanation for each warning signal.
5. A brief recommendation for the user.

Use clear result labels, such as:

- "Lower Apparent Risk"
- "Suspicious — Exercise Caution"
- "High Risk — Potentially Malicious"

Do not label a URL as definitively safe merely because it receives a low score.

If no warning signals are found, display a message such as:

"No major warning signs were detected by our basic URL analysis. This does not guarantee that the website is safe."

## 7. User Interface Design

Create a clean and professional interface suitable for a beginner cybersecurity project.

The preferred visual style is a simple security dashboard with:

- A dark navy or charcoal background.
- A contrasting accent color.
- A clearly visible application title.
- A URL input field.
- A prominent Analyze URL button.
- A results panel.
- A numerical risk score.
- A list of detected warning signals.
- Clear status labels.
- A small footer describing the application's limitations.

Keep the design responsive so it works on different browser window sizes.

Use plain HTML and CSS. Avoid complex UI libraries.

Use accessible labels, readable text, and sufficient contrast.

Display a useful initial state before the user analyzes a URL.

## 8. Flask Backend Requirements

Use Flask to handle the application routes.

Implement at least these routes:

- `/` — Displays the main application page.
- `/analyze` — Processes the submitted URL and returns the result.

Use standard Flask form handling and appropriate HTTP methods.

The analysis should happen on the server using Python.

Keep the route functions simple and easy to understand.

Use Flask's normal template rendering, with the HTML stored in a `templates` folder and CSS stored in a `static` folder.

Do not use a separate frontend framework.

Ensure that the application handles input errors gracefully.

## 9. Important Cybersecurity and Privacy Requirements

This application is intended for basic URL analysis, not professional threat intelligence.

Follow these rules:

1. **Do not open or visit the URL being analyzed.**
2. Do not fetch the submitted URL using `requests.get()`, `urllib.request.urlopen()`, or any other network request.
3. Do not automatically follow redirects.
4. Do not execute JavaScript, download website content, or open files from the submitted URL.
5. Perform the analysis using the URL string only.
6. Do not require API keys, paid services, external reputation services, or internet access for basic analysis.
7. Do not store submitted URLs in a database or log them unnecessarily.
8. Bind the Flask development server to `127.0.0.1`, not `0.0.0.0`.
9. Use normal Flask template escaping when displaying user input.
10. Treat all submitted URL data as untrusted input.

The application must clearly state that it uses basic, local, rule-based analysis. It is not an antivirus tool and cannot guarantee that a URL is safe or malicious.

## 10. Beginner-Friendly Code Requirements

This is a strict requirement.

Write the source code as simply as possible.

- Use meaningful variable and function names.
- Add comments explaining important lines.
- Use basic functions and conditional statements.
- Prefer simple lists and dictionaries.
- Avoid unnecessary classes and object-oriented architecture.
- Avoid decorators other than the normal Flask route decorators required by the framework.
- Avoid complex regular expressions unless genuinely necessary.
- Avoid advanced Python tricks, one-line conditional expressions, and overly compact code.
- Do not place the entire project in one large Python file if separating templates and CSS makes the project easier to understand.
- Avoid unnecessary abstraction and excessive helper functions.

Keep the number of files small and the project easy for a BCA student to explain during a project demonstration or viva.

## 11. Required Project Folder Structure

Create a folder structure similar to this:

```text
URL-SAFETY/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    └── style.css
```

You may add a small test file if needed, but do not add unnecessary folders or files.

Keep the main analysis logic in `app.py` to make the project easy for a beginner to follow.

## 12. Error Handling and Testing

Test the application against different types of inputs:

- An empty input.
- A normal HTTPS URL.
- An HTTP URL.
- A URL without a scheme.
- A very long URL.
- A URL using an IP address.
- A URL containing a suspicious keyword.
- A URL using a recognized URL shortener.
- A malformed URL.
- A URL with an unsupported scheme, such as `ftp://`.
- A URL containing special characters.
- A URL with an unusual port.
- A URL with a punycode hostname.

Check that each input produces a reasonable result without crashing.

Do not hardcode the output for individual example URLs.

If a URL is classified as risky, show which rules contributed to its score.

If it receives a low score, do not imply that it has been verified against known malicious websites.

## 13. Installation and Execution Instructions

Create a beginner-friendly `README.md` with the following information:

1. Project introduction.
2. Features of URL SAFETY.
3. Technologies used.
4. Required Python version, verified against the actual code and dependencies.
5. How to open the project folder in VS Code.
6. How to create a Python virtual environment on Windows.
7. How to activate the virtual environment in PowerShell.
8. How to install dependencies using `pip install -r requirements.txt`.
9. How to start the Flask application.
10. How to open `http://127.0.0.1:5000` in a browser.
11. How to stop the application.
12. Common errors and their solutions.

Include exact terminal commands, for example:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

If PowerShell blocks virtual-environment activation, explain a simple alternative without requiring changes to system-wide security settings.

## 14. Instructions for the IDE AI Assistant

Do not stop after writing a plan or showing example code.

Actually create all the required project files in my currently open project workspace.

Before writing the code:

1. Inspect the existing workspace.
2. Reuse any existing relevant project files.
3. Avoid unnecessarily overwriting unrelated files.
4. If an existing implementation is present, improve it while keeping the project beginner-friendly.

Then:

1. Implement the Flask application.
2. Implement the URL analysis function.
3. Create the HTML interface and CSS styling.
4. Create `requirements.txt`.
5. Write the README with Windows installation instructions.
6. Run the application and test it if the IDE environment supports execution.
7. Fix syntax errors, import errors, template errors, and other issues found during testing.
8. Check that every feature described in this prompt is implemented.
9. Explain how to launch the finished application.

Do not claim that the project was successfully tested unless you actually ran the relevant tests.

## 15. Final Response from the IDE

After creating the project, explain:

- What files were created.
- How the application works.
- How the risk score is calculated.
- How to run the application on my PC.
- What limitations the analyzer has.
- Which function I should edit if I want to add more URL analysis rules later.

Show the important source code in a simple, understandable way when explaining it.

**Final objective:** Deliver a complete, working, beginner-friendly Python and Flask application named **URL SAFETY** that runs locally on my Windows PC and analyzes submitted website URLs using simple risk-scoring rules without visiting those URLs.

Prioritize correctness, simplicity, readable code, and clear explanations over advanced features.
