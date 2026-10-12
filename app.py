"""
URL SAFETY — Simple Website URL Risk Analyzer
A beginner-friendly Flask application that analyzes URLs
using basic rule-based checks WITHOUT visiting the website.

Author: BCA Student Project
"""

# --- Import required libraries ---
from flask import Flask, render_template, request, jsonify, send_file
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timezone
from io import BytesIO
import ipaddress
import re
import socket
import ssl

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

# --- Create the Flask app ---
app = Flask(__name__)


# ============================================================
# LISTS USED BY THE ANALYZER
# ============================================================

# Common URL shortener domains
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "buff.ly", "ow.ly", "shorturl.at", "rb.gy", "cutt.ly",
    "short.io", "tiny.cc", "lnk.to"
]

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "banking", "confirm", "signin", "credential",
    "wallet", "suspend", "alert", "unlock", "expire"
]

# Free or commonly abused top-level domains
RISKY_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".buzz", ".club", ".work", ".link", ".click", ".surf"
]

# Well-known trusted domains (just hostnames, used for display context only)
WELL_KNOWN_DOMAINS = [
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "amazon.com", "www.amazon.com", "amazon.in", "www.amazon.in",
    "wikipedia.org", "en.wikipedia.org", "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
    "linkedin.com", "www.linkedin.com", "reddit.com", "www.reddit.com",
    "netflix.com", "www.netflix.com", "stackoverflow.com",
    "www.stackoverflow.com", "flipkart.com", "www.flipkart.com"
]

# Query parameters sometimes used in redirect/phishing attacks
REDIRECT_PARAMS = [
    "redirect", "url", "next", "goto", "return", "returnto",
    "redirect_uri", "continue", "dest", "destination", "rurl", "target"
]


# ============================================================
# URL ANALYSIS FUNCTION
# This is the main function that checks a URL for risk signals.
# Each rule adds points to the risk score.
# ============================================================

def analyze_url(url):
    """
    Analyze a URL string and return a risk score, classification,
    a list of check results, and a URL breakdown.

    This function does NOT visit or open the URL.
    It only examines the URL string itself.
    """

    # This list will hold all check results (both passed and flagged)
    checks = []

    # Start with a risk score of 0
    risk_score = 0

    # --- Parse the URL into its components ---
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()        # e.g., "https"
    hostname = parsed.hostname or ""      # e.g., "www.google.com"
    port = parsed.port                    # e.g., 8080 or None
    path = parsed.path or ""             # e.g., "/login/verify"
    query = parsed.query or ""           # e.g., "id=123&ref=abc"
    fragment = parsed.fragment or ""     # e.g., "section1"
    full_url_lower = url.lower()         # Full URL in lowercase

    # --- Build URL breakdown for display ---
    url_breakdown = {
        "scheme": scheme,
        "hostname": hostname,
        "port": str(port) if port else "Default",
        "path": path if path and path != "/" else "/",
        "query": query if query else "None",
        "fragment": fragment if fragment else "None",
        "total_length": len(url)
    }

    # Count subdomains for display
    if hostname and not _is_ip(hostname):
        parts = hostname.split(".")
        if len(parts) > 2:
            url_breakdown["subdomains"] = ".".join(parts[:-2])
            url_breakdown["main_domain"] = ".".join(parts[-2:])
        else:
            url_breakdown["subdomains"] = "None"
            url_breakdown["main_domain"] = hostname
    else:
        url_breakdown["subdomains"] = "N/A"
        url_breakdown["main_domain"] = hostname

    # ----------------------------------------------------------
    # RULE 1: Check HTTPS vs HTTP
    # ----------------------------------------------------------
    if scheme == "https":
        checks.append({
            "rule": "HTTPS Protocol",
            "status": "pass",
            "severity": "info",
            "message": "This URL uses HTTPS (encrypted connection). "
                       "HTTPS is good for security, but it alone does not "
                       "guarantee that the website is trustworthy."
        })
    elif scheme == "http":
        risk_score += 10
        checks.append({
            "rule": "HTTP Protocol (No Encryption)",
            "status": "flag",
            "severity": "warning",
            "message": "This URL uses HTTP, which means the connection is "
                       "not encrypted. Data sent to this site could be "
                       "intercepted. This is a warning signal, but some "
                       "legitimate sites still use HTTP."
        })

    # ----------------------------------------------------------
    # RULE 2: Check URL Length
    # ----------------------------------------------------------
    url_length = len(url)
    if url_length > 100:
        risk_score += 10
        checks.append({
            "rule": "URL Length",
            "status": "flag",
            "severity": "warning",
            "message": f"This URL is {url_length} characters long. "
                       "Very long URLs can sometimes hide suspicious "
                       "structures, but legitimate URLs can also be long "
                       "(e.g., search result pages)."
        })
    else:
        checks.append({
            "rule": "URL Length",
            "status": "pass",
            "severity": "info",
            "message": f"URL length is {url_length} characters — within "
                       "normal range."
        })

    # ----------------------------------------------------------
    # RULE 3: IP Address as Hostname
    # ----------------------------------------------------------
    is_ip_address = _is_ip(hostname)
    if is_ip_address:
        risk_score += 15
        checks.append({
            "rule": "IP Address Instead of Domain Name",
            "status": "flag",
            "severity": "warning",
            "message": f"The hostname '{hostname}' is an IP address "
                       "instead of a regular domain name. Legitimate "
                       "websites usually use domain names. IP-based URLs "
                       "can sometimes be used to hide a site's true identity."
        })
    else:
        checks.append({
            "rule": "Domain Name Check",
            "status": "pass",
            "severity": "info",
            "message": f"The hostname '{hostname}' uses a standard domain "
                       "name format."
        })

    # ----------------------------------------------------------
    # RULE 4: Suspicious Characters
    # ----------------------------------------------------------

    # Check for '@' symbol in the URL
    if "@" in url:
        risk_score += 20
        checks.append({
            "rule": "@ Symbol in URL",
            "status": "flag",
            "severity": "danger",
            "message": "This URL contains an '@' symbol, which can be used "
                       "to create misleading URLs. For example, "
                       "'http://google.com@evil.com' actually goes to "
                       "'evil.com', not 'google.com'."
        })

    # Check for multiple hyphens in the hostname
    if hostname:
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            risk_score += 10
            checks.append({
                "rule": "Multiple Hyphens in Hostname",
                "status": "flag",
                "severity": "warning",
                "message": f"The hostname contains {hyphen_count} hyphens. "
                           "While some legitimate domains use hyphens, an "
                           "unusual number can indicate a suspicious domain."
            })

    # Check for many subdomains (many dots in hostname)
    if hostname and not is_ip_address:
        dot_count = hostname.count(".")
        if dot_count >= 4:
            risk_score += 10
            checks.append({
                "rule": "Many Subdomains",
                "status": "flag",
                "severity": "warning",
                "message": f"The hostname has {dot_count} dots, suggesting "
                           "{dot_count} subdomain levels. Excessive "
                           "subdomains are sometimes used to create "
                           "confusing URLs."
            })
        else:
            checks.append({
                "rule": "Subdomain Count",
                "status": "pass",
                "severity": "info",
                "message": f"The hostname has {dot_count} dot(s) — "
                           "normal subdomain structure."
            })

    # Check for encoded characters in hostname
    if hostname and "%" in hostname:
        risk_score += 10
        checks.append({
            "rule": "Encoded Characters in Hostname",
            "status": "flag",
            "severity": "warning",
            "message": "The hostname contains percent-encoded characters. "
                       "This is unusual and can be used to disguise the "
                       "true destination of the URL."
        })

    # ----------------------------------------------------------
    # RULE 5: Suspicious Keywords
    # ----------------------------------------------------------
    found_keywords = []
    check_text = (hostname + path).lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in check_text:
            found_keywords.append(keyword)

    if found_keywords:
        risk_score += min(len(found_keywords) * 5, 15)
        checks.append({
            "rule": "Suspicious Keywords",
            "status": "flag",
            "severity": "warning",
            "message": "The URL contains keywords often associated with "
                       f"phishing: {', '.join(found_keywords)}. "
                       "These words also appear on many legitimate websites, "
                       "so this is just a caution signal."
        })
    else:
        checks.append({
            "rule": "Suspicious Keywords",
            "status": "pass",
            "severity": "info",
            "message": "No common phishing keywords detected in the "
                       "hostname or path."
        })

    # ----------------------------------------------------------
    # RULE 6: URL Shorteners
    # ----------------------------------------------------------
    if hostname in URL_SHORTENERS:
        risk_score += 15
        checks.append({
            "rule": "URL Shortener Detected",
            "status": "flag",
            "severity": "warning",
            "message": f"The domain '{hostname}' is a known URL shortener. "
                       "Shortened URLs hide the true destination. This is "
                       "not necessarily malicious, but you cannot see where "
                       "the link actually goes."
        })
    else:
        checks.append({
            "rule": "URL Shortener Check",
            "status": "pass",
            "severity": "info",
            "message": "This URL does not use a known URL-shortening service."
        })

    # ----------------------------------------------------------
    # RULE 7: Unusual Ports
    # ----------------------------------------------------------
    standard_ports = {80, 443}
    if port is not None and port not in standard_ports:
        risk_score += 10
        checks.append({
            "rule": "Non-Standard Port",
            "status": "flag",
            "severity": "warning",
            "message": f"This URL uses port {port}, which is not the "
                       "standard port for web traffic (80 for HTTP, "
                       "443 for HTTPS). Non-standard ports can indicate "
                       "a development server or an unusual configuration."
        })
    else:
        checks.append({
            "rule": "Port Check",
            "status": "pass",
            "severity": "info",
            "message": "This URL uses a standard web port."
        })

    # ----------------------------------------------------------
    # RULE 8: Punycode / Internationalized Domain Names
    # ----------------------------------------------------------
    if hostname and "xn--" in hostname.lower():
        risk_score += 15
        checks.append({
            "rule": "Punycode (Internationalized Domain)",
            "status": "flag",
            "severity": "warning",
            "message": "The hostname contains 'xn--', which indicates a "
                       "Punycode-encoded internationalized domain name. "
                       "While many are legitimate, punycode can be used "
                       "to create lookalike domains that mimic trusted "
                       "websites (homograph attacks)."
        })

    # ----------------------------------------------------------
    # RULE 9: Repeated or Unusual URL Structures
    # ----------------------------------------------------------

    # Check for double encoding (e.g., %2520 = double-encoded space)
    if "%25" in url:
        risk_score += 10
        checks.append({
            "rule": "Double-Encoded Characters",
            "status": "flag",
            "severity": "warning",
            "message": "The URL contains double-encoded characters (like "
                       "'%25'). This can indicate an attempt to bypass "
                       "security filters by encoding the URL multiple times."
        })

    # Check for unusually deep path nesting
    path_parts = [p for p in path.split("/") if p]
    path_depth = len(path_parts)
    if path_depth >= 6:
        risk_score += 5
        checks.append({
            "rule": "Deeply Nested Path",
            "status": "flag",
            "severity": "info",
            "message": f"The URL has a path depth of {path_depth} levels. "
                       "While this can be normal on large sites, deeply "
                       "nested paths are sometimes used to obscure URLs."
        })

    # Check for repeated slashes in the path
    if "//" in path:
        risk_score += 5
        checks.append({
            "rule": "Repeated Slashes in Path",
            "status": "flag",
            "severity": "info",
            "message": "The URL path contains repeated slashes ('//'), "
                       "which is unusual and might indicate a malformed "
                       "or intentionally confusing URL structure."
        })

    # ----------------------------------------------------------
    # RULE 10: Risky Top-Level Domains (TLDs)
    # ----------------------------------------------------------
    if hostname and not is_ip_address:
        tld_found = ""
        for risky_tld in RISKY_TLDS:
            if hostname.endswith(risky_tld):
                tld_found = risky_tld
                break

        if tld_found:
            risk_score += 10
            checks.append({
                "rule": "Risky Top-Level Domain",
                "status": "flag",
                "severity": "warning",
                "message": f"The domain uses '{tld_found}', a top-level "
                           "domain that is sometimes associated with spam "
                           "or phishing. Many legitimate sites also use "
                           "these TLDs, but exercise caution."
            })
        else:
            # Extract the TLD for display
            domain_parts = hostname.split(".")
            actual_tld = "." + domain_parts[-1] if domain_parts else ""
            checks.append({
                "rule": "Top-Level Domain",
                "status": "pass",
                "severity": "info",
                "message": f"The domain uses '{actual_tld}' — a commonly "
                           "used top-level domain."
            })

    # ----------------------------------------------------------
    # RULE 11: Long or Suspicious Hostname
    # ----------------------------------------------------------
    if hostname and len(hostname) > 40 and not is_ip_address:
        risk_score += 5
        checks.append({
            "rule": "Long Hostname",
            "status": "flag",
            "severity": "info",
            "message": f"The hostname is {len(hostname)} characters long. "
                       "Unusually long hostnames can sometimes be used to "
                       "confuse users about the actual domain."
        })

    # ----------------------------------------------------------
    # RULE 12: Query String with Redirect Parameters
    # ----------------------------------------------------------
    if query:
        query_params = parse_qs(query)
        found_redirect_params = []
        for param_name in query_params:
            if param_name.lower() in REDIRECT_PARAMS:
                found_redirect_params.append(param_name)

        if found_redirect_params:
            risk_score += 10
            checks.append({
                "rule": "Redirect Parameters in URL",
                "status": "flag",
                "severity": "warning",
                "message": "The URL contains query parameters that may "
                           "indicate a redirect: "
                           f"{', '.join(found_redirect_params)}. "
                           "Redirect parameters can be used in phishing to "
                           "send you to a different site after login."
            })
        else:
            param_count = len(query_params)
            checks.append({
                "rule": "Query Parameters",
                "status": "pass",
                "severity": "info",
                "message": f"The URL has {param_count} query parameter(s) — "
                           "no suspicious redirect parameters found."
            })
    else:
        checks.append({
            "rule": "Query Parameters",
            "status": "pass",
            "severity": "info",
            "message": "No query parameters present in this URL."
        })

    # ----------------------------------------------------------
    # RULE 13: Well-Known Domain Recognition
    # ----------------------------------------------------------
    is_well_known = hostname.lower() in WELL_KNOWN_DOMAINS
    if is_well_known:
        checks.append({
            "rule": "Well-Known Domain",
            "status": "pass",
            "severity": "info",
            "message": f"'{hostname}' is recognized as a well-known domain. "
                       "Note: This basic check only matches exact hostnames "
                       "and cannot detect typosquatting or lookalike domains."
        })
    else:
        checks.append({
            "rule": "Domain Recognition",
            "status": "neutral",
            "severity": "info",
            "message": f"'{hostname}' is not in our small list of well-known "
                       "domains. This does not mean it is suspicious — "
                       "most legitimate websites are not in this list."
        })

    # ----------------------------------------------------------
    # LIVE NETWORK VERIFICATION
    # These checks inspect DNS and the TLS handshake only. They do not
    # download page content or follow redirects.
    # ----------------------------------------------------------
    live_verification = verify_network_metadata(scheme, hostname, port)

    if live_verification["dns"]["status"] == "failed":
        risk_score += 20
        checks.append({
            "rule": "DNS Resolution",
            "status": "flag",
            "severity": "warning",
            "message": "The hostname could not be resolved from this machine. "
                       "The domain may be inactive, misspelled, or temporarily unavailable."
        })
    else:
        checks.append({
            "rule": "DNS Resolution",
            "status": "pass",
            "severity": "info",
            "message": "The hostname resolved successfully to: "
                       + ", ".join(live_verification["dns"]["addresses"])
        })

    if scheme == "https":
        tls_result = live_verification["tls"]
        if tls_result["status"] == "valid":
            checks.append({
                "rule": "TLS Certificate Verification",
                "status": "pass",
                "severity": "info",
                "message": "The TLS certificate was trusted by the local certificate store "
                           "and matched the requested hostname."
            })
        else:
            risk_score += 15
            checks.append({
                "rule": "TLS Certificate Verification",
                "status": "flag",
                "severity": "warning",
                "message": "TLS verification failed: " + tls_result["error"]
            })

    # ----------------------------------------------------------
    # Calculate the final risk score (keep between 0 and 100)
    # ----------------------------------------------------------
    risk_score = max(0, min(100, risk_score))

    # ----------------------------------------------------------
    # Determine the risk classification
    # ----------------------------------------------------------
    if risk_score < 25:
        classification = "Lower Apparent Risk"
        recommendation = (
            "This URL shows fewer warning signs based on our basic checks. "
            "However, this does NOT guarantee the website is safe. "
            "Always exercise caution when visiting unfamiliar websites."
        )
    elif risk_score < 50:
        classification = "Suspicious — Exercise Caution"
        recommendation = (
            "This URL shows some warning signs. Be cautious before "
            "clicking or entering any personal information. Verify the "
            "website's identity through other means if possible."
        )
    else:
        classification = "High Risk — Potentially Malicious"
        recommendation = (
            "This URL shows multiple warning signs that are commonly "
            "associated with malicious or phishing websites. Avoid "
            "visiting this URL unless you are certain it is legitimate."
        )

    # ----------------------------------------------------------
    # Separate flagged checks from passed checks
    # ----------------------------------------------------------
    flagged_checks = [c for c in checks if c["status"] == "flag"]
    passed_checks = [c for c in checks if c["status"] in ("pass", "neutral")]

    if len(flagged_checks) == 0:
        no_warnings_message = (
            "No major warning signs were detected by our basic URL "
            "analysis. This does not guarantee that the website is safe."
        )
    else:
        no_warnings_message = None

    # ----------------------------------------------------------
    # Return the results as a dictionary
    # ----------------------------------------------------------
    return {
        "url": url,
        "risk_score": risk_score,
        "classification": classification,
        "flagged_checks": flagged_checks,
        "passed_checks": passed_checks,
        "recommendation": recommendation,
        "no_warnings_message": no_warnings_message,
        "url_breakdown": url_breakdown,
        "live_verification": live_verification,
        "total_checks": len(checks),
        "flagged_count": len(flagged_checks),
        "passed_count": len(passed_checks)
    }


# ============================================================
# LIVE NETWORK HELPERS
# ============================================================

def verify_network_metadata(scheme, hostname, port):
    """Resolve the host and, for HTTPS, validate its TLS certificate.

    This deliberately does not request an HTTP page, follow redirects, or
    submit data. Network failures are returned as evidence rather than
    treated as proof that a domain is malicious.
    """
    checked_at = datetime.now(timezone.utc).isoformat()
    result = {
        "checked_at": checked_at,
        "dns": {"status": "failed", "addresses": [], "error": "Not checked"},
        "tls": {"status": "not_applicable", "subject": "", "expires": "", "error": ""}
    }

    if not hostname:
        result["dns"]["error"] = "No hostname was provided."
        return result

    try:
        address_info = socket.getaddrinfo(hostname, port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
        addresses = sorted({entry[4][0] for entry in address_info})
        result["dns"] = {"status": "resolved", "addresses": addresses, "error": ""}
    except (OSError, UnicodeError) as error:
        result["dns"]["error"] = str(error)

    if scheme != "https":
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port or 443), timeout=4) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secure_connection:
                certificate = secure_connection.getpeercert()
                subject = ", ".join(value for group in certificate.get("subject", ()) for key, value in group if key == "commonName")
                result["tls"] = {
                    "status": "valid",
                    "subject": subject,
                    "expires": certificate.get("notAfter", ""),
                    "error": ""
                }
    except (OSError, ssl.SSLError) as error:
        result["tls"]["status"] = "failed"
        result["tls"]["error"] = str(error)

    return result


# ============================================================
# HELPER FUNCTION
# ============================================================

def _is_ip(hostname):
    """Check if a hostname is an IP address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# ============================================================
# INPUT VALIDATION FUNCTION
# ============================================================

def validate_url(user_input):
    """
    Validate and clean the user's URL input.
    Returns (is_valid, cleaned_url_or_error_message)
    """

    # Step 1: Check if input is empty
    if not user_input or user_input.strip() == "":
        return False, "Please enter a URL to analyze."

    # Step 2: Remove extra spaces
    cleaned = user_input.strip()

    # Step 3: If no scheme is provided, add https://
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        # Check for other unsupported schemes
        if "://" in cleaned:
            scheme_part = cleaned.split("://")[0].lower()
            return False, (
                f"Unsupported URL scheme: '{scheme_part}'. "
                "Only 'http' and 'https' URLs are supported."
            )
        # Add https:// for convenience
        cleaned = "https://" + cleaned

    # Step 4: Parse the URL
    parsed = urlparse(cleaned)

    # Step 5: Check the scheme
    if parsed.scheme.lower() not in ("http", "https"):
        return False, (
            f"Unsupported URL scheme: '{parsed.scheme}'. "
            "Only 'http' and 'https' URLs are supported."
        )

    # Step 6: Check for a hostname
    if not parsed.hostname:
        return False, "The URL is missing a hostname (e.g., 'www.example.com')."

    # Step 7: Basic hostname check — must not be completely empty or just dots
    hostname = parsed.hostname
    if hostname.replace(".", "") == "":
        return False, "The hostname appears to be invalid."

    # Step 8: Check that hostname is not too short (at least "a.b")
    # Allow IP addresses through
    try:
        ipaddress.ip_address(hostname)
        # It's a valid IP, allow it
    except ValueError:
        # It's not an IP — check that it looks like a domain
        if "." not in hostname and hostname != "localhost":
            return False, (
                f"The hostname '{hostname}' does not appear to be "
                "a valid domain name. Did you mean "
                f"'https://{hostname}.com'?"
            )

    return True, cleaned


def build_pdf_report(analysis):
    """Build a readable, self-contained PDF report from an analysis result."""
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="Cyberguard URL Threat Analysis Report",
        author="Cyberguard URL Inspector",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=colors.HexColor("#12304a"),
        alignment=TA_CENTER, spaceAfter=5 * mm,
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", parent=styles["Normal"], fontSize=9, leading=13,
        textColor=colors.HexColor("#5f6f7f"), alignment=TA_CENTER,
        spaceAfter=7 * mm,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=colors.HexColor("#12304a"),
        spaceBefore=5 * mm, spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="BodySmall", parent=styles["BodyText"], fontSize=8.5, leading=12,
        textColor=colors.HexColor("#263746"),
    ))
    styles.add(ParagraphStyle(
        name="Cell", parent=styles["BodyText"], fontSize=8, leading=10,
        textColor=colors.HexColor("#263746"),
    ))
    styles.add(ParagraphStyle(
        name="CellBold", parent=styles["Cell"], fontName="Helvetica-Bold",
    ))

    def paragraph(value, style="Cell"):
        text = str(value if value not in (None, "") else "None")
        return Paragraph(text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), styles[style])

    def table(rows, widths):
        rendered = [[paragraph(cell, "CellBold" if index == 0 else "Cell")
                     for index, cell in enumerate(row)] for row in rows]
        result = Table(rendered, colWidths=widths, repeatRows=1)
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcecf4")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#12304a")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b7c8d3")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return result

    score = analysis["risk_score"]
    live = analysis.get("live_verification", {})
    dns = live.get("dns", {})
    tls = live.get("tls", {})
    story = [
        Paragraph("CYBERGUARD // URL THREAT ANALYSIS", styles["ReportTitle"]),
        Paragraph("Comprehensive local heuristic assessment", styles["Subtitle"]),
        table([
            ["Assessment", "Result"],
            ["Analyzed URL", analysis["url"]],
            ["Classification", analysis["classification"]],
            ["Risk score", f"{score}/100"],
            ["Generated (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Analysis scope", "URL structure, DNS metadata, and HTTPS certificate metadata"],
        ], [42 * mm, 132 * mm]),
        Paragraph("Executive Summary", styles["SectionHeading"]),
        Paragraph(
            f"The local rule engine assigned a risk score of <b>{score}/100</b> and "
            f"classified this URL as <b>{analysis['classification']}</b>. "
            f"{analysis['recommendation']}",
            styles["BodySmall"],
        ),
        Paragraph("Operator Recommendation", styles["SectionHeading"]),
        Paragraph(analysis["recommendation"], styles["BodySmall"]),
        Paragraph("URL Telemetry Breakdown", styles["SectionHeading"]),
    ]

    breakdown = analysis.get("url_breakdown", {})
    story.append(table(
        [["Component", "Observed value"]] +
        [[key.replace("_", " ").title(), value] for key, value in breakdown.items()],
        [52 * mm, 122 * mm],
    ))
    story.extend([
        Paragraph("Network Evidence", styles["SectionHeading"]),
        table([
            ["Evidence", "Status / details"],
            ["DNS resolution", f"{dns.get('status', 'unknown').upper()} — "
             f"{', '.join(dns.get('addresses', [])) or dns.get('error', 'No address data')}"],
            ["TLS certificate", f"{tls.get('status', 'unknown').upper()} — "
             f"{tls.get('subject') or tls.get('error') or 'Not applicable'}"],
            ["Checked at", live.get("checked_at", "Not recorded")],
        ], [52 * mm, 122 * mm]),
        Paragraph("Heuristic Rule Results", styles["SectionHeading"]),
    ])

    checks = analysis.get("flagged_checks", []) + analysis.get("passed_checks", [])
    check_rows = [["Rule", "Status", "Severity", "Finding"]]
    for check in checks:
        check_rows.append([
            check.get("rule", "Unknown"),
            check.get("status", "unknown").upper(),
            check.get("severity", "info").upper(),
            check.get("message", ""),
        ])
    story.append(table(check_rows, [39 * mm, 20 * mm, 23 * mm, 92 * mm]))
    story.extend([
        Paragraph("Assessment Notes and Limitations", styles["SectionHeading"]),
        Paragraph(
            "This report is based on transparent local heuristics. The analyzer does not "
            "download page content, execute scripts, submit forms, follow redirects, or "
            "query an online reputation database. DNS resolution and a valid TLS certificate "
            "are technical signals, not proof that a website is safe. A low score does not "
            "guarantee safety, and a high score does not by itself prove maliciousness.",
            styles["BodySmall"],
        ),
    ])

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#b7c8d3"))
        canvas.line(16 * mm, 12 * mm, 194 * mm, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5f6f7f"))
        canvas.drawString(16 * mm, 8 * mm, "CYBERGUARD // LOCAL ANALYSIS")
        canvas.drawRightString(194 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return buffer


# ============================================================
# FLASK ROUTES
# ============================================================

@app.route("/")
def home():
    """Display the main page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Receive a URL from the user, validate it,
    analyze it, and return the results as JSON.
    """

    # Get the URL from the form data
    user_url = request.form.get("url", "")

    # Validate the input
    is_valid, result = validate_url(user_url)

    if not is_valid:
        # Return an error message
        return jsonify({
            "success": False,
            "error": result
        })

    # The URL is valid — analyze it
    analysis = analyze_url(result)

    # Return the analysis results
    return jsonify({
        "success": True,
        "data": analysis
    })


@app.route("/report", methods=["POST"])
def report():
    """Generate a comprehensive PDF report for a validated URL."""
    user_url = request.form.get("url", "")
    is_valid, result = validate_url(user_url)
    if not is_valid:
        return jsonify({"success": False, "error": result}), 400

    analysis = analyze_url(result)
    report_file = build_pdf_report(analysis)
    return send_file(
        report_file,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="cyberguard-threat-analysis.pdf",
    )


# ============================================================
# RUN THE APPLICATION
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  URL SAFETY — Simple URL Risk Analyzer")
    print("  Open your browser at: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 50)

    # Run the Flask development server
    # host="127.0.0.1" means it only runs on your computer (not public)
    # debug=True will auto-reload when you change the code
    app.run(host="127.0.0.1", port=5000, debug=True)
