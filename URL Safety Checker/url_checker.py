import re
import socket
import ssl
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any, Tuple

class URLSafetyChecker:
    """Core analysis engine to validate URL format, HTTPS status, suspicious keywords, and risk score."""

    DEFAULT_KEYWORDS = {
        "login", "signin", "verify", "account", "banking", "update", "security",
        "password", "authenticate", "wallet", "claim", "bonus", "free", "paypal",
        "netbanking", "support-login", "confirm", "billing", "recovery", "crypto",
        "secure-update", "verification"
    }

    DEFAULT_SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov",
        ".click", ".work", ".download", ".link", ".rest", ".site", ".online"
    }

    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
    }

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".vbs", ".apk", ".js", ".py", ".dll", ".cmd", ".ps1"
    }

    TYPOSQUATTING_PATTERNS = [
        (r'g[0o]{2}gl[e3]', 'google'),
        (r'p[a4]yp[a4]l', 'paypal'),
        (r'm[i1]cr[0o]s[0o]ft', 'microsoft'),
        (r'[a4]ppl[e3]', 'apple'),
        (r'am[a4]z[0o]n', 'amazon'),
        (r'f[a4]c[e3]b[0o]{2}k', 'facebook'),
        (r'n[e3]tfl[i1]x', 'netflix')
    ]

    def __init__(self, custom_keywords: List[str] = None, custom_tlds: List[str] = None):
        self.keywords = set(custom_keywords) if custom_keywords else self.DEFAULT_KEYWORDS
        self.suspicious_tlds = set(custom_tlds) if custom_tlds else self.DEFAULT_SUSPICIOUS_TLDS

    def validate_url_format(self, url: str) -> Tuple[bool, str, Any]:
        """Validates if input string has proper URL format."""
        if not url:
            return False, "URL string is empty", None

        url_to_parse = url.strip()
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url_to_parse):
            # Prepend http:// for parsing if missing scheme
            url_to_parse = "http://" + url_to_parse

        try:
            parsed = urlparse(url_to_parse)
            if not parsed.netloc:
                return False, "Invalid URL structure: missing domain/hostname", None
            return True, "Valid URL format", parsed
        except Exception as e:
            return False, f"URL parse error: {str(e)}", None

    def analyze_url(self, url: str, perform_live_ssl: bool = False) -> Dict[str, Any]:
        valid, format_msg, parsed = self.validate_url_format(url)
        
        if not valid or not parsed:
            return {
                "url": url,
                "is_valid_format": False,
                "format_message": format_msg,
                "status": "INVALID_URL",
                "risk_score": 100,
                "findings": [{"rule": "Format Validation", "detail": format_msg, "risk_points": 100}]
            }

        findings = []
        risk_score = 0
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        full_decoded = unquote(url).lower()

        # 1. HTTPS Protocol Check
        is_https = (scheme == "https")
        if not is_https:
            risk_score += 20
            findings.append({
                "rule": "Insecure Protocol (No HTTPS)",
                "detail": f"URL uses unencrypted '{scheme.upper()}' scheme instead of HTTPS.",
                "risk_points": 20
            })
        else:
            findings.append({
                "rule": "HTTPS Check",
                "detail": "URL uses secure HTTPS protocol.",
                "risk_points": 0
            })

        # 2. Hostname & IP Address Analysis
        # Strip port if present
        host_without_port = netloc.split(":")[0]
        
        # Check IP address as hostname
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, host_without_port):
            risk_score += 30
            findings.append({
                "rule": "IP Address Hostname",
                "detail": f"URL uses raw IP address ({host_without_port}) instead of domain name.",
                "risk_points": 30
            })

        # Check @ symbol in netloc (credential spoofing trick)
        if "@" in netloc or "@" in url:
            risk_score += 35
            findings.append({
                "rule": "User Authentication @ Symbol",
                "detail": "URL contains '@' symbol, often used to obscure true destination domain.",
                "risk_points": 35
            })

        # Check excessive subdomains
        domain_parts = host_without_port.split(".")
        if len(domain_parts) > 3 and not re.match(ip_pattern, host_without_port):
            risk_score += 15
            findings.append({
                "rule": "Excessive Subdomains",
                "detail": f"Domain contains {len(domain_parts)-2} subdomains ({host_without_port}).",
                "risk_points": 15
            })

        # 3. TLD & Shortener Checks
        found_tld = ""
        for tld in self.suspicious_tlds:
            if host_without_port.endswith(tld):
                found_tld = tld
                break
        if found_tld:
            risk_score += 25
            findings.append({
                "rule": "Suspicious TLD",
                "detail": f"Domain uses high-risk Top Level Domain '{found_tld}'.",
                "risk_points": 25
            })

        if host_without_port in self.URL_SHORTENERS:
            risk_score += 15
            findings.append({
                "rule": "URL Shortener Detected",
                "detail": f"Domain '{host_without_port}' is a known URL shortening service.",
                "risk_points": 15
            })

        # 4. Keyword Identification
        matched_keywords = [kw for kw in self.keywords if kw in full_decoded]
        if matched_keywords:
            points = min(40, len(matched_keywords) * 15)
            risk_score += points
            findings.append({
                "rule": "Suspicious Phishing Keywords",
                "detail": f"Found sensitive/phishing keywords: {', '.join(matched_keywords)}",
                "risk_points": points
            })

        # 5. Suspicious File Extensions / Double Extensions
        path_lower = path.lower()
        found_exts = [ext for ext in self.SUSPICIOUS_EXTENSIONS if path_lower.endswith(ext) or (ext in path_lower and not path_lower.endswith(ext))]
        if found_exts:
            risk_score += 30
            findings.append({
                "rule": "Executable/Suspicious File Path",
                "detail": f"Path contains executable/suspicious file extension: {', '.join(found_exts)}",
                "risk_points": 30
            })

        # 6. Typosquatting Check
        typo_matches = []
        for pat, brand in self.TYPOSQUATTING_PATTERNS:
            if re.search(pat, host_without_port) and brand not in host_without_port:
                typo_matches.append(brand)
        if typo_matches:
            risk_score += 30
            findings.append({
                "rule": "Possible Typosquatting / Brand Impersonation",
                "detail": f"Domain looks similar to popular brand: {', '.join(typo_matches)}",
                "risk_points": 30
            })

        # Cap total risk score at 100
        risk_score = min(100, risk_score)

        # Determine Final Result Classification
        if risk_score >= 50:
            status = "SUSPICIOUS"
        elif risk_score >= 20:
            status = "LOW_TO_MEDIUM_RISK"
        else:
            status = "SAFE"

        # Optional Live SSL Connection Check
        ssl_info = None
        if perform_live_ssl and is_https:
            ssl_info = self._check_live_ssl(host_without_port, parsed.port or 443)

        return {
            "url": url,
            "is_valid_format": True,
            "format_message": "Valid URL format",
            "scheme": scheme,
            "domain": host_without_port,
            "is_https": is_https,
            "status": status,
            "risk_score": risk_score,
            "findings": findings,
            "ssl_info": ssl_info
        }

    def _check_live_ssl(self, host: str, port: int = 443) -> Dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    return {
                        "verified": True,
                        "subject_cn": subject.get('commonName', 'Unknown'),
                        "issuer_org": issuer.get('organizationName', 'Unknown'),
                    }
        except Exception as e:
            return {
                "verified": False,
                "error": str(e)
            }
