#!/usr/bin/env python3
"""
Site Security Report
--------------------
A defensive HTTP/web-security posture reporter inspired by the kind of
information shown by SecurityHeaders.com, but implemented independently.

Outputs:
  - PDF report
  - PNG report
  - JSON report (optional)

Install:
  pip install requests beautifulsoup4 dnspython reportlab pillow flask

Usage:
  python site_security.py
  python site_security_report.py example.com --format all
  python site_security_report.py https://example.com --format pdf --output report.pdf

Notes:
  - This is a passive web-security configuration scanner.
  - It does not exploit vulnerabilities.
  - It primarily inspects the supplied URL, its HTTP redirects, response
    headers, cookies, TLS certificate properties, and HTML.
  - For a deployed web service, consider blocking private/loopback targets
    to prevent SSRF. The CLI below supports --allow-private for local testing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import sys
import os
import threading
import webbrowser
from flask import Flask, request, render_template_string, send_file, url_for
import textwrap
import urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics


USER_AGENT = (
    "SiteSecurityReport/1.0 "
    "(passive security configuration scanner; +https://example.invalid)"
)

TIMEOUT = 15

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "pass": 5,
}


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str = ""


@dataclass
class Check:
    category: str
    name: str
    status: str
    severity: str
    value: str
    detail: str
    recommendation: str = ""


class SecurityScanner:
    def __init__(
        self,
        url: str,
        follow_redirects: bool = True,
        allow_private: bool = False,
    ):
        self.original_url = normalize_url(url)
        self.follow_redirects = follow_redirects
        self.allow_private = allow_private

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.response: Optional[requests.Response] = None
        self.headers: Dict[str, str] = {}
        self.cookies: List[Dict[str, Any]] = []
        self.checks: List[Check] = []
        self.findings: List[Finding] = []

        self.scan_time = dt.datetime.now(dt.timezone.utc)
        self.redirects: List[Dict[str, Any]] = []
        self.html_analysis: Dict[str, Any] = {}
        self.tls_analysis: Dict[str, Any] = {}
        self.dns_analysis: Dict[str, Any] = {}

    # ---------------------------
    # Main scan
    # ---------------------------

    def scan(self) -> Dict[str, Any]:
        self._validate_target()

        self.response = self.session.get(
            self.original_url,
            timeout=TIMEOUT,
            allow_redirects=self.follow_redirects,
            verify=True,
        )

        self.headers = {
            k.lower(): v.strip()
            for k, v in self.response.headers.items()
        }

        self._collect_redirects()
        self._collect_cookies()
        self._analyze_security_headers()
        self._analyze_information_disclosure()
        self._analyze_cors()
        self._analyze_cache()
        self._analyze_html()
        self._analyze_tls()
        self._analyze_dns()

        score, grade = calculate_score(self.checks)

        return {
            "meta": {
                "scanner": "Site Security Report",
                "version": "1.0",
                "scanned_at": self.scan_time.isoformat(),
                "requested_url": self.original_url,
                "final_url": self.response.url,
                "status_code": self.response.status_code,
                "elapsed_seconds": round(self.response.elapsed.total_seconds(), 3),
                "content_type": self.response.headers.get("Content-Type", ""),
                "server": self.response.headers.get("Server", ""),
                "ip": self._get_ip(),
            },
            "score": score,
            "grade": grade,
            "checks": [asdict(x) for x in self.checks],
            "findings": [asdict(x) for x in self.findings],
            "redirects": self.redirects,
            "cookies": self.cookies,
            "html": self.html_analysis,
            "tls": self.tls_analysis,
            "dns": self.dns_analysis,
            "raw_headers": dict(self.response.headers),
        }

    # ---------------------------
    # Target / networking
    # ---------------------------

    def _validate_target(self):
        parsed = urllib.parse.urlparse(self.original_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only http:// and https:// URLs are supported.")
        if not parsed.hostname:
            raise ValueError("Invalid URL: hostname is missing.")

        if self.allow_private:
            return

        try:
            addresses = socket.getaddrinfo(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(f"DNS lookup failed for target: {exc}") from exc

        for item in addresses:
            ip_text = item[4][0]
            ip = ipaddress.ip_address(ip_text)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                raise ValueError(
                    f"Target resolves to a non-public address ({ip_text}). "
                    "Use --allow-private only for trusted local testing."
                )

    def _get_ip(self) -> str:
        try:
            host = urllib.parse.urlparse(self.response.url).hostname
            if not host:
                return ""
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def _collect_redirects(self):
        if not self.response:
            return

        for r in self.response.history:
            self.redirects.append(
                {
                    "status": r.status_code,
                    "from": r.url,
                    "location": r.headers.get("Location", ""),
                    "to": urllib.parse.urljoin(
                        r.url, r.headers.get("Location", "")
                    ),
                }
            )

        self.redirects.append(
            {
                "status": self.response.status_code,
                "from": self.response.url,
                "location": "",
                "to": self.response.url,
            }
        )

        if len(self.response.history) > 5:
            self.findings.append(
                Finding(
                    "Transport / Redirects",
                    "medium",
                    "Long redirect chain",
                    f"{len(self.response.history)} redirects were followed.",
                    "Reduce unnecessary redirects and avoid chains.",
                )
            )

        if urllib.parse.urlparse(self.original_url).scheme == "http":
            final_scheme = urllib.parse.urlparse(self.response.url).scheme
            if final_scheme != "https":
                self.findings.append(
                    Finding(
                        "Transport / TLS",
                        "high",
                        "HTTP target did not end on HTTPS",
                        "The requested URL did not reach an HTTPS final URL.",
                        "Serve the site over HTTPS and redirect HTTP to HTTPS.",
                    )
                )

    # ---------------------------
    # Cookie analysis
    # ---------------------------

    def _collect_cookies(self):
        raw = self.response.raw.headers.get_all("Set-Cookie", [])
        if not raw:
            # Some adapters expose combined headers differently.
            combined = self.response.headers.get("Set-Cookie")
            if combined:
                raw = [combined]

        for cookie_line in raw:
            parts = [p.strip() for p in cookie_line.split(";")]
            if not parts or "=" not in parts[0]:
                continue

            name = parts[0].split("=", 1)[0].strip()
            attrs = {p.split("=", 1)[0].lower(): p for p in parts[1:]}
            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = None

            for p in parts[1:]:
                if p.lower().startswith("samesite="):
                    samesite = p.split("=", 1)[1].strip()

            item = {
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "raw": cookie_line,
            }
            self.cookies.append(item)

            if urllib.parse.urlparse(self.response.url).scheme == "https" and not secure:
                self.findings.append(
                    Finding(
                        "Cookies",
                        "medium",
                        f"Cookie '{name}' lacks Secure",
                        "The cookie can potentially be sent over a non-HTTPS connection.",
                        "Add the Secure attribute to cookies that should only travel over HTTPS.",
                    )
                )

            if not httponly:
                self.findings.append(
                    Finding(
                        "Cookies",
                        "low",
                        f"Cookie '{name}' lacks HttpOnly",
                        "JavaScript can access this cookie through document.cookie.",
                        "Use HttpOnly for cookies that do not need client-side JavaScript access.",
                    )
                )

            if not samesite:
                self.findings.append(
                    Finding(
                        "Cookies",
                        "low",
                        f"Cookie '{name}' lacks SameSite",
                        "No SameSite policy was declared.",
                        "Consider SameSite=Lax or SameSite=Strict where compatible.",
                    )
                )

    # ---------------------------
    # Security headers
    # ---------------------------

    def _add_check(
        self,
        category: str,
        name: str,
        status: str,
        severity: str,
        value: str,
        detail: str,
        recommendation: str = "",
    ):
        self.checks.append(
            Check(
                category,
                name,
                status,
                severity,
                value,
                detail,
                recommendation,
            )
        )

    def _analyze_security_headers(self):
        h = self.headers

        # HSTS
        hsts = h.get("strict-transport-security")
        if urllib.parse.urlparse(self.response.url).scheme != "https":
            self._add_check(
                "Security Headers",
                "Strict-Transport-Security",
                "N/A",
                "info",
                hsts or "",
                "HSTS is meaningful for HTTPS responses.",
            )
        elif not hsts:
            self._add_check(
                "Security Headers",
                "Strict-Transport-Security",
                "FAIL",
                "high",
                "",
                "HSTS is missing from the HTTPS response.",
                "Add Strict-Transport-Security with an appropriate max-age.",
            )
        else:
            max_age = extract_int(hsts, r"max-age\s*=\s*(\d+)")
            include_subdomains = "includesubdomains" in hsts.lower()
            preload = "preload" in hsts.lower()

            if max_age is None:
                status, sev = "WARN", "medium"
                detail = "HSTS exists but max-age could not be parsed."
            elif max_age < 15552000:
                status, sev = "WARN", "medium"
                detail = f"HSTS max-age is only {max_age} seconds."
            else:
                status, sev = "PASS", "pass"
                detail = f"HSTS max-age is {max_age} seconds."

            self._add_check(
                "Security Headers",
                "Strict-Transport-Security",
                status,
                sev,
                hsts,
                detail,
                "Use a sufficiently long max-age after validating your HTTPS deployment.",
            )

            if not include_subdomains:
                self.findings.append(
                    Finding(
                        "Security Headers",
                        "low",
                        "HSTS does not include subdomains",
                        "includeSubDomains was not present.",
                        "Use includeSubDomains if all relevant subdomains are HTTPS-ready.",
                    )
                )

        # CSP
        csp = h.get("content-security-policy")
        if not csp:
            self._add_check(
                "Security Headers",
                "Content-Security-Policy",
                "FAIL",
                "high",
                "",
                "No Content-Security-Policy header was observed.",
                "Define a restrictive CSP appropriate for the application.",
            )
        else:
            csp_lower = csp.lower()
            issues = []

            if "'unsafe-eval'" in csp_lower:
                issues.append("unsafe-eval")
            if "'unsafe-inline'" in csp_lower:
                issues.append("unsafe-inline")
            if "default-src *" in csp_lower:
                issues.append("default-src *")
            if "script-src *" in csp_lower:
                issues.append("script-src *")
            if "object-src *" in csp_lower:
                issues.append("object-src *")

            has_frame_ancestors = "frame-ancestors" in csp_lower
            has_default_or_script = (
                "default-src" in csp_lower or "script-src" in csp_lower
            )

            if issues:
                self._add_check(
                    "Security Headers",
                    "Content-Security-Policy",
                    "WARN",
                    "medium",
                    csp,
                    "Potentially permissive CSP directives detected: "
                    + ", ".join(issues),
                    "Review CSP directives and remove unnecessary unsafe or wildcard sources.",
                )
            elif not has_default_or_script:
                self._add_check(
                    "Security Headers",
                    "Content-Security-Policy",
                    "WARN",
                    "medium",
                    csp,
                    "CSP exists but does not contain an obvious default-src or script-src policy.",
                    "Review the policy for complete coverage.",
                )
            else:
                self._add_check(
                    "Security Headers",
                    "Content-Security-Policy",
                    "PASS",
                    "pass",
                    csp,
                    "CSP is present and no obvious high-level wildcard/unsafe patterns were found.",
                )

            if not has_frame_ancestors:
                self.findings.append(
                    Finding(
                        "Security Headers",
                        "low",
                        "CSP has no frame-ancestors directive",
                        "Clickjacking protection may depend on another mechanism.",
                        "Consider frame-ancestors 'none' or an appropriate allowlist.",
                    )
                )

        # X-Content-Type-Options
        xcto = h.get("x-content-type-options")
        if xcto and xcto.lower().strip() == "nosniff":
            self._add_check(
                "Security Headers",
                "X-Content-Type-Options",
                "PASS",
                "pass",
                xcto,
                "Correct nosniff value detected.",
            )
        else:
            self._add_check(
                "Security Headers",
                "X-Content-Type-Options",
                "FAIL",
                "medium",
                xcto or "",
                "Missing or invalid X-Content-Type-Options.",
                "Set X-Content-Type-Options: nosniff.",
            )

        # X-Frame-Options
        xfo = h.get("x-frame-options")
        frame_protected_by_csp = bool(
            csp and "frame-ancestors" in csp.lower()
        )

        if xfo:
            valid = xfo.lower().strip() in ("deny", "sameorigin") or xfo.lower().startswith(
                "allow-from "
            )
            self._add_check(
                "Security Headers",
                "X-Frame-Options",
                "PASS" if valid else "WARN",
                "pass" if valid else "medium",
                xfo,
                "Frame embedding policy was detected."
                if valid
                else "X-Frame-Options contains an unusual value.",
                "Prefer DENY/SAMEORIGIN where appropriate; CSP frame-ancestors is the modern control.",
            )
        elif frame_protected_by_csp:
            self._add_check(
                "Security Headers",
                "X-Frame-Options",
                "PASS",
                "pass",
                "",
                "No X-Frame-Options, but CSP frame-ancestors is present.",
            )
        else:
            self._add_check(
                "Security Headers",
                "X-Frame-Options",
                "FAIL",
                "medium",
                "",
                "No obvious clickjacking protection was detected.",
                "Use CSP frame-ancestors and/or X-Frame-Options as appropriate.",
            )

        # Referrer-Policy
        referrer = h.get("referrer-policy")
        allowed_referrer = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "unsafe-url",
        }
        if not referrer:
            self._add_check(
                "Security Headers",
                "Referrer-Policy",
                "FAIL",
                "medium",
                "",
                "Referrer-Policy is missing.",
                "Use a privacy-preserving policy such as strict-origin-when-cross-origin.",
            )
        else:
            token = referrer.lower().split(",")[0].strip()
            self._add_check(
                "Security Headers",
                "Referrer-Policy",
                "PASS" if token in allowed_referrer else "WARN",
                "pass" if token in allowed_referrer else "low",
                referrer,
                "Referrer policy detected.",
            )

        # Permissions-Policy
        pp = h.get("permissions-policy")
        if pp:
            self._add_check(
                "Security Headers",
                "Permissions-Policy",
                "PASS",
                "pass",
                pp,
                "Permissions-Policy is present.",
            )
        else:
            self._add_check(
                "Security Headers",
                "Permissions-Policy",
                "WARN",
                "low",
                "",
                "Permissions-Policy is missing.",
                "Declare browser capabilities that the application does not need.",
            )

        # Cross-origin policies
        for header, recommendation in [
            (
                "cross-origin-opener-policy",
                "Consider same-origin where compatible with the application.",
            ),
            (
                "cross-origin-resource-policy",
                "Consider same-origin or same-site where compatible.",
            ),
            (
                "cross-origin-embedder-policy",
                "Consider require-corp where cross-origin isolation is appropriate.",
            ),
        ]:
            value = h.get(header)
            if value:
                self._add_check(
                    "Cross-Origin Isolation",
                    header.title(),
                    "PASS",
                    "pass",
                    value,
                    f"{header} is present.",
                )
            else:
                self._add_check(
                    "Cross-Origin Isolation",
                    header.title(),
                    "INFO",
                    "info",
                    "",
                    f"{header} is not present.",
                    recommendation,
                )

        # COOP opener policy deserves special attention if missing.
        if not h.get("cross-origin-opener-policy"):
            self.findings.append(
                Finding(
                    "Cross-Origin Isolation",
                    "info",
                    "Cross-Origin-Opener-Policy not observed",
                    "The site does not opt into a COOP policy on this response.",
                    "Consider COOP if your application benefits from cross-origin isolation.",
                )
            )

    # ---------------------------
    # Information disclosure
    # ---------------------------

    def _analyze_information_disclosure(self):
        server = self.headers.get("server")
        powered = self.headers.get("x-powered-by")
        aspnet = self.headers.get("x-aspnet-version")

        if server:
            if re.search(r"/\d", server):
                self.findings.append(
                    Finding(
                        "Information Disclosure",
                        "low",
                        "Server header exposes version information",
                        f"Observed Server: {server}",
                        "Minimize unnecessary software/version disclosure.",
                    )
                )
                self._add_check(
                    "Information Disclosure",
                    "Server",
                    "WARN",
                    "low",
                    server,
                    "Server appears to include a version string.",
                )
            else:
                self._add_check(
                    "Information Disclosure",
                    "Server",
                    "INFO",
                    "info",
                    server,
                    "Server header is present without an obvious version.",
                )
        else:
            self._add_check(
                "Information Disclosure",
                "Server",
                "PASS",
                "pass",
                "",
                "No Server header was observed.",
            )

        if powered:
            self.findings.append(
                Finding(
                    "Information Disclosure",
                    "low",
                    "X-Powered-By exposes technology information",
                    f"Observed X-Powered-By: {powered}",
                    "Remove the header where practical.",
                )
            )

        if aspnet:
            self.findings.append(
                Finding(
                    "Information Disclosure",
                    "low",
                    "ASP.NET version information exposed",
                    f"Observed X-AspNet-Version: {aspnet}",
                    "Disable unnecessary framework version disclosure.",
                )
            )

        for header in ("x-aspnetmvc-version", "x-generator", "x-drupal-cache"):
            if header in self.headers:
                self.findings.append(
                    Finding(
                        "Information Disclosure",
                        "low",
                        f"{header} is exposed",
                        f"Observed {header}: {self.headers[header]}",
                        "Review whether the header is necessary.",
                    )
                )

    # ---------------------------
    # CORS
    # ---------------------------

    def _analyze_cors(self):
        acao = self.headers.get("access-control-allow-origin")
        acac = self.headers.get("access-control-allow-credentials")

        if not acao:
            self._add_check(
                "CORS",
                "Access-Control-Allow-Origin",
                "INFO",
                "info",
                "",
                "No CORS allow-origin header was observed.",
            )
            return

        if acao.strip() == "*" and acac and acac.lower() == "true":
            self._add_check(
                "CORS",
                "Access-Control-Allow-Origin",
                "WARN",
                "high",
                acao,
                "Wildcard CORS origin was observed together with credentials=true.",
                "Avoid wildcard origins for credentialed cross-origin requests.",
            )
            self.findings.append(
                Finding(
                    "CORS",
                    "high",
                    "Potentially unsafe credentialed CORS configuration",
                    "Access-Control-Allow-Origin: * was observed with Access-Control-Allow-Credentials: true.",
                    "Use an explicit trusted origin allowlist.",
                )
            )
        elif acao.strip() == "*":
            self._add_check(
                "CORS",
                "Access-Control-Allow-Origin",
                "WARN",
                "low",
                acao,
                "Wildcard CORS origin is allowed.",
                "Use an explicit allowlist when cross-origin access is not intended to be public.",
            )
        else:
            self._add_check(
                "CORS",
                "Access-Control-Allow-Origin",
                "PASS",
                "pass",
                acao,
                "An explicit CORS origin policy was observed.",
            )

    # ---------------------------
    # Cache
    # ---------------------------

    def _analyze_cache(self):
        cache = self.headers.get("cache-control", "")
        pragma = self.headers.get("pragma", "")

        if "no-store" in cache.lower():
            status = "PASS"
            sev = "pass"
            detail = "no-store is present."
        elif "private" in cache.lower():
            status = "PASS"
            sev = "pass"
            detail = "private caching is present."
        elif cache:
            status = "INFO"
            sev = "info"
            detail = "Cache-Control is present; review whether it matches the sensitivity of the content."
        else:
            status = "INFO"
            sev = "info"
            detail = "No Cache-Control header was observed."

        self._add_check(
            "Caching",
            "Cache-Control",
            status,
            sev,
            cache,
            detail,
        )

        if "set-cookie" in self.headers and cache and "public" in cache.lower():
            self.findings.append(
                Finding(
                    "Caching",
                    "medium",
                    "Public caching observed with Set-Cookie",
                    "The response sets cookies while Cache-Control contains public.",
                    "Review whether personalized or sensitive content can be cached publicly.",
                )
            )

    # ---------------------------
    # HTML analysis
    # ---------------------------

    def _analyze_html(self):
        content_type = self.response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            self.html_analysis = {
                "is_html": False,
                "message": "Final response is not identified as HTML.",
            }
            return

        soup = BeautifulSoup(self.response.text, "html.parser")

        scripts = soup.find_all("script")
        inline_scripts = [
            s for s in scripts if not s.get("src") and s.get_text(strip=True)
        ]
        external_scripts = [s.get("src") for s in scripts if s.get("src")]

        forms = soup.find_all("form")
        password_forms = []
        insecure_password_forms = []

        for form in forms:
            inputs = form.find_all("input")
            if any((i.get("type") or "").lower() == "password" for i in inputs):
                password_forms.append(form)
                action = form.get("action", "")
                resolved = urllib.parse.urljoin(self.response.url, action)
                if urllib.parse.urlparse(resolved).scheme != "https":
                    insecure_password_forms.append(resolved)

        mixed_content = []
        page_scheme = urllib.parse.urlparse(self.response.url).scheme

        if page_scheme == "https":
            for tag in soup.find_all(src=True):
                src = tag.get("src")
                if isinstance(src, str) and src.lower().startswith("http://"):
                    mixed_content.append(src)
            for tag in soup.find_all(href=True):
                href = tag.get("href")
                if isinstance(href, str) and href.lower().startswith("http://"):
                    if tag.name in ("link", "script", "img", "iframe", "audio", "video"):
                        mixed_content.append(href)

        if inline_scripts:
            self.findings.append(
                Finding(
                    "HTML / JavaScript",
                    "low",
                    "Inline JavaScript detected",
                    f"{len(inline_scripts)} inline script block(s) were found.",
                    "Prefer nonces/hashes with a strict CSP instead of broad unsafe-inline.",
                )
            )

        if mixed_content:
            self.findings.append(
                Finding(
                    "HTML / Transport",
                    "high",
                    "Potential mixed content detected",
                    f"{len(mixed_content)} HTTP resource reference(s) were found on an HTTPS page.",
                    "Load active and sensitive resources over HTTPS.",
                )
            )

        if insecure_password_forms:
            self.findings.append(
                Finding(
                    "HTML / Forms",
                    "high",
                    "Password form submits to HTTP",
                    f"{len(insecure_password_forms)} password form(s) resolve to HTTP.",
                    "Submit credentials only over HTTPS.",
                )
            )

        self.html_analysis = {
            "is_html": True,
            "title": soup.title.get_text(" ", strip=True) if soup.title else "",
            "scripts": len(scripts),
            "inline_scripts": len(inline_scripts),
            "external_scripts": len(external_scripts),
            "external_script_urls": external_scripts[:100],
            "forms": len(forms),
            "password_forms": len(password_forms),
            "insecure_password_forms": insecure_password_forms,
            "mixed_content": mixed_content[:100],
            "iframes": len(soup.find_all("iframe")),
            "images": len(soup.find_all("img")),
            "links": len(soup.find_all("a")),
        }

        # Target blank without rel=noopener
        unsafe_blank = []
        for a in soup.find_all("a", href=True):
            if a.get("target", "").lower() == "_blank":
                rel = {x.lower() for x in (a.get("rel") or [])}
                if "noopener" not in rel and "noreferrer" not in rel:
                    unsafe_blank.append(a.get("href"))

        if unsafe_blank:
            self.findings.append(
                Finding(
                    "HTML / Links",
                    "low",
                    "target=_blank links without noopener/noreferrer",
                    f"{len(unsafe_blank)} link(s) were found.",
                    "Use rel=\"noopener\" (and optionally noreferrer) on untrusted/new-tab links.",
                )
            )

    # ---------------------------
    # TLS
    # ---------------------------

    def _analyze_tls(self):
        parsed = urllib.parse.urlparse(self.response.url)
        if parsed.scheme != "https":
            self.tls_analysis = {
                "https": False,
                "message": "Final URL is not HTTPS.",
            }
            self._add_check(
                "TLS",
                "HTTPS",
                "FAIL",
                "high",
                "",
                "Final URL is not HTTPS.",
                "Serve the site over HTTPS.",
            )
            return

        host = parsed.hostname
        port = parsed.port or 443

        context = ssl.create_default_context()

        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")

                    days_remaining = None
                    if not_after:
                        try:
                            expiry = dt.datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=dt.timezone.utc)
                            days_remaining = (expiry - dt.datetime.now(dt.timezone.utc)).days
                        except Exception:
                            pass

                    san = []
                    for key, values in cert.get("subjectAltName", []):
                        if key == "DNS":
                            san.append(values)

                    self.tls_analysis = {
                        "https": True,
                        "version": tls_version,
                        "cipher": cipher[0] if cipher else "",
                        "certificate_subject": cert.get("subject", ""),
                        "certificate_issuer": cert.get("issuer", ""),
                        "not_before": not_before,
                        "not_after": not_after,
                        "days_remaining": days_remaining,
                        "san_count": len(san),
                    }

                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self._add_check(
                            "TLS",
                            "TLS Protocol",
                            "FAIL",
                            "high",
                            tls_version,
                            "An obsolete TLS protocol was negotiated.",
                            "Disable obsolete protocols and require modern TLS.",
                        )
                    else:
                        self._add_check(
                            "TLS",
                            "TLS Protocol",
                            "PASS",
                            "pass",
                            tls_version or "",
                            "A modern TLS protocol was negotiated.",
                        )

                    if days_remaining is not None:
                        if days_remaining < 0:
                            self._add_check(
                                "TLS",
                                "Certificate Expiry",
                                "FAIL",
                                "critical",
                                not_after or "",
                                "Certificate appears to be expired.",
                                "Renew the certificate immediately.",
                            )
                        elif days_remaining < 30:
                            self._add_check(
                                "TLS",
                                "Certificate Expiry",
                                "WARN",
                                "high",
                                not_after or "",
                                f"Certificate expires in approximately {days_remaining} days.",
                                "Renew before expiration.",
                            )
                        else:
                            self._add_check(
                                "TLS",
                                "Certificate Expiry",
                                "PASS",
                                "pass",
                                not_after or "",
                                f"Certificate has approximately {days_remaining} days remaining.",
                            )

        except Exception as exc:
            self.tls_analysis = {
                "https": True,
                "error": str(exc),
            }
            self._add_check(
                "TLS",
                "TLS Inspection",
                "WARN",
                "medium",
                "",
                f"Could not inspect the TLS certificate directly: {exc}",
            )

    # ---------------------------
    # DNS
    # ---------------------------

    def _analyze_dns(self):
        host = urllib.parse.urlparse(self.response.url).hostname
        result: Dict[str, Any] = {"hostname": host, "a": [], "aaaa": []}

        if not host:
            self.dns_analysis = result
            return

        try:
            infos = socket.getaddrinfo(host, None)
            for item in infos:
                addr = item[4][0]
                if ":" in addr:
                    if addr not in result["aaaa"]:
                        result["aaaa"].append(addr)
                else:
                    if addr not in result["a"]:
                        result["a"].append(addr)
        except Exception as exc:
            result["error"] = str(exc)

        self.dns_analysis = result

    # ---------------------------
    # Utility
    # ---------------------------

    def add_summary_findings(self):
        # Convert missing/high checks into findings for the report.
        for c in self.checks:
            if c.status in ("FAIL", "WARN") and c.recommendation:
                self.findings.append(
                    Finding(
                        c.category,
                        c.severity,
                        c.name,
                        c.detail,
                        c.recommendation,
                    )
                )


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def extract_int(value: str, pattern: str) -> Optional[int]:
    m = re.search(pattern, value, re.I)
    return int(m.group(1)) if m else None


def calculate_score(checks: List[Check]) -> Tuple[int, str]:
    """
    Deliberately simple and transparent scoring.

    This is NOT an official SecurityHeaders.com score.
    It is an independent posture score for this scanner.
    """
    score = 100

    weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
        "pass": 0,
    }

    for c in checks:
        if c.status == "FAIL":
            score -= weights.get(c.severity, 5)
        elif c.status == "WARN":
            score -= max(2, weights.get(c.severity, 3) // 2)

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


# ============================================================
# REPORT RENDERING
# ============================================================

def safe_font(size: int, bold: bool = False):
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]

    for path in candidates:
        if Path(path).exists():
            name = "CustomBold" if bold else "CustomRegular"
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                return name, size
            except Exception:
                pass

    return "Helvetica-Bold" if bold else "Helvetica", size


def status_color(status: str):
    return {
        "PASS": colors.HexColor("#14833B"),
        "FAIL": colors.HexColor("#D71920"),
        "WARN": colors.HexColor("#C47A00"),
        "INFO": colors.HexColor("#3568B8"),
        "N/A": colors.HexColor("#777777"),
    }.get(status, colors.HexColor("#777777"))


def grade_color(grade: str):
    return {
        "A+": "#14833B",
        "A": "#2E8B57",
        "B": "#4C8C2B",
        "C": "#C47A00",
        "D": "#D66A00",
        "F": "#C62828",
    }.get(grade, "#555555")


def build_pdf(data: Dict[str, Any], output: str):
    regular, regular_size = safe_font(9, False)
    bold, bold_size = safe_font(9, True)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName=bold,
        fontSize=24,
        leading=28,
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName=bold,
        fontSize=14,
        leading=18,
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName=regular,
        fontSize=8.5,
        leading=12,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=body_style,
        fontSize=7.5,
        leading=10,
    )

    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="Site Security Report",
        author="Site Security Report",
    )

    story = []

    meta = data["meta"]
    score = data["score"]
    grade = data["grade"]

    story.append(Paragraph("SITE SECURITY REPORT", title_style))
    story.append(
        Paragraph(
            f"<b>Target:</b> {escape(meta['requested_url'])}<br/>"
            f"<b>Final URL:</b> {escape(meta['final_url'])}<br/>"
            f"<b>Status:</b> {meta['status_code']} &nbsp;&nbsp; "
            f"<b>IP:</b> {escape(meta.get('ip', ''))}<br/>"
            f"<b>Scanned:</b> {escape(meta['scanned_at'])}",
            body_style,
        )
    )
    story.append(Spacer(1, 8))

    summary = Table(
        [
            [
                Paragraph(
                    f"<font size='36'><b>{grade}</b></font><br/>"
                    f"<font size='12'>{score}/100</font>",
                    ParagraphStyle(
                        "Grade",
                        parent=body_style,
                        alignment=TA_CENTER,
                        textColor=colors.white,
                    ),
                ),
                Paragraph(
                    "<b>Security posture</b><br/>"
                    "This report evaluates observable HTTP/TLS/browser security "
                    "configuration. It is not a penetration test.",
                    body_style,
                ),
            ]
        ],
        colWidths=[42 * mm, 135 * mm],
    )

    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(grade_color(grade))),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#EEF5FC")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#B7C7D8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D4DEE8")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )

    story.append(summary)
    story.append(Spacer(1, 10))

    # Quick stats
    checks = data["checks"]
    stats = {
        "PASS": sum(1 for c in checks if c["status"] == "PASS"),
        "WARN": sum(1 for c in checks if c["status"] == "WARN"),
        "FAIL": sum(1 for c in checks if c["status"] == "FAIL"),
        "INFO": sum(1 for c in checks if c["status"] == "INFO"),
    }

    stats_table = Table(
        [
            [
                Paragraph(f"<b>{stats['PASS']}</b><br/>Passed", body_style),
                Paragraph(f"<b>{stats['WARN']}</b><br/>Warnings", body_style),
                Paragraph(f"<b>{stats['FAIL']}</b><br/>Failed", body_style),
                Paragraph(f"<b>{stats['INFO']}</b><br/>Info", body_style),
            ]
        ],
        colWidths=[44 * mm] * 4,
    )
    stats_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(stats_table)

    # Findings
    story.append(Paragraph("Priority Findings", heading_style))

    findings = sorted(
        data["findings"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 9),
    )

    if not findings:
        story.append(
            Paragraph(
                "No findings were generated by the configured checks.",
                body_style,
            )
        )
    else:
        rows = [
            [
                Paragraph("<b>Severity</b>", small_style),
                Paragraph("<b>Category</b>", small_style),
                Paragraph("<b>Finding</b>", small_style),
                Paragraph("<b>Recommendation</b>", small_style),
            ]
        ]

        for f in findings[:100]:
            rows.append(
                [
                    Paragraph(
                        f"<b>{escape(f['severity'].upper())}</b>",
                        small_style,
                    ),
                    Paragraph(escape(f["category"]), small_style),
                    Paragraph(
                        f"<b>{escape(f['title'])}</b><br/>{escape(f['detail'])}",
                        small_style,
                    ),
                    Paragraph(escape(f.get("recommendation", "")), small_style),
                ]
            )

        table = Table(
            rows,
            colWidths=[22 * mm, 32 * mm, 62 * mm, 61 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDEAF7")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8C5D1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7DEE5")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(table)

    # Checks
    story.append(Paragraph("Security Checks", heading_style))

    check_rows = [
        [
            Paragraph("<b>Category</b>", small_style),
            Paragraph("<b>Check</b>", small_style),
            Paragraph("<b>Status</b>", small_style),
            Paragraph("<b>Observed value / detail</b>", small_style),
        ]
    ]

    for c in checks:
        value = c["value"] or c["detail"]
        if len(value) > 500:
            value = value[:500] + "…"

        check_rows.append(
            [
                Paragraph(escape(c["category"]), small_style),
                Paragraph(escape(c["name"]), small_style),
                Paragraph(
                    f"<font color='{status_color(c['status']).hexval()}'>"
                    f"<b>{escape(c['status'])}</b></font>",
                    small_style,
                ),
                Paragraph(escape(value), small_style),
            ]
        )

    checks_table = Table(
        check_rows,
        colWidths=[35 * mm, 47 * mm, 22 * mm, 73 * mm],
        repeatRows=1,
    )
    checks_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDEAF7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8C5D1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7DEE5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(checks_table)

    # Cookies
    story.append(PageBreak())
    story.append(Paragraph("Cookie Security", heading_style))

    cookie_rows = [
        [
            Paragraph("<b>Name</b>", small_style),
            Paragraph("<b>Secure</b>", small_style),
            Paragraph("<b>HttpOnly</b>", small_style),
            Paragraph("<b>SameSite</b>", small_style),
        ]
    ]

    for c in data["cookies"]:
        cookie_rows.append(
            [
                Paragraph(escape(c["name"]), small_style),
                Paragraph("YES" if c["secure"] else "NO", small_style),
                Paragraph("YES" if c["httponly"] else "NO", small_style),
                Paragraph(escape(c["samesite"] or "missing"), small_style),
            ]
        )

    if len(cookie_rows) == 1:
        cookie_rows.append(
            [Paragraph("No Set-Cookie headers observed.", small_style), "", "", ""]
        )

    cookie_table = Table(
        cookie_rows,
        colWidths=[70 * mm, 30 * mm, 30 * mm, 40 * mm],
        repeatRows=1,
    )
    cookie_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDEAF7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8C5D1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7DEE5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(cookie_table)

    # TLS / DNS / HTML
    story.append(Paragraph("TLS / DNS / HTML Observations", heading_style))

    tls = data["tls"]
    dns = data["dns"]
    html = data["html"]

    details = [
        "<b>TLS</b><br/>" + escape(json.dumps(tls, indent=2, default=str)),
        "<b>DNS</b><br/>" + escape(json.dumps(dns, indent=2, default=str)),
        "<b>HTML</b><br/>" + escape(json.dumps(html, indent=2, default=str)),
    ]

    for d in details:
        story.append(
            Paragraph(
                d.replace("\n", "<br/>"),
                small_style,
            )
        )
        story.append(Spacer(1, 6))

    # Redirects
    story.append(Paragraph("Redirect Chain", heading_style))
    redirect_rows = [
        [
            Paragraph("<b>Status</b>", small_style),
            Paragraph("<b>From</b>", small_style),
            Paragraph("<b>To</b>", small_style),
        ]
    ]
    for r in data["redirects"]:
        redirect_rows.append(
            [
                Paragraph(str(r["status"]), small_style),
                Paragraph(escape(r["from"]), small_style),
                Paragraph(escape(r["to"]), small_style),
            ]
        )

    redirect_table = Table(
        redirect_rows,
        colWidths=[20 * mm, 75 * mm, 75 * mm],
        repeatRows=1,
    )
    redirect_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DDEAF7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8C5D1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7DEE5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(redirect_table)

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "<b>Methodology note:</b> This report is an independent passive "
            "configuration assessment. A PASS does not prove that an application "
            "is free of vulnerabilities, and a missing header does not necessarily "
            "mean the application is exploitable. Header recommendations should be "
            "reviewed against the application's functionality and threat model.",
            small_style,
        )
    )

    doc.build(story)


def escape(value: Any) -> str:
    if value is None:
        return ""
    s = str(value)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def load_font(size: int, bold: bool = False):
    names = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    for path in names:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                pass
    return ImageFont.load_default()


def build_png(data: Dict[str, Any], output: str):
    """
    Render a long, readable PNG report using Pillow.
    """
    width = 1800
    margin = 70
    bg = (247, 249, 252)
    ink = (35, 43, 52)
    muted = (93, 105, 118)
    panel = (255, 255, 255)
    border = (205, 215, 225)

    img = Image.new("RGB", (width, 1200), bg)
    draw = ImageDraw.Draw(img)

    title_font = load_font(54, True)
    h_font = load_font(31, True)
    body_font = load_font(22, False)
    body_bold = load_font(22, True)
    small_font = load_font(18, False)
    grade_font = load_font(90, True)

    y = 55

    def ensure(height_needed):
        nonlocal img, draw, y
        if y + height_needed > img.height - 50:
            new_height = max(img.height * 2, y + height_needed + 100)
            new = Image.new("RGB", (width, new_height), bg)
            new.paste(img, (0, 0))
            img = new
            draw = ImageDraw.Draw(img)

    def text(txt, x, yy, font=body_font, fill=ink, max_width=None, line_spacing=8):
        if max_width:
            words = str(txt).split()
            lines = []
            line = ""
            for word in words:
                test = (line + " " + word).strip()
                if draw.textbbox((0, 0), test, font=font)[2] <= max_width:
                    line = test
                else:
                    if line:
                        lines.append(line)
                    line = word
            if line:
                lines.append(line)
        else:
            lines = str(txt).splitlines()

        for line in lines:
            draw.text((x, yy), line, font=font, fill=fill)
            yy += font.size + line_spacing
        return yy

    # Header
    draw.rectangle((0, 0, width, 210), fill=(235, 112, 20))
    text("SITE SECURITY REPORT", margin, 42, title_font, (255, 255, 255))
    text(
        data["meta"]["requested_url"],
        margin,
        112,
        body_font,
        (255, 255, 255),
        max_width=width - 2 * margin,
    )

    y = 250

    # Score card
    ensure(260)
    card_h = 220
    draw.rounded_rectangle(
        (margin, y, width - margin, y + card_h),
        radius=20,
        fill=panel,
        outline=border,
        width=2,
    )

    grade = data["grade"]
    score = data["score"]
    gc = grade_color(grade)
    gc_rgb = tuple(int(gc[i:i + 2], 16) for i in (1, 3, 5))

    draw.rounded_rectangle(
        (margin + 25, y + 25, margin + 260, y + card_h - 25),
        radius=18,
        fill=gc_rgb,
    )
    draw.text((margin + 92, y + 50), grade, font=grade_font, fill=(255, 255, 255))
    draw.text(
        (margin + 90, y + 150),
        f"{score}/100",
        font=body_bold,
        fill=(255, 255, 255),
    )

    meta_x = margin + 310
    text(
        f"Final URL: {data['meta']['final_url']}",
        meta_x,
        y + 35,
        body_font,
        ink,
        max_width=width - meta_x - margin,
    )
    text(
        f"HTTP status: {data['meta']['status_code']}    IP: {data['meta'].get('ip', '')}",
        meta_x,
        y + 80,
        body_font,
        muted,
    )
    text(
        f"Content-Type: {data['meta'].get('content_type', '')}",
        meta_x,
        y + 120,
        body_font,
        muted,
    )
    text(
        "Passive configuration assessment — not a penetration test.",
        meta_x,
        y + 160,
        small_font,
        muted,
    )

    y += card_h + 35

    # Stats
    checks = data["checks"]
    stat_values = [
        ("PASS", sum(1 for c in checks if c["status"] == "PASS")),
        ("WARN", sum(1 for c in checks if c["status"] == "WARN")),
        ("FAIL", sum(1 for c in checks if c["status"] == "FAIL")),
        ("INFO", sum(1 for c in checks if c["status"] == "INFO")),
    ]

    box_w = (width - 2 * margin - 45) // 4
    for i, (label, value) in enumerate(stat_values):
        x1 = margin + i * (box_w + 15)
        ensure(120)
        draw.rounded_rectangle(
            (x1, y, x1 + box_w, y + 105),
            radius=12,
            fill=panel,
            outline=border,
            width=2,
        )
        text(str(value), x1 + 20, y + 15, h_font, ink)
        text(label, x1 + 20, y + 58, small_font, muted)

    y += 145

    # Findings
    text("PRIORITY FINDINGS", margin, y, h_font, ink)
    y += 55

    findings = sorted(
        data["findings"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 9),
    )

    if not findings:
        text("No findings generated.", margin, y, body_font, muted)
        y += 45
    else:
        for f in findings[:100]:
            severity = f["severity"].upper()
            sev_color = {
                "CRITICAL": (198, 40, 40),
                "HIGH": (215, 25, 32),
                "MEDIUM": (196, 122, 0),
                "LOW": (53, 104, 184),
                "INFO": (100, 110, 120),
            }.get(severity, (100, 110, 120))

            block_h = 150
            ensure(block_h)

            draw.rounded_rectangle(
                (margin, y, width - margin, y + block_h),
                radius=12,
                fill=panel,
                outline=border,
                width=2,
            )

            draw.rounded_rectangle(
                (margin + 15, y + 15, margin + 160, y + 53),
                radius=8,
                fill=sev_color,
            )
            draw.text(
                (margin + 30, y + 20),
                severity,
                font=small_font,
                fill=(255, 255, 255),
            )

            text(
                f["category"] + " — " + f["title"],
                margin + 185,
                y + 18,
                body_bold,
                ink,
                max_width=width - margin - (margin + 185) - 20,
            )

            text(
                f["detail"],
                margin + 185,
                y + 57,
                small_font,
                muted,
                max_width=width - margin - (margin + 185) - 20,
            )

            text(
                "Recommendation: " + f.get("recommendation", ""),
                margin + 185,
                y + 95,
                small_font,
                ink,
                max_width=width - margin - (margin + 185) - 20,
            )

            y += block_h + 12

    # Checks table
    ensure(250)
    text("SECURITY CHECKS", margin, y, h_font, ink)
    y += 55

    row_h = 64
    cols = [
        margin,
        margin + 350,
        margin + 700,
        margin + 850,
        width - margin,
    ]

    header_y = y
    draw.rectangle(
        (margin, header_y, width - margin, header_y + row_h),
        fill=(221, 234, 247),
    )
    headers = ["Category", "Check", "Status", "Severity", "Observed"]
    for i, h in enumerate(headers):
        text(h, cols[i] + 12, header_y + 18, small_font, ink)

    y += row_h

    for c in checks:
        ensure(row_h + 20)
        value = c["value"] or c["detail"]
        if len(value) > 150:
            value = value[:150] + "…"

        draw.rectangle(
            (margin, y, width - margin, y + row_h),
            fill=panel,
            outline=border,
        )

        vals = [
            c["category"],
            c["name"],
            c["status"],
            c["severity"],
            value,
        ]

        for i, v in enumerate(vals):
            fill = ink
            if i == 2:
                fill = {
                    "PASS": (20, 131, 59),
                    "FAIL": (215, 25, 32),
                    "WARN": (196, 122, 0),
                    "INFO": (53, 104, 184),
                }.get(v, muted)

            text(
                v,
                cols[i] + 12,
                y + 17,
                small_font,
                fill,
                max_width=(cols[i + 1] - cols[i] - 20),
            )

        y += row_h

    # Footer
    ensure(100)
    y += 30
    text(
        "Generated by Site Security Report. Results are based on the observable response from the scanned URL.",
        margin,
        y,
        small_font,
        muted,
        max_width=width - 2 * margin,
    )

    # Trim image to content
    crop_h = min(img.height, y + 80)
    img = img.crop((0, 0, width, crop_h))
    img.save(output, "PNG", optimize=True)


def write_json(data: Dict[str, Any], output: str):
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def print_terminal(data: Dict[str, Any]):
    print()
    print("=" * 78)
    print(" SITE SECURITY REPORT")
    print("=" * 78)
    print(f"Target : {data['meta']['requested_url']}")
    print(f"Final  : {data['meta']['final_url']}")
    print(f"Status : {data['meta']['status_code']}")
    print(f"IP     : {data['meta'].get('ip', '')}")
    print()
    print(f" GRADE: {data['grade']}    SCORE: {data['score']}/100")
    print("=" * 78)

    for c in data["checks"]:
        print(
            f"[{c['status']:4}] "
            f"{c['category']:<24} "
            f"{c['name']:<34} "
            f"{c['severity']}"
        )

    print()
    print("PRIORITY FINDINGS")
    print("-" * 78)

    findings = sorted(
        data["findings"],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 9),
    )

    if not findings:
        print("No findings.")
    else:
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['title']}")
            print(f"  {f['detail']}")
            if f.get("recommendation"):
                print(f"  -> {f['recommendation']}")
            print()


# ---------------------------------------------------------------------------
# Modern local web UI
# ---------------------------------------------------------------------------

app = Flask(__name__)
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)
LAST_REPORTS: Dict[str, Dict[str, Any]] = {}

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Sentinel — Web Security Assessment</title>

<style>
:root{
    --bg:#070a0d;
    --bg-soft:#0b1014;
    --panel:#0e1419;
    --panel-hover:#121a21;
    --border:#1d2932;
    --border-bright:#2a3a46;

    --text:#eef4f1;
    --text-soft:#aebbb5;
    --muted:#708078;

    --green:#6df2a3;
    --green-dark:#173a28;
    --green-border:#347452;

    --red:#ff6b72;
    --red-dark:#301317;

    --orange:#f0b45c;
    --orange-dark:#302512;

    --blue:#75a9ff;
    --blue-dark:#111f35;

    --shadow:0 20px 60px rgba(0,0,0,.28);

    --mono:ui-monospace,
        SFMono-Regular,
        Menlo,
        Monaco,
        Consolas,
        "Liberation Mono",
        monospace;

    --sans:Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

*{
    box-sizing:border-box;
}

html{
    background:var(--bg);
    scroll-behavior:smooth;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at 75% -10%,
            rgba(65,130,92,.12),
            transparent 35%
        ),
        var(--bg);
    color:var(--text);
    font-family:var(--sans);
    font-size:14px;
    min-height:100vh;
}

button,
input{
    font:inherit;
}

a{
    color:inherit;
}

.wrap{
    width:min(1380px,calc(100% - 40px));
    margin:auto;
    padding:24px 0 60px;
}

/* =========================================================
   HEADER
   ========================================================= */

.topbar{
    height:54px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    border-bottom:1px solid var(--border);
    margin-bottom:44px;
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;

    font-family:var(--mono);
    font-size:12px;
    font-weight:700;
    letter-spacing:.12em;
}

.brand-mark{
    width:32px;
    height:32px;

    display:flex;
    align-items:center;
    justify-content:center;

    border:1px solid var(--green-border);
    border-radius:8px;

    color:var(--green);
    background:rgba(109,242,163,.06);

    box-shadow:
        0 0 20px rgba(109,242,163,.08);
}

.system-status{
    display:flex;
    align-items:center;
    gap:8px;

    color:var(--muted);
    font-family:var(--mono);
    font-size:10px;
    letter-spacing:.08em;
}

.status-dot{
    width:7px;
    height:7px;
    border-radius:50%;
    background:var(--green);
    box-shadow:0 0 10px rgba(109,242,163,.7);
}

/* =========================================================
   HERO
   ========================================================= */

.hero{
    display:grid;
    grid-template-columns:minmax(0,1fr) auto;
    gap:40px;
    align-items:end;
    margin-bottom:30px;
}

.eyebrow{
    margin-bottom:12px;

    color:var(--green);
    font-family:var(--mono);
    font-size:10px;
    font-weight:700;
    letter-spacing:.18em;
    text-transform:uppercase;
}

.hero h1{
    margin:0 0 16px;

    font-family:var(--sans);
    font-size:clamp(38px,5vw,66px);
    line-height:.98;
    letter-spacing:-.055em;
    font-weight:750;
}

.hero h1 span{
    color:var(--green);
}

.hero p{
    max-width:760px;
    margin:0;

    color:var(--text-soft);
    font-size:15px;
    line-height:1.75;
}

.engine-card{
    min-width:230px;

    padding:18px 20px;

    border:1px solid var(--border);
    border-radius:12px;

    background:rgba(14,20,25,.72);
    box-shadow:var(--shadow);

    font-family:var(--mono);
    font-size:10px;
    line-height:2;
    color:var(--muted);
}

.engine-card strong{
    color:var(--text-soft);
    font-weight:500;
}

.engine-card .active{
    color:var(--green);
}

/* =========================================================
   SCAN FORM
   ========================================================= */

.scan-panel{
    padding:8px;

    border:1px solid var(--border-bright);
    border-radius:13px;

    background:
        linear-gradient(
            135deg,
            rgba(109,242,163,.035),
            transparent 45%
        ),
        var(--panel);

    box-shadow:var(--shadow);

    margin-bottom:18px;
}

.scan{
    display:flex;
    gap:8px;
}

.url-input{
    flex:1;
    min-width:0;

    height:54px;

    border:1px solid var(--border);
    border-radius:8px;

    outline:none;

    padding:0 17px;

    background:#080c10;
    color:var(--text);

    font-family:var(--mono);
    font-size:13px;

    transition:
        border-color .2s,
        box-shadow .2s;
}

.url-input::placeholder{
    color:#4f5d57;
}

.url-input:focus{
    border-color:var(--green-border);

    box-shadow:
        0 0 0 3px rgba(109,242,163,.07);
}

/* Main scan button */

.scan-btn{
    height:54px;

    padding:0 24px;

    border:1px solid var(--green-border);
    border-radius:8px;

    background:linear-gradient(
        180deg,
        #1e5035,
        #173a28
    );

    color:var(--green);

    font-family:var(--mono);
    font-size:11px;
    font-weight:700;
    letter-spacing:.07em;

    cursor:pointer;

    transition:
        transform .15s,
        background .2s,
        box-shadow .2s;
}

.scan-btn:hover{
    background:#22583a;
    box-shadow:0 8px 25px rgba(45,150,89,.16);
    transform:translateY(-1px);
}

.scan-btn:disabled{
    opacity:.6;
    cursor:wait;
    transform:none;
}

/* =========================================================
   LOADING / ERROR
   ========================================================= */

.loading{
    display:none;

    padding:12px 15px;

    border:1px solid #254c36;
    border-radius:8px;

    background:#0a160f;
    color:var(--green);

    font-family:var(--mono);
    font-size:10px;

    margin-bottom:18px;
}

.loading.on{
    display:block;
}

.blink{
    animation:blink 1s step-end infinite;
}

@keyframes blink{
    50%{opacity:0}
}

.error{
    padding:14px 16px;

    border:1px solid #633238;
    border-radius:8px;

    background:var(--red-dark);
    color:#ffafb3;

    font-family:var(--mono);
    font-size:11px;

    margin-bottom:18px;
}

/* =========================================================
   DASHBOARD
   ========================================================= */

.dashboard{
    display:grid;
    grid-template-columns:300px minmax(0,1fr);
    gap:12px;
    margin-bottom:12px;
}

/* Score */

.score-card{
    position:relative;
    overflow:hidden;

    min-height:350px;

    padding:25px;

    border:1px solid var(--border);
    border-radius:12px;

    background:
        radial-gradient(
            circle at 50% 35%,
            rgba(109,242,163,.07),
            transparent 42%
        ),
        var(--panel);

    box-shadow:var(--shadow);
}

.score-card:before{
    content:"";

    position:absolute;
    left:0;
    right:0;
    top:0;

    height:2px;

    background:linear-gradient(
        90deg,
        transparent,
        var(--green),
        transparent
    );

    opacity:.7;
}

.card-label{
    color:var(--muted);

    font-family:var(--mono);
    font-size:9px;
    font-weight:700;
    letter-spacing:.15em;
    text-transform:uppercase;
}

.grade{
    margin-top:38px;

    font-family:var(--mono);
    font-size:92px;
    line-height:.8;
    font-weight:800;
    letter-spacing:-.09em;

    color:var(--green);

    text-shadow:
        0 0 35px rgba(109,242,163,.13);
}

.score-number{
    margin-top:14px;

    font-family:var(--mono);
    color:var(--text-soft);
    font-size:12px;
}

.target-info{
    margin-top:30px;
    padding-top:18px;

    border-top:1px solid var(--border);

    color:var(--muted);

    font-family:var(--mono);
    font-size:10px;
    line-height:1.65;

    overflow-wrap:anywhere;
}

.target-info strong{
    color:#8e9b94;
    font-weight:500;
}

/* Statistics */

.stats{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:1px;

    background:var(--border);

    border:1px solid var(--border);
    border-radius:12px;

    overflow:hidden;
}

.stat{
    min-height:174px;

    padding:21px;

    background:var(--panel);

    transition:
        background .2s,
        transform .2s;
}

.stat:hover{
    background:var(--panel-hover);
}

.stat-number{
    margin-top:26px;

    font-family:var(--mono);
    font-size:34px;
    font-weight:700;
    letter-spacing:-.06em;
}

.stat-caption{
    margin-top:7px;

    color:#66736d;

    font-family:var(--mono);
    font-size:9px;
    letter-spacing:.1em;
}

.stat.pass .stat-number{
    color:var(--green);
}

.stat.warn .stat-number,
.stat.medium .stat-number{
    color:var(--orange);
}

.stat.fail .stat-number,
.stat.high .stat-number,
.stat.critical .stat-number{
    color:var(--red);
}

.stat.info .stat-number{
    color:var(--blue);
}

/* =========================================================
   DOWNLOAD / ACTION BAR
   ========================================================= */

.action-bar{
    position:sticky;
    top:12px;
    z-index:20;

    display:flex;
    align-items:center;
    gap:9px;

    min-height:70px;

    padding:10px 12px;

    margin:0 0 12px;

    border:1px solid var(--green-border);
    border-radius:12px;

    background:
        linear-gradient(
            90deg,
            rgba(23,58,40,.97),
            rgba(14,20,25,.97)
        );

    box-shadow:
        0 15px 40px rgba(0,0,0,.32),
        0 0 30px rgba(109,242,163,.05);

    backdrop-filter:blur(14px);
}

.action-title{
    display:flex;
    align-items:center;
    gap:10px;

    margin-right:auto;

    font-family:var(--mono);
    font-size:10px;
    color:#a5b2ab;
    letter-spacing:.08em;
}

.action-icon{
    width:36px;
    height:36px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:8px;

    background:rgba(109,242,163,.1);
    color:var(--green);

    font-size:17px;
}

.download-pdf{
    position:relative;

    min-height:48px;

    padding:0 20px;

    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:10px;

    border:1px solid #6df2a3;
    border-radius:8px;

    background:linear-gradient(
        180deg,
        #37a765,
        #23834b
    );

    color:white;

    font-family:var(--mono);
    font-size:11px;
    font-weight:800;
    letter-spacing:.06em;

    text-decoration:none;

    box-shadow:
        0 8px 25px rgba(47,174,98,.24);

    transition:
        transform .15s,
        box-shadow .2s,
        filter .2s;
}

.download-pdf:hover{
    transform:translateY(-2px);

    filter:brightness(1.08);

    box-shadow:
        0 12px 34px rgba(47,174,98,.35);
}

.download-pdf:active{
    transform:translateY(0);
}

.download-pdf .download-icon{
    font-size:17px;
    line-height:1;
}

/* Secondary download */

.download-json{
    min-height:48px;

    padding:0 15px;

    display:inline-flex;
    align-items:center;
    justify-content:center;

    border:1px solid var(--border-bright);
    border-radius:8px;

    background:#0b1014;

    color:#a8b4ae;

    font-family:var(--mono);
    font-size:10px;
    font-weight:700;

    text-decoration:none;

    transition:
        background .2s,
        border-color .2s,
        color .2s;
}

.download-json:hover{
    background:#131b20;
    border-color:#40515d;
    color:white;
}

/* =========================================================
   SECTIONS
   ========================================================= */

.section{
    margin-bottom:12px;

    border:1px solid var(--border);
    border-radius:12px;

    background:var(--panel);

    overflow:hidden;

    box-shadow:0 10px 35px rgba(0,0,0,.12);
}

.section-header{
    min-height:60px;

    display:flex;
    align-items:center;
    justify-content:space-between;

    padding:0 20px;

    border-bottom:1px solid var(--border);

    background:
        linear-gradient(
            90deg,
            rgba(255,255,255,.018),
            transparent
        );
}

.section-title{
    display:flex;
    align-items:center;
    gap:10px;

    color:#aab6b0;

    font-family:var(--mono);
    font-size:10px;
    font-weight:700;
    letter-spacing:.1em;
    text-transform:uppercase;
}

.section-title:before{
    content:"";

    width:5px;
    height:5px;

    border-radius:50%;

    background:var(--green);

    box-shadow:0 0 8px rgba(109,242,163,.5);
}

.section-count{
    color:#536159;

    font-family:var(--mono);
    font-size:9px;
}

/* =========================================================
   FINDINGS
   ========================================================= */

.findings{
    padding:0 20px;
}

.finding{
    border-bottom:1px solid #182129;
}

.finding:last-child{
    border-bottom:0;
}

.finding summary{
    list-style:none;

    cursor:pointer;

    min-height:72px;

    display:grid;
    grid-template-columns:82px minmax(0,1fr) 20px;
    gap:15px;

    align-items:center;

    color:var(--text);

    transition:color .2s;
}

.finding summary::-webkit-details-marker{
    display:none;
}

.finding summary:hover{
    color:white;
}

.finding summary:after{
    content:"+";

    color:#596861;

    font-family:var(--mono);
    font-size:17px;
    text-align:right;
}

.finding[open] summary:after{
    content:"−";
}

.severity{
    padding:6px 5px;

    border:1px solid;

    border-radius:5px;

    text-align:center;

    font-family:var(--mono);
    font-size:8px;
    font-weight:800;
    letter-spacing:.08em;
}

.sev-critical,
.sev-high{
    color:#ff898e;
    background:#241014;
    border-color:#653138;
}

.sev-medium{
    color:var(--orange);
    background:#21190d;
    border-color:#5d4925;
}

.sev-low{
    color:var(--blue);
    background:#0e1829;
    border-color:#30486e;
}

.sev-info{
    color:#9ca9a2;
    background:#0d1215;
    border-color:#344149;
}

.finding-title{
    font-size:13px;
    font-weight:600;
}

.finding-id{
    color:#4d5a54;

    font-family:var(--mono);
    font-size:9px;
}

.finding-detail{
    padding:0 35px 20px 97px;

    color:#7f8d86;

    font-family:var(--mono);
    font-size:10px;
    line-height:1.7;
}

.finding-detail strong{
    color:#aab5af;
    font-weight:500;
}

.evidence{
    margin-top:14px;

    padding:13px 15px;

    border-left:2px solid #2d6948;

    border-radius:0 6px 6px 0;

    background:#080d0b;

    color:#89978f;

    white-space:pre-wrap;
    overflow-wrap:anywhere;
}

/* =========================================================
   CHECK MATRIX
   ========================================================= */

.table-scroll{
    overflow:auto;
}

.checks{
    width:100%;
    border-collapse:collapse;
    min-width:850px;
}

.checks th,
.checks td{
    padding:13px 15px;

    border-bottom:1px solid #172028;

    text-align:left;

    vertical-align:top;
}

.checks th{
    background:#0b1014;

    color:#5e6b64;

    font-family:var(--mono);
    font-size:8px;
    font-weight:600;
    letter-spacing:.1em;
    text-transform:uppercase;
}

.checks td{
    color:#96a39c;

    font-family:var(--mono);
    font-size:10px;

    line-height:1.5;
}

.checks tr:hover td{
    background:rgba(255,255,255,.012);
}

.status-pass{
    color:var(--green)!important;
}

.status-warn{
    color:var(--orange)!important;
}

.status-fail{
    color:var(--red)!important;
}

.status-info{
    color:var(--blue)!important;
}

.status-na{
    color:#758078!important;
}

/* =========================================================
   FOOTER
   ========================================================= */

.footer{
    margin-top:30px;
    padding:18px 0 0;

    border-top:1px solid var(--border);

    color:#536059;

    font-family:var(--mono);
    font-size:9px;
    line-height:1.8;
}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media(max-width:1050px){

    .dashboard{
        grid-template-columns:1fr;
    }

    .score-card{
        min-height:280px;
    }

    .stats{
        grid-template-columns:repeat(4,1fr);
    }
}

@media(max-width:800px){

    .wrap{
        width:min(100% - 22px,1380px);
        padding-top:15px;
    }

    .topbar{
        margin-bottom:30px;
    }

    .system-status{
        display:none;
    }

    .hero{
        grid-template-columns:1fr;
        gap:20px;
    }

    .hero h1{
        font-size:42px;
    }

    .engine-card{
        min-width:0;
    }

    .scan{
        flex-direction:column;
    }

    .scan-btn{
        width:100%;
    }

    .stats{
        grid-template-columns:repeat(2,1fr);
    }

    .stat{
        min-height:145px;
    }

    .action-bar{
        top:6px;
        flex-wrap:wrap;
    }

    .action-title{
        width:100%;
        margin-right:0;
    }

    .download-pdf,
    .download-json{
        flex:1;
    }

    .finding summary{
        grid-template-columns:68px minmax(0,1fr) 15px;
        gap:10px;
    }

    .finding-detail{
        padding-left:0;
    }
}

@media(max-width:500px){

    .hero h1{
        font-size:36px;
    }

    .stats{
        grid-template-columns:1fr 1fr;
    }

    .grade{
        font-size:75px;
    }

    .action-bar{
        padding:9px;
    }

    .download-pdf{
        padding:0 10px;
        font-size:9px;
    }

    .download-json{
        padding:0 10px;
        font-size:9px;
    }

    .finding summary{
        grid-template-columns:1fr 18px;
    }

    .severity{
        width:max-content;
        min-width:68px;
        margin-bottom:5px;
    }

    .finding-title{
        grid-column:1;
        grid-row:2;
    }
}
</style>
</head>

<body>

<div class="wrap">

    <!-- =====================================================
         HEADER
         ===================================================== -->

    <header class="topbar">

        <div class="brand">
            <span class="brand-mark">◆</span>
            <span>SENTINEL / WEB SECURITY</span>
        </div>

        <div class="system-status">
            <span class="status-dot"></span>
            LOCAL ASSESSMENT CONSOLE
        </div>

    </header>


    <!-- =====================================================
         HERO
         ===================================================== -->

    <section class="hero">

        <div>

            <div class="eyebrow">
                PASSIVE SECURITY ASSESSMENT
            </div>

            <h1>
                Find exposure.<br>
                <span>Capture evidence.</span>
            </h1>

            <p>
                Analyse HTTP headers, TLS, cookies, redirects, DNS and HTML
                security configuration for authorised web assessments.
                Generate a professional report without exploiting the target.
            </p>

        </div>


        <div class="engine-card">

            <strong>ENGINE</strong>
            &nbsp;&nbsp; SITE SECURITY<br>

            <strong>MODE</strong>
            &nbsp;&nbsp;&nbsp;&nbsp; PASSIVE<br>

            <strong>OUTPUT</strong>
            &nbsp;&nbsp; PDF / JSON<br>

            <strong>STATUS</strong>
            &nbsp;&nbsp; <span class="active">READY</span>

        </div>

    </section>


    <!-- =====================================================
         SCAN FORM
         ===================================================== -->

    <div class="scan-panel">

        <form
            class="scan"
            method="post"
            action="/scan"
            onsubmit="startScan()"
        >

            <input
                class="url-input"
                name="url"
                id="url"
                placeholder="https://target.example"
                value="{{ url|default('') }}"
                autocomplete="url"
                required
            >

            <button
                class="scan-btn"
                id="scanBtn"
                type="submit"
            >
                RUN ASSESSMENT →
            </button>

        </form>

    </div>


    <!-- =====================================================
         LOADING
         ===================================================== -->

    <div id="loading" class="loading">

        <span class="blink">█</span>

        &nbsp; Collecting HTTP response, TLS metadata,
        cookies, DNS and HTML observations...

    </div>


    <!-- =====================================================
         ERROR
         ===================================================== -->

    {% if error %}

    <div class="error">
        [ERROR] {{ error }}
    </div>

    {% endif %}


    {% if report %}

    <!-- =====================================================
         SCORE + STATISTICS
         ===================================================== -->

    <section class="dashboard">

        <div class="score-card">

            <div class="card-label">
                SECURITY POSTURE
            </div>

            <div class="grade">
                {{ report.grade }}
            </div>

            <div class="score-number">
                {{ report.score }}/100 assessment score
            </div>

            <div class="target-info">

                <strong>REQUESTED TARGET</strong><br>
                {{ report.meta.requested_url }}

                <br><br>

                <strong>FINAL URL</strong><br>
                {{ report.meta.final_url }}

                <br><br>

                <strong>HTTP</strong>
                {{ report.meta.status_code }}

                {% if report.meta.get('ip') %}
                    &nbsp;&nbsp;
                    <strong>IP</strong>
                    {{ report.meta.ip }}
                {% endif %}

            </div>

        </div>


        <div class="stats">

            <div class="stat critical">
                <div class="card-label">Critical</div>
                <div class="stat-number">
                    {{ counts.critical }}
                </div>
                <div class="stat-caption">
                    IMMEDIATE REVIEW
                </div>
            </div>

            <div class="stat high">
                <div class="card-label">High</div>
                <div class="stat-number">
                    {{ counts.high }}
                </div>
                <div class="stat-caption">
                    PRIORITY
                </div>
            </div>

            <div class="stat medium">
                <div class="card-label">Medium</div>
                <div class="stat-number">
                    {{ counts.medium }}
                </div>
                <div class="stat-caption">
                    REVIEW
                </div>
            </div>

            <div class="stat info">
                <div class="card-label">Low / Info</div>
                <div class="stat-number">
                    {{ counts.low + counts.info }}
                </div>
                <div class="stat-caption">
                    OBSERVATIONS
                </div>
            </div>

            <div class="stat pass">
                <div class="card-label">Passed</div>
                <div class="stat-number">
                    {{ check_counts.pass }}
                </div>
                <div class="stat-caption">
                    PASS
                </div>
            </div>

            <div class="stat warn">
                <div class="card-label">Warnings</div>
                <div class="stat-number">
                    {{ check_counts.warn }}
                </div>
                <div class="stat-caption">
                    WARN
                </div>
            </div>

            <div class="stat fail">
                <div class="card-label">Failures</div>
                <div class="stat-number">
                    {{ check_counts.fail }}
                </div>
                <div class="stat-caption">
                    FAIL
                </div>
            </div>

            <div class="stat">
                <div class="card-label">Checks</div>
                <div class="stat-number">
                    {{ report.checks|length }}
                </div>
                <div class="stat-caption">
                    TOTAL
                </div>
            </div>

        </div>

    </section>


    <!-- =====================================================
         DOWNLOAD / EXPORT BAR
         ===================================================== -->

    <div class="action-bar">

        <div class="action-title">

            <span class="action-icon">↓</span>

            <span>
                REPORT READY
                <br>
                <small style="color:#65736b">
                    Export the completed security assessment
                </small>
            </span>

        </div>


        <!-- PRIMARY DOWNLOAD ACTION -->

        <a
            class="download-pdf"
            href="{{ url_for('download_report', report_id=report_id) }}"
            title="Download the full PDF security report"
        >
            <span class="download-icon">⇩</span>
            DOWNLOAD PDF REPORT
        </a>


        <!-- SECONDARY JSON ACTION -->

        <a
            class="download-json"
            href="{{ url_for('download_json', report_id=report_id) }}"
            title="Download raw JSON report data"
        >
            JSON
        </a>

    </div>


    <!-- =====================================================
         FINDINGS
         ===================================================== -->

    <section class="section">

        <div class="section-header">

            <div class="section-title">
                Priority Findings
            </div>

            <div class="section-count">
                {{ report.findings|length }} findings
            </div>

        </div>


        <div class="findings">

            {% if report.findings %}

                {% for f in report.findings %}

                <details class="finding">

                    <summary>

                        <span class="severity sev-{{ f.severity }}">
                            {{ f.severity|upper }}
                        </span>

                        <span class="finding-title">
                            {{ f.title }}
                        </span>

                        <span class="finding-id">
                            {{ f.get('id','FINDING') }}
                        </span>

                    </summary>


                    <div class="finding-detail">

                        <strong>Category:</strong>
                        {{ f.category }}

                        {% if f.get('owasp') %}
                            &nbsp;&nbsp;
                            <strong>OWASP:</strong>
                            {{ f.owasp }}
                        {% endif %}

                        {% if f.get('cwe') %}
                            &nbsp;&nbsp;
                            <strong>CWE:</strong>
                            {{ f.cwe }}
                        {% endif %}

                        <br><br>

                        <strong>Description:</strong>
                        {{ f.detail }}

                        {% if f.get('recommendation') %}

                            <br><br>

                            <strong>Remediation:</strong>
                            {{ f.recommendation }}

                        {% endif %}


                        <div class="evidence">

                            <strong>OBSERVATION</strong>

                            <br>

                            {{ f.get('evidence', f.detail) }}

                        </div>

                    </div>

                </details>

                {% endfor %}

            {% else %}

                <div
                    class="finding-detail"
                    style="padding-left:0;padding-top:20px;"
                >
                    No priority findings were generated by the
                    current passive checks.
                </div>

            {% endif %}

        </div>

    </section>


    <!-- =====================================================
         CHECK MATRIX
         ===================================================== -->

    <section class="section">

        <div class="section-header">

            <div class="section-title">
                Control Matrix / Observed Checks
            </div>

            <div class="section-count">
                {{ report.checks|length }} checks
            </div>

        </div>


        <div class="table-scroll">

            <table class="checks">

                <thead>

                    <tr>
                        <th>Category</th>
                        <th>Control</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Observed / Detail</th>
                    </tr>

                </thead>


                <tbody>

                    {% for c in report.checks %}

                    <tr>

                        <td>
                            {{ c.category }}
                        </td>

                        <td>
                            {{ c.name }}
                        </td>

                        <td class="status-{{ c.status|lower }}">
                            {{ c.status }}
                        </td>

                        <td>
                            {{ c.severity }}
                        </td>

                        <td>
                            {{ c.value or c.detail }}
                        </td>

                    </tr>

                    {% endfor %}

                </tbody>

            </table>

        </div>

    </section>


    {% endif %}


    <!-- =====================================================
         FOOTER
         ===================================================== -->

    <footer class="footer">

        SENTINEL / SITE SECURITY

        <br>

        Passive assessment only. Findings represent observable
        configuration and response behaviour from the supplied target.
        Validate findings manually before treating them as confirmed
        vulnerabilities.

        <br>

        Only scan systems you are authorised to assess.

    </footer>

</div>


<script>

function startScan(){

    const button = document.getElementById("scanBtn");
    const loading = document.getElementById("loading");

    if(button){

        button.disabled = true;
        button.textContent = "ASSESSING...";
    }

    if(loading){

        loading.classList.add("on");
    }
}


/*
 * Make the PDF download button slightly more obvious
 * after a report has been generated.
 */
document.addEventListener("DOMContentLoaded", function(){

    const pdfButton = document.querySelector(".download-pdf");

    if(pdfButton){

        setTimeout(function(){

            pdfButton.animate(
                [
                    {
                        boxShadow:
                            "0 8px 25px rgba(47,174,98,.24)"
                    },
                    {
                        boxShadow:
                            "0 8px 38px rgba(109,242,163,.55)"
                    },
                    {
                        boxShadow:
                            "0 8px 25px rgba(47,174,98,.24)"
                    }
                ],
                {
                    duration:900,
                    iterations:2
                }
            );

        }, 500);

    }

});

</script>

</body>
</html>
"""



def run_scan(url: str) -> tuple[str, Dict[str, Any]]:
    scanner = SecurityScanner(url, follow_redirects=True, allow_private=False)
    data = scanner.scan()
    scanner.add_summary_findings()
    raw_findings = [asdict(x) for x in scanner.findings]
    for idx, finding in enumerate(raw_findings, 1):
        sev = finding.get("severity", "info")
        finding["id"] = f"VULN-WEB-{idx:03d}"
        finding["evidence"] = finding.get("detail", "")
        title = finding.get("title", "").lower()
        if "content-security-policy" in title or "csp" in title:
            finding["owasp"], finding["cwe"] = "A05:2021 – Security Misconfiguration", "CWE-693"
        elif "cookie" in title:
            finding["owasp"], finding["cwe"] = "A05:2021 – Security Misconfiguration", "CWE-614"
        elif "cors" in title:
            finding["owasp"], finding["cwe"] = "A05:2021 – Security Misconfiguration", "CWE-942"
        elif "mixed content" in title or "http" in title and "password" in title:
            finding["owasp"], finding["cwe"] = "A02:2021 – Cryptographic Failures", "CWE-319"
        else:
            finding["owasp"], finding["cwe"] = "A05:2021 – Security Misconfiguration", "CWE-16"
    data["findings"] = raw_findings
    report_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pdf_path = REPORT_DIR / f"security_report_{report_id}.pdf"
    build_pdf(data, str(pdf_path))
    LAST_REPORTS[report_id] = {"data": data, "pdf": pdf_path}
    return report_id, data


def _template_context(report=None, error=None, url="", report_id=None):
    findings = (report or {}).get("findings", [])
    checks = (report or {}).get("checks", [])
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in ("critical", "high", "medium", "low", "info")}
    check_counts = {s: sum(1 for c in checks if c.get("status", "").lower() == s) for s in ("pass", "warn", "fail", "info")}
    return dict(report=report, error=error, url=url, report_id=report_id, counts=counts, check_counts=check_counts)


@app.get("/")
def index():
    return render_template_string(HTML, **_template_context())


@app.post("/scan")
def scan():
    target = request.form.get("url", "").strip()
    try:
        report_id, data = run_scan(target)
        return render_template_string(HTML, **_template_context(data, None, target, report_id))
    except requests.RequestException as exc:
        return render_template_string(HTML, **_template_context(None, f"Unable to scan the URL: {exc}", target)), 400
    except Exception as exc:
        return render_template_string(HTML, **_template_context(None, f"Scan failed: {exc}", target)), 400


@app.get("/download-json/<report_id>")
def download_json(report_id: str):
    item = LAST_REPORTS.get(report_id)
    if not item:
        return "Report not found. Run the assessment again.", 404
    payload = json.dumps(item["data"], indent=2, ensure_ascii=False, default=str)
    from io import BytesIO
    return send_file(BytesIO(payload.encode("utf-8")), as_attachment=True, download_name=f"security_report_{report_id}.json", mimetype="application/json")


@app.get("/download/<report_id>")
def download_report(report_id: str):
    item = LAST_REPORTS.get(report_id)
    if not item or not item["pdf"].exists():
        return "Report not found. Run the scan again.", 404
    return send_file(item["pdf"], as_attachment=True, download_name=item["pdf"].name, mimetype="application/pdf")


def main():
    port = int(os.environ.get("SITE_SECURITY_PORT", "5000"))
    url = f"http://127.0.0.1:{port}"
    print(f"\nSite Security UI: {url}")
    print("Press Ctrl+C to stop.\n")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
