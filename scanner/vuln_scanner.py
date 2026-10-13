"""
Professional-grade Website Vulnerability Scanner (educational / authorized use)
Checks:
  - Security headers & cookie flags
  - Error-based SQLi
  - Reflected XSS
  - Open redirect
  - Sensitive file / path exposure
  - Directory listing
  - CORS misconfiguration
  - Server / technology disclosure
  - Form security (autocomplete password, missing CSRF token hint)
  - HTTP methods (TRACE/OPTIONS)
  - Mixed content hints on HTTPS pages
"""
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, timeout=10, max_pages=15, delay=0.15):
        self.timeout = timeout
        self.max_pages = max_pages
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "PhishGuardPro-Scanner/3.1 (+educational; authorized testing only)"
        })
        self.visited = set()

        self.sqli_payloads = [
            "'", "''", "1' OR '1'='1' --", "' OR 1=1--",
            "1 AND 1=1", "1 AND 1=2", "admin'--",
            "\" OR \"1\"=\"1", "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
        ]
        self.xss_payloads = [
            "<script>alert('PGP')</script>",
            "\"><script>alert('PGP')</script>",
            "'\"><img src=x onerror=alert('PGP')>",
            "<svg/onload=alert('PGP')>",
            "<body onload=alert('PGP')>",
            "javascript:alert('PGP')",
        ]
        self.open_redirect_payloads = [
            "//evil-phishguard-test.com",
            "https://evil-phishguard-test.com",
            "////evil-phishguard-test.com",
        ]
        self.security_headers = {
            "Content-Security-Policy": ("High", "Mitigates XSS and data injection."),
            "X-Frame-Options": ("Medium", "Mitigates clickjacking."),
            "X-Content-Type-Options": ("Medium", "Prevents MIME sniffing."),
            "Strict-Transport-Security": ("High", "Enforces HTTPS."),
            "Referrer-Policy": ("Low", "Controls referrer leakage."),
            "Permissions-Policy": ("Low", "Restricts browser features."),
        }
        self.sql_errors = [
            r"you have an error in your sql syntax",
            r"warning: mysql_",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"sql syntax.*mysql",
            r"ora-\d{5}",
            r"postgresql.*error",
            r"sqlite3?\.OperationalError",
            r"microsoft ole db.*sql",
            r"odbc.*driver.*sql",
            r"syntax error.*unexpected",
            r"mysql_fetch_",
            r"pg_query\(",
            r"SQLSTATE\[",
            r"mysqli_",
            r"PDOException",
        ]
        self.sensitive_paths = [
            "/.env", "/.git/config", "/.git/HEAD", "/robots.txt",
            "/backup.sql", "/dump.sql", "/wp-config.php.bak",
            "/config.php.bak", "/.htaccess", "/server-status",
            "/phpinfo.php", "/info.php", "/admin/", "/administrator/",
            "/.svn/entries", "/web.config", "/crossdomain.xml",
            "/package.json", "/composer.json", "/.DS_Store",
        ]

    def _normalize(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    def _same_domain(self, base, target):
        try:
            return urlparse(base).netloc.lower() == urlparse(target).netloc.lower()
        except Exception:
            return False

    def _get(self, url, allow_redirects=True, method="GET"):
        try:
            time.sleep(self.delay)
            if method == "OPTIONS":
                return self.session.options(url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects)
            if method == "TRACE":
                return self.session.request("TRACE", url, timeout=self.timeout, verify=False, allow_redirects=False)
            return self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects, verify=False)
        except Exception:
            return None

    def _finding(self, **kwargs):
        kwargs.setdefault("parameter", "-")
        kwargs.setdefault("payload", "-")
        kwargs.setdefault("evidence", "")
        kwargs.setdefault("recommendation", "")
        return kwargs

    def crawl(self, start_url):
        start_url = self._normalize(start_url)
        to_visit = [start_url]
        pages = []
        while to_visit and len(pages) < self.max_pages:
            url = to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            resp = self._get(url)
            if not resp or resp.status_code >= 400:
                continue
            pages.append({"url": url, "response": resp})
            try:
                soup = BeautifulSoup(resp.text, "lxml")
                for a in soup.find_all("a", href=True):
                    link = urljoin(url, a["href"]).split("#")[0]
                    if link.startswith("mailto:") or link.startswith("javascript:"):
                        continue
                    if (self._same_domain(start_url, link)
                            and link not in self.visited
                            and link not in to_visit
                            and not link.lower().endswith(
                                (".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".pdf", ".zip", ".woff", ".woff2"))):
                        to_visit.append(link)
            except Exception:
                pass
        return pages

    def check_headers(self, url, response):
        findings = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        for h, (sev, why) in self.security_headers.items():
            if h.lower() not in headers:
                findings.append(self._finding(
                    type="Missing Security Header",
                    name=h,
                    severity=sev,
                    url=url,
                    evidence=f"Response lacks '{h}'",
                    description=f"Missing {h}. {why}",
                    recommendation=f"Configure the server/CDN to send a secure {h} value.",
                ))

        server = headers.get("server")
        powered = headers.get("x-powered-by")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(self._finding(
                type="Information Disclosure",
                name="Server version exposed",
                severity="Low",
                url=url,
                evidence=f"Server: {server}",
                description="Server header reveals software version, aiding targeted exploits.",
                recommendation="Remove or genericize the Server header.",
            ))
        if powered:
            findings.append(self._finding(
                type="Information Disclosure",
                name="X-Powered-By exposed",
                severity="Low",
                url=url,
                evidence=f"X-Powered-By: {powered}",
                description="Technology stack is disclosed via X-Powered-By.",
                recommendation="Disable X-Powered-By in application/server config.",
            ))

        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            low = set_cookie.lower()
            if "httponly" not in low:
                findings.append(self._finding(
                    type="Insecure Cookie",
                    name="Missing HttpOnly",
                    severity="Medium",
                    url=url,
                    evidence="Set-Cookie without HttpOnly",
                    description="Cookie accessible to JavaScript increases XSS impact.",
                    recommendation="Add HttpOnly (and Secure on HTTPS) to session cookies.",
                ))
            if urlparse(url).scheme == "https" and "secure" not in low:
                findings.append(self._finding(
                    type="Insecure Cookie",
                    name="Missing Secure flag",
                    severity="Medium",
                    url=url,
                    evidence="Set-Cookie without Secure on HTTPS",
                    description="Cookie may be sent over HTTP.",
                    recommendation="Add the Secure flag on HTTPS sites.",
                ))
            if "samesite" not in low:
                findings.append(self._finding(
                    type="Insecure Cookie",
                    name="Missing SameSite",
                    severity="Low",
                    url=url,
                    evidence="Set-Cookie without SameSite",
                    description="Missing SameSite increases CSRF risk.",
                    recommendation="Set SameSite=Lax or Strict as appropriate.",
                ))
        return findings

    def check_cors(self, url, response):
        findings = []
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            findings.append(self._finding(
                type="CORS Misconfiguration",
                name="ACA-Origin reflects *",
                severity="Medium" if acac.lower() != "true" else "High",
                url=url,
                evidence=f"Access-Control-Allow-Origin: *",
                description="Wildcard CORS allows any origin to read responses.",
                recommendation="Reflect only trusted origins; avoid * with credentials.",
            ))
        return findings

    def check_http_methods(self, url):
        findings = []
        resp = self._get(url, method="OPTIONS")
        if resp is not None:
            allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
            if "TRACE" in allow.upper():
                findings.append(self._finding(
                    type="Dangerous HTTP Method",
                    name="TRACE enabled",
                    severity="Medium",
                    url=url,
                    evidence=f"Allow: {allow}",
                    description="TRACE can enable cross-site tracing attacks.",
                    recommendation="Disable TRACE on the web server.",
                ))
        return findings

    def check_directory_listing(self, url, response):
        findings = []
        body = (response.text or "")[:5000].lower()
        if ("index of /" in body or "directory listing for" in body) and "<title>" in body:
            findings.append(self._finding(
                type="Directory Listing",
                name="Open directory listing",
                severity="Medium",
                url=url,
                evidence="Page content indicates directory index",
                description="Server exposes file listing, revealing sensitive paths.",
                recommendation="Disable autoindex / directory browsing.",
            ))
        return findings

    def check_forms(self, page_url, html):
        findings = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = urljoin(page_url, form.get("action") or page_url)
                inputs = form.find_all("input")
                has_password = any((i.get("type") or "").lower() == "password" for i in inputs)
                has_csrf = any(
                    (i.get("name") or "").lower() in ("csrf", "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token")
                    or "csrf" in (i.get("name") or "").lower()
                    for i in inputs
                )
                if has_password and not has_csrf:
                    findings.append(self._finding(
                        type="CSRF Risk",
                        name="Password form without visible CSRF token",
                        severity="Medium",
                        url=action,
                        evidence="Password field present; no common CSRF field name found",
                        description="Login/password forms should include anti-CSRF tokens (heuristic check).",
                        recommendation="Implement synchronizer tokens or SameSite cookies + CSRF tokens.",
                    ))
                for i in inputs:
                    if (i.get("type") or "").lower() == "password" and (i.get("autocomplete") or "").lower() == "on":
                        findings.append(self._finding(
                            type="Form Security",
                            name="Password autocomplete enabled",
                            severity="Low",
                            url=action,
                            evidence="autocomplete=on on password field",
                            description="May store credentials in browser on shared devices.",
                            recommendation="Use autocomplete=current-password carefully; follow UX security guidelines.",
                        ))
                        break
        except Exception:
            pass
        return findings

    def check_mixed_content(self, url, html):
        findings = []
        if not url.lower().startswith("https://"):
            return findings
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag, attr in (("script", "src"), ("img", "src"), ("iframe", "src"), ("link", "href")):
                for el in soup.find_all(tag):
                    src = el.get(attr) or ""
                    if src.startswith("http://"):
                        findings.append(self._finding(
                            type="Mixed Content",
                            name=f"Insecure {tag} on HTTPS page",
                            severity="Medium",
                            url=url,
                            evidence=src[:120],
                            description="HTTPS page loads active/passive content over HTTP.",
                            recommendation="Serve all assets over HTTPS.",
                        ))
                        return findings  # one is enough
        except Exception:
            pass
        return findings

    def test_sqli(self, url, params, method="GET"):
        findings = []
        for param in list(params.keys()):
            for payload in self.sqli_payloads:
                test = params.copy()
                test[param] = payload
                try:
                    if method == "GET":
                        resp = self.session.get(url, params=test, timeout=self.timeout, verify=False)
                    else:
                        resp = self.session.post(url, data=test, timeout=self.timeout, verify=False)
                    body = (resp.text or "").lower()
                    for pat in self.sql_errors:
                        if re.search(pat, body, re.I):
                            findings.append(self._finding(
                                type="SQL Injection",
                                name="Error-based SQL Injection",
                                severity="High",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=f"Matched SQL error pattern: {pat}",
                                description=f"SQL error reflected when injecting into '{param}'.",
                                recommendation="Use parameterized queries / ORM. Never concatenate user input into SQL.",
                            ))
                            return findings
                except Exception:
                    continue
        return findings

    def test_xss(self, url, params, method="GET"):
        findings = []
        marker = "PGP"
        for param in list(params.keys()):
            for payload in self.xss_payloads:
                test = params.copy()
                test[param] = payload
                try:
                    if method == "GET":
                        resp = self.session.get(url, params=test, timeout=self.timeout, verify=False)
                    else:
                        resp = self.session.post(url, data=test, timeout=self.timeout, verify=False)
                    body = resp.text or ""
                    if payload in body and marker in body:
                        findings.append(self._finding(
                            type="Cross-Site Scripting (XSS)",
                            name="Reflected XSS",
                            severity="High",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Payload with marker '{marker}' reflected unescaped",
                            description=f"Input from '{param}' reflected without encoding.",
                            recommendation="Context-aware output encoding, trusted types, and a strict CSP.",
                        ))
                        break
                except Exception:
                    continue
        return findings

    def test_open_redirect(self, url, params):
        findings = []
        keys = ["url", "redirect", "next", "return", "returnurl", "redirect_uri",
                "continue", "dest", "destination", "redir", "goto", "target", "rurl"]
        for param in params:
            if param.lower() not in keys:
                continue
            for payload in self.open_redirect_payloads:
                test = params.copy()
                test[param] = payload
                try:
                    resp = self.session.get(url, params=test, timeout=self.timeout,
                                            allow_redirects=False, verify=False)
                    loc = resp.headers.get("Location", "") or ""
                    if "evil-phishguard-test.com" in loc.lower():
                        findings.append(self._finding(
                            type="Open Redirect",
                            name="Open Redirect",
                            severity="Medium",
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Location: {loc[:150]}",
                            description=f"External redirect controlled via '{param}'.",
                            recommendation="Whitelist allowed redirect targets.",
                        ))
                        break
                except Exception:
                    continue
        return findings

    def check_sensitive_files(self, base_url):
        findings = []
        for path in self.sensitive_paths:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._get(url)
            if not resp or resp.status_code != 200 or len(resp.text or "") < 20:
                continue
            body = (resp.text or "").lower()
            interesting = any(x in body for x in [
                "db_", "password", "secret", "api_key", "aws_", "[core]",
                "phpinfo", "allow from", "disallow", "root:", "mysql",
                "app_key", "database", "redis_password"
            ]) or path in ["/.env", "/.git/config", "/phpinfo.php", "/server-status", "/.git/HEAD"]
            if interesting or path.endswith((".bak", ".sql", ".env")):
                sev = "High" if path in ["/.env", "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql"] else "Medium"
                findings.append(self._finding(
                    type="Sensitive File Exposure",
                    name=path,
                    severity=sev,
                    url=url,
                    evidence=f"HTTP {resp.status_code}, length {len(resp.text)}",
                    description=f"Potentially sensitive path '{path}' is publicly readable.",
                    recommendation="Block public access to config, VCS, and backup files.",
                ))
        return findings

    def extract_forms_and_params(self, page_url, html):
        results = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = urljoin(page_url, form.get("action") or page_url)
                method = (form.get("method") or "get").upper()
                params = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        params[name] = inp.get("value") or "test"
                if params:
                    results.append((action, method, params))
            qs = parse_qs(urlparse(page_url).query)
            if qs:
                results.append((page_url, "GET", {k: v[0] for k, v in qs.items()}))
        except Exception:
            pass
        return results

    def scan(self, target_url: str) -> dict:
        self.visited = set()
        findings = []
        target_url = self._normalize(target_url)
        result = {
            "target": target_url,
            "status": "completed",
            "pages_crawled": 0,
            "vulnerabilities": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "scanner_version": "3.1-professional",
        }
        try:
            first = self._get(target_url)
            if first:
                findings.extend(self.check_headers(target_url, first))
                findings.extend(self.check_cors(target_url, first))
                findings.extend(self.check_directory_listing(target_url, first))
                findings.extend(self.check_forms(target_url, first.text or ""))
                findings.extend(self.check_mixed_content(target_url, first.text or ""))
            findings.extend(self.check_http_methods(target_url))
            findings.extend(self.check_sensitive_files(target_url))

            pages = self.crawl(target_url)
            result["pages_crawled"] = len(pages)

            for page in pages:
                html = page["response"].text or ""
                findings.extend(self.check_directory_listing(page["url"], page["response"]))
                findings.extend(self.check_forms(page["url"], html))
                findings.extend(self.check_mixed_content(page["url"], html))
                for action, method, params in self.extract_forms_and_params(page["url"], html):
                    findings.extend(self.test_sqli(action, params, method))
                    findings.extend(self.test_xss(action, params, method))
                    if method == "GET":
                        findings.extend(self.test_open_redirect(action, params))

            unique, seen = [], set()
            for f in findings:
                key = (f["type"], f.get("url"), f.get("parameter"), f.get("name"))
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            result["vulnerabilities"] = unique
            for v in unique:
                sev = (v.get("severity") or "info").lower()
                if sev in result["summary"]:
                    result["summary"][sev] += 1
                else:
                    result["summary"]["info"] += 1
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result
