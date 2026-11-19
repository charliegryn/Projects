#!/usr/bin/env python3
"""
bugscan.py - passive-first web application scanner.

Passive checks run on every response the crawler sees (no extra requests).
Active checks (reflected XSS, error-based SQLi) are OPT-IN and only
run against hosts you explicitly allowlist.

    pip install requests beautifulsoup4
    python bugscan.py <http://localhost:3000> --out <output file name> # passive only
    python bugscan.py http://localhost:8080 --active --allow localhost
    python bugscan.py http://localhost/dvwa --active --allow localhost
        --cookie "PHPSESSID=abc; security=low"
"""

# Overview of the program
# 1. The crawler visits the website page by page.
# 2. Every page it visits gets checked from problems (passive check).
# 3. If --active is enabled, it also sends test inputs to the site (active check).
# 4. All problems found are ranked and saved to a report file.

import argparse, json, re, sys, time, uuid
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup, Comment

# ----------------------------------------------------------------- findings
@dataclass(frozen=True)
# Findings are a problem the scanner found
class Finding:
    check: str
    severity: str      # High / Medium / Low / Info
    url: str
    detail: str
    evidence: str = ""
    mode: str = "passive"

# This class holds every finding
class Results:
    def __init__(self):
        self.items = {}

    def add(self, f: Finding):
        # dedupe on (check, url, detail) so repeated pages don't spam the report
        self.items.setdefault((f.check, f.url, f.detail), f)

    # Sorts most serious problems first
    def sorted(self):
        order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        return sorted(self.items.values(), key=lambda f: (order[f.severity], f.check))


# ------------------------------------------------------------ passive checks

# Security headers a website should have
SEC_HEADERS = {
    "Content-Security-Policy": ("Medium", "Mitigates XSS / data injection"),
    "X-Content-Type-Options": ("Low", "Prevents MIME sniffing"),
    "X-Frame-Options": ("Low", "Clickjacking protection (or CSP frame-ancestors)"),
    "Referrer-Policy": ("Info", "Controls Referer leakage"),
    "Permissions-Policy": ("Info", "Restricts browser features"),
}

# Patterns that look like secret keys or passwords
SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "Google API key": r"AIza[0-9A-Za-z_\-]{35}",
    "Private key block": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "JWT": r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    "Hardcoded secret/token": r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
}

# Patterns that look like error messages
ERROR_LEAKS = {
    "Python traceback": r"Traceback \(most recent call last\)",
    "Java stack trace": r"at [\w.$]+\([\w]+\.java:\d+\)",
    "PHP error": r"(?:Warning|Fatal error|Notice): .+ on line \d+",
    "Node/Express stack": r"at [\w.<>]+ \(.*\.js:\d+:\d+\)",
    "ASP.NET error": r"Server Error in '/' Application",
}

# small "known old" table
OLD_JS = {"jquery": (3, 5, 0), "angular": (1, 8, 0), "bootstrap": (4, 3, 1)}
VERSION_IN_NAME = re.compile(r"(jquery|angular|bootstrap)[-.@/]*v?(\d+)\.(\d+)\.(\d+)", re.I)


def passive_checks(resp: requests.Response, body: str, res: Results):
    url, h = resp.url, resp.headers
    is_html = "html" in h.get("Content-Type", "")

    if is_html:
        # Check 1: Are security headers missing?
        for name, (sev, why) in SEC_HEADERS.items():
            if name not in h and not (name == "X-Frame-Options" and "frame-ancestors" in h.get("Content-Security-Policy", "")):
                res.add(Finding("missing-header", sev, url, f"Missing {name}", why))
        if url.startswith("https") and "Strict-Transport-Security" not in h:
            res.add(Finding("missing-header", "Medium", url, "Missing HSTS header"))

    # Check 2: Does the server reveal its software version?
    for k in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if k in h and re.search(r"\d", h[k]):
            res.add(Finding("info-leak", "Low", url, f"Version disclosed in {k}", h[k]))

    # Check 3: Are cookies set up safely?
    # cookies: parse each Set-Cookie header individually
    raw = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    for c in raw:
        name, low = c.split("=", 1)[0], c.lower()
        if "httponly" not in low:
            res.add(Finding("cookie-flags", "Medium", url, f"Cookie '{name}' lacks HttpOnly", c[:80]))
        if "samesite" not in low:
            res.add(Finding("cookie-flags", "Low", url, f"Cookie '{name}' lacks SameSite", c[:80]))
        if url.startswith("https") and "secure" not in low:
            res.add(Finding("cookie-flags", "Medium", url, f"Cookie '{name}' lacks Secure", c[:80]))

    # Check 4: CORS settings. "*" means any website is allowed to read responses.
    acao = h.get("Access-Control-Allow-Origin")
    if acao == "*":
        sev = "Medium" if h.get("Access-Control-Allow-Credentials", "").lower() == "true" else "Low"
        res.add(Finding("cors", sev, url, "Wildcard Access-Control-Allow-Origin", "ACAO: *"))

    # Check 5: Does the page show an error message that leaks private info?
    for label, pat in ERROR_LEAKS.items():
        m = re.search(pat, body)
        if m:
            res.add(Finding("error-leak", "Medium", url, f"{label} in response", m.group(0)[:100]))

    # Check 6: Is there a secret key or password on the page?
    for label, pat in SECRET_PATTERNS.items():
        m = re.search(pat, body)
        if m:
            res.add(Finding("secret-exposure", "High", url, f"Possible {label}", m.group(0)[:12] + "..."))

    if is_html:
        soup = BeautifulSoup(body, "html.parser")
        # Check 7: Check for developer HTML comments
        for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
            if re.search(r"(?i)todo|fixme|password|admin|debug|secret|key", c):
                res.add(Finding("html-comment", "Info", url, "Suspicious HTML comment", c.strip()[:100]))
        # Check 8: A secure https page loading over insecure http
        if url.startswith("https"):
            for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")):
                for t in soup.find_all(tag):
                    if str(t.get(attr, "")).startswith("http://"):
                        res.add(Finding("mixed-content", "Medium", url, f"<{tag}> loads over HTTP", t[attr]))
        # Check 9: Login forms
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}) and urlparse(urljoin(url, form.get("action", ""))).scheme == "http":
                res.add(Finding("insecure-login", "High", url, "Password form submits over HTTP"))
            if form.find("input", {"type": "password"}) and form.get("autocomplete", "").lower() != "off":
                res.add(Finding("form", "Info", url, "Password field allows autocomplete"))
        # Check 10: Look for old javascript version
        for s in soup.find_all("script", src=True):
            check_js_version(urljoin(url, s["src"]), url, res)
    # Checks if the page's URL is a library file with an old version
    for m in VERSION_IN_NAME.finditer(url):
        check_js_version(url, url, res)


def check_js_version(src, page, res):
    m = VERSION_IN_NAME.search(src)
    if not m:
        return
    lib, ver = m.group(1).lower(), tuple(int(x) for x in m.groups()[1:])
    if ver < OLD_JS[lib]:
        res.add(Finding("outdated-js", "Medium", page, f"{lib} {'.'.join(map(str, ver))} is outdated", src))


# ------------------------------------------------------------- active checks
# Sends test inputs to website to see how it reacts
# Only runs if with --active turned on
SQL_ERRORS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"sqlite3?\.operationalerror", r"sqlite_error",
    r"pg_query\(\)|psycopg2\.errors|syntax error at or near", r"odbc.*driver|microsoft ole db",
]


def inject(url, param, value):
    # Builds a new URL with one parameter swapped for test value.
    # ?id=1 for ?id=test
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


def active_checks(session, targets, res, delay):
    """targets: list of (method, url, {param: default}) discovered by the crawler."""
    for method, url, params in targets:
        for param in params:
            # --- reflected XSS: harmless canary, see if angle brackets come back unencoded
            # Test 1 (XSS): Sends a word with special characters.
            canary = "bs" + uuid.uuid4().hex[:8]
            payload = f"{canary}<\"'>"
            r = send(session, method, url, params, param, payload)
            time.sleep(delay)
            if r is not None and payload in r.text:
                res.add(Finding("reflected-xss", "High", url, f"Parameter '{param}' reflects <\"'> unencoded",
                                f"canary {canary} found raw in response", "active"))
            # --- error-based SQLi: single quote, look for DB error strings
            # Test 2 (SQL injection): Sends a single quote ('). If it returns an error
            # it may be passing input directly into database
            r = send(session, method, url, params, param, "'")
            time.sleep(delay)
            if r is not None:
                for pat in SQL_ERRORS:
                    if re.search(pat, r.text, re.I):
                        res.add(Finding("sqli-error", "High", url, f"Parameter '{param}' triggers a SQL error",
                                        pat, "active"))
                        break


def send(session, method, url, params, param, value):
    data = dict(params, **{param: value})
    try:
        if method == "GET":
            return session.get(url.split("?")[0], params=data, timeout=10)
        return session.post(url, data=data, timeout=10)
    except requests.RequestException:
        return None


# ------------------------------------------------------------------- crawler
# Visits website and finds all pages
def crawl(base, session, res, max_pages, delay, seeds=(), exclude=()):
    host = urlparse(base).netloc
    queue, seen, targets = [base] + [urljoin(base, x) for x in seeds], set(), []
    # Keep going until no pages left or hit page limit.
    while queue and len(seen) < max_pages:
        url = queue.pop(0).split("#")[0]
        if url in seen or any(x.lower() in url.lower() for x in exclude):
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=10) # download the page
        except requests.RequestException as e:
            print(f"[!] {url}: {e}", file=sys.stderr)
            continue
        print(f"[{r.status_code}] {url}") # show progress in terminal
        passive_checks(r, r.text, res) # run all passive checks
        time.sleep(delay)
        # If webpage has parameters like ?id=1, save them
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if q:
            targets.append(("GET", url, q))
        # If not a normal webpage then no links to follow
        if "html" not in r.headers.get("Content-Type", ""):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        # Find every link on page then add to queue
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            if urlparse(nxt).netloc == host and nxt not in seen:
                queue.append(nxt)
        # parameters from forms
        # Find every form on page and save as targets.
        for f in soup.find_all("form"):
            action = urljoin(url, f.get("action", ""))
            if urlparse(action).netloc != host:
                continue
            fields = {i.get("name"): i.get("value", "test") for i in f.find_all(["input", "textarea"])
                      if i.get("name") and i.get("type") not in ("password", "file")}
            if fields:
                targets.append((f.get("method", "get").upper(), action, fields))
    return targets


# -------------------------------------------------------------------- report
# Saves all findings into files
def write_report(res, base, mode, path):
    items = res.sorted() # all sorted findings
    counts = {} # how many findings of each severity
    for f in items:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    # save .json file
    with open(path + ".json", "w") as fh:
        json.dump([asdict(f) for f in items], fh, indent=2)
    # save .md file
    with open(path + ".md", "w") as fh:
        fh.write(f"# bugscan report\n\n- Target: {base}\n- Mode: {mode}\n- Findings: {len(items)} {counts}\n\n")
        fh.write("| Severity | Mode | Check | URL | Detail | Evidence |\n|---|---|---|---|---|---|\n")
        for f in items:
            ev = f.evidence.replace("|", "\\|").replace("\n", " ")
            fh.write(f"| {f.severity} | {f.mode} | {f.check} | {f.url} | {f.detail} | `{ev}` |\n")
    # Show summary in terminal
    print(f"\n{len(items)} findings {counts} -> {path}.md / {path}.json")


# Reads user input, runs crawler, active scan if enabled, then prints report.
def main():
    ap = argparse.ArgumentParser(description="Passive-first web bug scanner (authorized targets only)")
    ap.add_argument("target")
    ap.add_argument("--active", action="store_true", help="enable active checks (needs --allow)")
    ap.add_argument("--allow", action="append", default=[], help="hostname allowed for active checks (repeatable)")
    ap.add_argument("--max-pages", type=int, default=30)
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests")
    ap.add_argument("--seed", action="append", default=[], help="extra path/URL to scan, e.g. '/rest/products/search?q=test' (repeatable)")
    ap.add_argument("--exclude", action="append", default=["logout", "setup.php"], help="skip URLs containing this text (repeatable; default: logout, setup.php)")
    ap.add_argument("--cookie", help='e.g. "PHPSESSID=abc; security=low"')
    ap.add_argument("--out", default="bugscan_report")
    a = ap.parse_args()

    host = urlparse(a.target).hostname
    if a.active and host not in a.allow:
        sys.exit(f"[x] Refusing active scan: '{host}' is not in --allow. Only scan systems you are authorized to test.")

    s = requests.Session()
    s.headers["User-Agent"] = "bugscan/0.1 (class project)"
    if a.cookie:
        for part in a.cookie.split(";"):
            k, _, v = part.strip().partition("=")
            s.cookies.set(k, v)

    res = Results()
    # Crawl the site
    targets = crawl(a.target, s, res, a.max_pages, a.delay, a.seed, a.exclude)
    # Active scan
    if a.active:
        print(f"\n[active] testing {len(targets)} injection points")
        active_checks(s, targets, res, a.delay)
    # Save to report files
    write_report(res, a.target, "hybrid" if a.active else "passive", a.out)


if __name__ == "__main__":
    main()
