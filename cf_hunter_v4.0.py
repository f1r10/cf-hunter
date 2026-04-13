#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         CF-HUNTER v4.0 @f1r10 — Advanced Cloudflare IP Intelligence     ║
║  BGP/ASN · TLS/SAN · Tech-Detect · JS-Scan · Favicon · Leak-Detect      ║
║  Source Scoring · Cross-Validation · Correlation Engine · Cloud-Classify ║
║              Yalnız icazəli testlər üçün istifadə edin                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import sys
import socket
import json
import time
import ipaddress
import argparse
import concurrent.futures
import re
import ssl
import hashlib
import struct
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urlparse, urljoin
from datetime import datetime

# ──────────────────────────────────────────────────────────────
#  Terminal rənglər
# ──────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗███████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗  █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔══╝  ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}  Cloudflare Real IP Intelligence v4.0 @f1r10
  BGP/ASN | TLS/SAN | Tech-Detect | JS-Scan | Favicon | Leak-Detect | Correlation{C.RESET}
""")

# ──────────────────────────────────────────────────────────────
#  Source Reliability Scoring
# ──────────────────────────────────────────────────────────────
# DIRECT OBSERVATION = highest trust (live DNS, TLS cert, live HTTP)
# VERIFIED_API       = medium trust  (known APIs with structured response)
# SCRAPED_DATA       = low trust     (scraped HTML, third-party aggregators)

SOURCE_TRUST = {
    # DIRECT OBSERVATION (weight 3)
    "current-dns":   ("DIRECT", 3),
    "mx-record":     ("DIRECT", 3),
    "spf-record":    ("DIRECT", 3),
    "zone-transfer": ("DIRECT", 3),
    "tls-san":       ("DIRECT", 3),
    # VERIFIED API (weight 2)
    "urlscan.io":    ("VERIFIED_API", 2),
    "alienvault-otx":("VERIFIED_API", 2),
    "shodan-idb":    ("VERIFIED_API", 2),
    "bgpview":       ("VERIFIED_API", 2),
    "ipinfo":        ("VERIFIED_API", 2),
    "crtsh":         ("VERIFIED_API", 2),
    "certspotter":   ("VERIFIED_API", 2),
    "hackertarget":  ("VERIFIED_API", 2),
    "github-leak":   ("VERIFIED_API", 2),
    # SCRAPED DATA (weight 1)
    "rapiddns":      ("SCRAPED", 1),
    "bufferover":    ("SCRAPED", 1),
    "wayback":       ("SCRAPED", 1),
    "threatminer":   ("SCRAPED", 1),
    "anubis":        ("SCRAPED", 1),
    "reverse-ip":    ("SCRAPED", 1),
    "favicon-match": ("SCRAPED", 1),
}

def source_trust(src):
    """Return (tier, weight) for a source label (handles sub:* prefixes)."""
    if src.startswith("sub:"):
        return ("DIRECT", 2)   # live resolved subdomain IP
    for key, val in SOURCE_TRUST.items():
        if key in src:
            return val
    return ("SCRAPED", 1)

# ──────────────────────────────────────────────────────────────
#  Cloudflare CIDR ranges
# ──────────────────────────────────────────────────────────────
CF_RANGES = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
    "2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32",
    "2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
]
CF_NETS = []
for _r in CF_RANGES:
    try:
        CF_NETS.append(ipaddress.ip_network(_r, strict=False))
    except Exception:
        pass

# ── Known Cloud / CDN ASN fingerprints ────────────────────────
CLOUD_ASN_MAP = {
    # Amazon / AWS
    "AS16509": "AWS", "AS14618": "AWS", "AS8987": "AWS",
    # Google / GCP
    "AS15169": "GCP", "AS396982": "GCP", "AS19527": "GCP",
    # Microsoft / Azure
    "AS8075": "Azure", "AS8069": "Azure",
    # Cloudflare
    "AS13335": "Cloudflare", "AS209242": "Cloudflare",
    # Fastly
    "AS54113": "Fastly",
    # Akamai
    "AS20940": "Akamai", "AS16625": "Akamai",
    # DigitalOcean
    "AS14061": "DigitalOcean",
    # Vultr
    "AS20473": "Vultr",
    # Linode
    "AS63949": "Linode",
    # OVH
    "AS16276": "OVH",
    # Hetzner
    "AS24940": "Hetzner",
    # Imperva/Incapsula
    "AS19551": "Imperva",
    # Sucuri
    "AS30148": "Sucuri",
}

CLOUD_ORG_KEYWORDS = {
    "amazon": "AWS", "aws": "AWS",
    "google": "GCP", "gcp": "GCP",
    "microsoft": "Azure", "azure": "Azure",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "digitalocean": "DigitalOcean",
    "vultr": "Vultr",
    "linode": "Linode",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "incapsula": "Imperva", "imperva": "Imperva",
    "sucuri": "Sucuri",
}

def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in CF_NETS)
    except Exception:
        return False

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def classify_cloud(asn="", org=""):
    """Return cloud/CDN provider name or None."""
    asn_key = asn.split()[0].upper() if asn else ""
    if asn_key in CLOUD_ASN_MAP:
        return CLOUD_ASN_MAP[asn_key]
    org_lower = org.lower()
    for kw, provider in CLOUD_ORG_KEYWORDS.items():
        if kw in org_lower:
            return provider
    return None

def ip_label(ip, provider=None):
    if is_cloudflare(ip):
        return f"{C.RED}[CF]{C.RESET}     "
    if is_private(ip):
        return f"{C.DIM}[PRIV]{C.RESET}   "
    if provider and provider != "Cloudflare":
        return f"{C.YELLOW}[{provider[:6].upper()}]{C.RESET} "
    return f"{C.GREEN}[REAL?]{C.RESET}  "

# ──────────────────────────────────────────────────────────────
#  HTTP helper — SSL skip + retry + header capture
# ──────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CF-Hunter/4.0",
    "Accept":     "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

def http_get(url, timeout=14, retries=2):
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=_HEADERS)
            with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception:
            if attempt < retries:
                time.sleep(1.5)
    return None

def http_get_with_headers(url, timeout=14):
    """Returns (body, response_headers_dict) or (None, {})."""
    try:
        req = Request(url, headers=_HEADERS)
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            body = r.read().decode("utf-8", errors="replace")
            hdrs = dict(r.headers)
            return body, hdrs
    except Exception:
        return None, {}

def http_get_bytes(url, timeout=10):
    try:
        req = Request(url, headers=_HEADERS)
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            return r.read()
    except Exception:
        return None

def http_json(url, timeout=14, retries=2):
    raw = http_get(url, timeout=timeout, retries=retries)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None

# ──────────────────────────────────────────────────────────────
#  Subdomain collector
# ──────────────────────────────────────────────────────────────
class SubCollector:
    def __init__(self, domain):
        self.domain = domain
        self.subs   = set()

    def add(self, raw):
        s = raw.strip().lower().lstrip("*.")
        if s.endswith(f".{self.domain}") and s != self.domain:
            self.subs.add(s)

    def result(self):
        return sorted(self.subs)


# ══════════════════════════════════════════════════════════════
#  OSINT SOURCES (original 12)
# ══════════════════════════════════════════════════════════════

def src_crtsh(domain, col):
    for url in [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]:
        data = http_json(url, timeout=20)
        if not data:
            continue
        for entry in data:
            for field in ("name_value", "common_name"):
                for line in entry.get(field, "").replace(",", "\n").split("\n"):
                    col.add(line.strip())
    return len(col.subs)

def src_certspotter(domain, col):
    data = http_json(
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names",
        timeout=15,
    )
    n = 0
    if data and isinstance(data, list):
        for cert in data:
            for name in cert.get("dns_names", []):
                col.add(name)
                n += 1
    return n

def src_alienvault(domain, col):
    ips = []
    d = http_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=12,
    )
    if d:
        for e in d.get("passive_dns", []):
            a = e.get("address", "")
            if is_valid_ip(a) and a not in ips:
                ips.append(a)
    for page in range(1, 6):
        d2 = http_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
            f"/url_list?limit=100&page={page}",
            timeout=12,
        )
        if not d2:
            break
        urls = d2.get("url_list", [])
        if not urls:
            break
        for u in urls:
            h = u.get("domain", "") or u.get("hostname", "")
            if h:
                col.add(h)
    return ips

def src_hackertarget(domain, col):
    ips = []
    raw = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12)
    if raw and "error" not in raw.lower() and "API count" not in raw:
        for line in raw.strip().split("\n"):
            parts = line.split(",")
            if len(parts) >= 2:
                col.add(parts[0].strip())
                ip = parts[1].strip()
                if is_valid_ip(ip) and ip not in ips:
                    ips.append(ip)
    return ips

def src_urlscan(domain, col):
    ips = []
    data = http_json(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
        timeout=15,
    )
    if data:
        for r in data.get("results", []):
            ip = r.get("page", {}).get("ip", "")
            if is_valid_ip(ip) and ip not in ips:
                ips.append(ip)
            h = r.get("page", {}).get("domain", "")
            if h:
                col.add(h)
    return ips

def src_threatminer(domain, col):
    data = http_json(
        f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
        timeout=12,
    )
    n = 0
    if data:
        for s in data.get("results", []):
            col.add(s)
            n += 1
    return n

def src_anubis(domain, col):
    data = http_json(f"https://jldc.me/anubis/subdomains/{domain}", timeout=12)
    n = 0
    if data and isinstance(data, list):
        for s in data:
            col.add(s)
            n += 1
    return n

def src_rapiddns(domain, col):
    raw = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15)
    n = 0
    if raw:
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        for s in re.findall(pattern, raw):
            col.add(s)
            n += 1
    return n

def src_bufferover(domain, col):
    data = http_json(f"https://tls.bufferover.run/dns?q=.{domain}", timeout=10)
    n = 0
    if data:
        for line in data.get("Results", []) or []:
            parts = line.split(",")
            if len(parts) >= 4:
                col.add(parts[3].strip())
                n += 1
    return n

def src_wayback(domain, col):
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    )
    data = http_json(url, timeout=20)
    n = 0
    if data and len(data) > 1:
        pat = re.compile(
            r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')'
        )
        for row in data[1:]:
            if row:
                m = pat.search(row[0])
                if m:
                    col.add(m.group(1))
                    n += 1
    return n


# ══════════════════════════════════════════════════════════════
#  NEW: NETWORK INTELLIGENCE (BGPView + ip-api + RIPE)
# ══════════════════════════════════════════════════════════════

def bgpview_lookup(ip):
    """BGPView API — ASN, prefix, RIR info."""
    d = http_json(f"https://api.bgpview.io/ip/{ip}", timeout=10)
    if not d or d.get("status") != "ok":
        return {}
    data = d.get("data", {})
    result = {
        "asn": "", "asn_name": "", "prefix": "", "rir": "", "country": ""
    }
    prefixes = data.get("prefixes", [])
    if prefixes:
        p = prefixes[0]
        asn_info = p.get("asn", {})
        result["asn"]      = f"AS{asn_info.get('asn', '')}"
        result["asn_name"] = asn_info.get("name", "")
        result["prefix"]   = p.get("prefix", "")
        result["rir"]      = p.get("rir_allocation", {}).get("rir_name", "")
        result["country"]  = p.get("country_codes", {}).get("whois_country_code", "")
    return result

def ipapi_info(ip):
    """ip-api.com — org, ISP, mobile/proxy/hosting flags."""
    d = http_json(
        f"http://ip-api.com/json/{ip}?fields=status,org,isp,country,city,hosting,proxy,mobile",
        timeout=8,
    )
    if d and d.get("status") == "success":
        return {
            "org":     d.get("org", ""),
            "isp":     d.get("isp", ""),
            "country": d.get("country", ""),
            "city":    d.get("city", ""),
            "hosting": d.get("hosting", False),
            "proxy":   d.get("proxy", False),
            "mobile":  d.get("mobile", False),
        }
    return {}

def ip_info(ip):
    """ipinfo.io — primary IP enrichment."""
    d = http_json(f"https://ipinfo.io/{ip}/json", timeout=8)
    if d:
        return {
            "org":      d.get("org", "?"),
            "city":     d.get("city", "?"),
            "country":  d.get("country", "?"),
            "hostname": d.get("hostname", ""),
        }
    return {"org": "?", "city": "?", "country": "?", "hostname": ""}


# ══════════════════════════════════════════════════════════════
#  NEW: REVERSE INFRASTRUCTURE ANALYSIS
# ══════════════════════════════════════════════════════════════

def reverse_ip_lookup(ip):
    """HackerTarget reverse IP — find co-hosted domains."""
    raw = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12)
    if not raw or "error" in raw.lower() or "API count" in raw:
        return []
    domains = [d.strip() for d in raw.strip().split("\n") if d.strip()]
    return domains[:50]

def viewdns_reverse_ip(ip):
    """ViewDNS.info reverse IP (HTML scrape fallback)."""
    raw = http_get(f"https://viewdns.info/reverseip/?host={ip}&apikey=free", timeout=12)
    if not raw:
        return []
    pattern = r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>'
    return list(set(re.findall(pattern, raw)))[:30]


# ══════════════════════════════════════════════════════════════
#  NEW: TLS DEEP ANALYSIS
# ══════════════════════════════════════════════════════════════

def tls_analyze(hostname, port=443, timeout=8):
    """
    Extract TLS certificate info: SANs, CN, issuer, validity,
    cipher suite. Returns dict with findings.
    """
    result = {
        "cn": "", "sans": [], "issuer": "", "not_after": "",
        "cipher": "", "version": "", "weak": False,
        "error": None
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                result["version"] = ssock.version() or ""
                result["cipher"]  = cipher[0] if cipher else ""

                # CN
                for field in cert.get("subject", []):
                    for k, v in field:
                        if k == "commonName":
                            result["cn"] = v

                # Issuer
                for field in cert.get("issuer", []):
                    for k, v in field:
                        if k == "organizationName":
                            result["issuer"] = v

                # SANs
                for entry in cert.get("subjectAltName", []):
                    if entry[0] == "DNS":
                        result["sans"].append(entry[1].lstrip("*."))

                # Validity
                result["not_after"] = cert.get("notAfter", "")

                # Weak TLS check
                weak_versions = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
                if result["version"] in weak_versions:
                    result["weak"] = True
                weak_ciphers = {"RC4", "DES", "3DES", "NULL", "EXPORT"}
                if any(w in result["cipher"].upper() for w in weak_ciphers):
                    result["weak"] = True

    except Exception as e:
        result["error"] = str(e)

    return result

def tls_san_to_ips(sans, domain):
    """Resolve TLS SANs to IPs. Returns list of (san, ip) tuples."""
    pairs = []
    for san in sans:
        if not san.endswith(f".{domain}") and san != domain:
            continue
        try:
            for info in socket.getaddrinfo(san, None):
                ip = info[4][0]
                if is_valid_ip(ip):
                    pairs.append((san, ip))
        except Exception:
            pass
    return pairs


# ══════════════════════════════════════════════════════════════
#  NEW: TECHNOLOGY DETECTION
# ══════════════════════════════════════════════════════════════

TECH_PATTERNS = {
    # Web servers
    "Apache":       [r'Server:\s*Apache', r'<address>Apache'],
    "Nginx":        [r'Server:\s*nginx'],
    "LiteSpeed":    [r'Server:\s*LiteSpeed'],
    "IIS":          [r'Server:\s*Microsoft-IIS'],
    "Caddy":        [r'Server:\s*Caddy'],
    # Languages / Frameworks
    "PHP":          [r'X-Powered-By:\s*PHP', r'\.php\b', r'PHPSESSID'],
    "ASP.NET":      [r'X-Powered-By:\s*ASP\.NET', r'__VIEWSTATE', r'\.aspx\b'],
    "Django":       [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
    "Laravel":      [r'laravel_session', r'XSRF-TOKEN'],
    "WordPress":    [r'/wp-content/', r'/wp-includes/', r'wp-login\.php'],
    "Joomla":       [r'/components/com_', r'Joomla'],
    "Drupal":       [r'Drupal\.settings', r'/sites/default/files/'],
    "React":        [r'__reactFiber', r'_reactRootContainer', r'react-app'],
    "Next.js":      [r'__NEXT_DATA__', r'/_next/static/'],
    "Vue.js":       [r'__vue__', r'data-v-'],
    "Angular":      [r'ng-version', r'ng-app', r'angular\.js'],
    # CDN / Infrastructure
    "Cloudflare":   [r'CF-Ray:', r'cf-cache-status', r'__cfduid'],
    "Varnish":      [r'X-Varnish:', r'Via:.*varnish'],
    "Fastly":       [r'X-Served-By:.*cache', r'Fastly-Restarts:'],
    # Security
    "ModSecurity":  [r'Mod_Security', r'NOYB'],
    "reCAPTCHA":    [r'google\.com/recaptcha', r'g-recaptcha'],
    # CMS / Platforms
    "Shopify":      [r'cdn\.shopify\.com', r'Shopify\.theme'],
    "Magento":      [r'Mage\.', r'/skin/frontend/'],
    "Wix":          [r'static\.wixstatic\.com'],
    "Squarespace":  [r'static\.squarespace\.com'],
}

def detect_technology(body="", headers=None):
    """
    Detect technologies from HTTP headers + HTML body.
    Returns dict: {tech_name: [matched_patterns]}.
    """
    if headers is None:
        headers = {}
    found = {}
    # Merge headers into a searchable string
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    combined   = header_str + "\n" + (body or "")

    for tech, patterns in TECH_PATTERNS.items():
        hits = []
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                hits.append(pat.split(r'[:\s]')[0].strip(r'\\'))
        if hits:
            found[tech] = hits
    return found


# ══════════════════════════════════════════════════════════════
#  NEW: JAVASCRIPT & ENDPOINT DISCOVERY
# ══════════════════════════════════════════════════════════════

_JS_ENDPOINT_RE = re.compile(
    r"""(?:['"`])((?:/[a-zA-Z0-9_\-./]+){1,5}(?:\?[^'"`\s]*)?)(?:['"`])""",
    re.VERBOSE,
)
_JS_URL_RE = re.compile(
    r"""(?:url|endpoint|api|href|action)\s*[:=]\s*['"`]([^'"`\s]{5,100})['"`]""",
    re.IGNORECASE,
)

def extract_js_endpoints(base_url, html, max_scripts=5):
    """
    Find <script src> tags in HTML, fetch JS files, extract endpoint patterns.
    Returns list of unique endpoint strings.
    """
    endpoints = set()
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)

    parsed  = urlparse(base_url)
    base    = f"{parsed.scheme}://{parsed.netloc}"

    for src in script_srcs[:max_scripts]:
        if src.startswith("//"):
            src = parsed.scheme + ":" + src
        elif src.startswith("/"):
            src = base + src
        elif not src.startswith("http"):
            src = base + "/" + src

        js_body = http_get(src, timeout=10, retries=1)
        if not js_body:
            continue

        for m in _JS_ENDPOINT_RE.finditer(js_body):
            ep = m.group(1)
            if len(ep) > 3 and not ep.startswith("//"):
                endpoints.add(ep)

        for m in _JS_URL_RE.finditer(js_body):
            ep = m.group(1)
            if ep.startswith("/") or ep.startswith("http"):
                endpoints.add(ep)

    # Filter: keep likely API/endpoint patterns
    interesting = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql",
                                             "/auth/", "/user", "/admin", "/upload", "/config"])
    ]
    return sorted(interesting)[:50]


# ══════════════════════════════════════════════════════════════
#  NEW: FAVICON HASH FINGERPRINTING
# ══════════════════════════════════════════════════════════════

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 (32-bit) — Shodan-compatible."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h      = seed
    length = len(data)
    nblocks = length // 4

    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = ((h * 5) + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3: k ^= tail[2] << 16
    if len(tail) >= 2: k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k  = (k * c1) & 0xFFFFFFFF
        k  = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k  = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length
    h ^= (h >> 16)
    h  = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h  = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)

    # Return as signed 32-bit (Shodan convention)
    return h - 2**32 if h >= 2**31 else h

import base64 as _b64

def favicon_hash(domain):
    """
    Download /favicon.ico, compute Shodan-compatible mmh3 hash.
    Returns dict with hash, size, md5, url.
    """
    for scheme in ("https", "http"):
        url  = f"{scheme}://{domain}/favicon.ico"
        data = http_get_bytes(url, timeout=8)
        if data and len(data) > 10:
            # Shodan uses base64 of raw bytes then mmh3
            b64  = _b64.encodebytes(data).decode()
            mmh  = _murmur3_32(b64.encode())
            md5  = hashlib.md5(data).hexdigest()
            return {
                "url":     url,
                "size":    len(data),
                "mmh3":    mmh,
                "md5":     md5,
                "shodan_query": f"http.favicon.hash:{mmh}",
            }
    return {}


# ══════════════════════════════════════════════════════════════
#  NEW: GITHUB LEAK DETECTION (safe mode)
# ══════════════════════════════════════════════════════════════

GITHUB_SAFE_QUERIES = [
    "{domain}",
    "{domain} password",
    "{domain} config",
    "{domain} api_key",
    "{domain} secret",
    "{domain} db_host",
    "{domain} private_key",
    "{domain} connection_string",
]

def github_leak_scan(domain):
    """
    Public GitHub code search for accidental exposure of domain credentials/config.
    Uses unauthenticated API (rate-limited). Returns list of finding dicts.
    """
    findings = []
    seen_repos = set()

    for q_template in GITHUB_SAFE_QUERIES[:4]:   # limit to 4 queries to avoid rate-limit
        q   = quote(q_template.format(domain=domain))
        url = f"https://api.github.com/search/code?q={q}&per_page=10"
        data = http_json(url, timeout=12)
        if not data or "items" not in data:
            break

        for item in data.get("items", []):
            repo  = item.get("repository", {}).get("full_name", "")
            fname = item.get("name", "")
            furl  = item.get("html_url", "")
            if repo and repo not in seen_repos:
                seen_repos.add(repo)
                findings.append({
                    "repo":  repo,
                    "file":  fname,
                    "url":   furl,
                    "query": q_template.format(domain=domain),
                })
        time.sleep(1.2)   # respect public rate-limit

    return findings


# ══════════════════════════════════════════════════════════════
#  DNS RECORDS (original — unchanged)
# ══════════════════════════════════════════════════════════════

def doh_query(name, rtype):
    data = http_json(
        f"https://dns.google/resolve?name={quote(name)}&type={rtype}",
        timeout=10,
    )
    if data:
        return data.get("Answer", [])
    return []

def dns_records_analysis(domain):
    out = {"mx": [], "mx_ips": [], "spf_ips": [], "ns": [], "txt": []}
    for a in doh_query(domain, "MX"):
        raw = a.get("data", "")
        mx_host = raw.split()[-1].rstrip(".") if raw else ""
        if mx_host and mx_host not in out["mx"]:
            out["mx"].append(mx_host)
            try:
                for info in socket.getaddrinfo(mx_host, None):
                    ip = info[4][0]
                    if is_valid_ip(ip) and ip not in out["mx_ips"]:
                        out["mx_ips"].append(ip)
            except Exception:
                pass
    for a in doh_query(domain, "TXT"):
        txt = a.get("data", "").strip('"')
        out["txt"].append(txt)
        if "v=spf1" in txt:
            for ip_cidr in re.findall(r'ip4:([0-9./]+)', txt):
                try:
                    net = ipaddress.ip_network(ip_cidr, strict=False)
                    ip  = str(net.network_address)
                except Exception:
                    ip = ip_cidr
                if ip not in out["spf_ips"]:
                    out["spf_ips"].append(ip)
    for a in doh_query(domain, "NS"):
        ns = a.get("data", "").rstrip(".")
        if ns and ns not in out["ns"]:
            out["ns"].append(ns)
    return out

def try_zone_transfer(domain, ns_list):
    subs = []
    try:
        import dns.query, dns.zone
        for ns in ns_list[:3]:
            try:
                ns_ip = socket.gethostbyname(ns)
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                for name in z.nodes.keys():
                    s = str(name)
                    if s != "@":
                        subs.append(f"{s}.{domain}")
            except Exception:
                pass
    except ImportError:
        pass
    return subs


# ──────────────────────────────────────────────────────────────
#  Brute wordlist
# ──────────────────────────────────────────────────────────────
WORDLIST = [
    "www","www2","www3","web","web1","web2","website","site","portal","home",
    "mail","mail1","mail2","smtp","imap","pop","pop3","mx","mx1","mx2",
    "webmail","email","mailserver","autodiscover","autoconfig","exchange",
    "admin","administrator","panel","cpanel","whm","plesk","dashboard",
    "manage","management","control","backend","backoffice","staff","login",
    "dev","develop","development","staging","stage","test","testing","qa",
    "beta","alpha","demo","sandbox","preview","temp","tmp","new","old","uat",
    "api","api2","api-v1","api-v2","rest","graphql","gateway","services","ws",
    "cdn","static","assets","img","images","media","files","upload","uploads",
    "download","downloads","storage","s3","blob","content","video","audio",
    "ns1","ns2","ns3","ns4","dns","dns1","dns2","vpn","proxy","firewall",
    "db","database","mysql","postgres","redis","mongo","elastic","kibana",
    "grafana","prometheus","jenkins","gitlab","git","svn","repo","jira","ci",
    "secure","ssl","auth","sso","oauth","ldap","ad","idp","saml",
    "app","app1","app2","mobile","m","wap","v1","v2","intranet","extranet",
    "monitor","monitoring","status","health","metrics","logs","log","alert",
    "support","help","helpdesk","ticket","forum","blog","news","shop","store",
    "pay","payment","checkout","cart","crm","erp","hr","remote","access",
    "lms","moodle","edu","student","students","professor","library","lib",
    "elib","elearning","exam","admission","rector","department","science",
    "research","sport","dorm","hostel","video","conf","conference","meet",
    "office","docs","doc","wiki","kb","ftp","sftp","ssh","rdp","vnc",
    "backup","bak","archive","old2","test2","preprod","prod","production",
    "cloud","cluster","node","worker","master","slave","replica",
    "mail3","imap2","smtp2","relay","mx3","mta","postfix","dovecot",
    "_dmarc","dkim","spf","vpn2","remote2","portal2","secure2","app3",
]

def brute_subs(domain):
    return sorted(set(f"{w}.{domain}" for w in WORDLIST))


# ──────────────────────────────────────────────────────────────
#  Parallel resolve
# ──────────────────────────────────────────────────────────────
def _resolve_one(sub):
    try:
        return sub, list({i[4][0] for i in socket.getaddrinfo(sub, None, proto=socket.IPPROTO_TCP)})
    except Exception:
        return sub, []

def resolve_all(subs, workers=60):
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for sub, ips in ex.map(_resolve_one, subs):
            if ips:
                out[sub] = ips
    return out


# ──────────────────────────────────────────────────────────────
#  Shodan InternetDB
# ──────────────────────────────────────────────────────────────
def shodan_info(ip):
    d = http_json(f"https://internetdb.shodan.io/{ip}", timeout=8)
    if d and "detail" not in str(d).lower():
        return d
    return None


# ══════════════════════════════════════════════════════════════
#  CONFIDENCE SCORING (enhanced with source trust tiers)
# ══════════════════════════════════════════════════════════════

def confidence_score(sources):
    """
    Weighted confidence using source reliability tiers.
    Cross-validation: bonus if 2+ independent high-trust sources confirm.
    """
    s        = set(sources)
    total    = 0
    direct   = 0
    verified = 0

    for src in s:
        tier, weight = source_trust(src)
        total += weight
        if tier == "DIRECT":
            direct += 1
        elif tier == "VERIFIED_API":
            verified += 1

    # Bonus for high-trust signals
    if any("mx" in x or "spf" in x for x in s):  total += 3
    if "urlscan.io"     in s:                     total += 2
    if "alienvault-otx" in s:                     total += 2
    if "hackertarget"   in s:                     total += 1
    if any("sub:" in x for x in s):               total += 1
    if "tls-san"        in s:                     total += 3

    # Cross-validation bonus: 2+ independent DIRECT signals
    if direct >= 2:
        total += 4
    elif direct >= 1 and verified >= 1:
        total += 2

    return total

def cross_validated(sources):
    """True if IP is confirmed by ≥2 independent signals or 1 strong direct."""
    s      = set(sources)
    direct = sum(1 for src in s if source_trust(src)[0] == "DIRECT")
    if direct >= 1:          return True
    if len(s) >= 2:          return True
    return False


# ══════════════════════════════════════════════════════════════
#  CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════

class CorrelationEngine:
    """
    Classifies each IP as: ORIGIN | CDN | MAIL | API | SHARED_HOST | UNKNOWN.
    Groups related infrastructure and eliminates noise.
    """

    def __init__(self, domain):
        self.domain   = domain
        self.ip_data  = {}   # ip -> {sources, bgp, ipapi, cloud, rdns_domains, role}

    def add_ip(self, ip, sources, bgp=None, ipapi=None, rdns=None, cloud=None):
        if not is_valid_ip(ip) or is_private(ip):
            return
        self.ip_data[ip] = {
            "sources":      list(sources),
            "bgp":          bgp or {},
            "ipapi":        ipapi or {},
            "cloud":        cloud,
            "rdns_domains": rdns or [],
            "role":         self._classify_role(ip, sources, cloud, rdns or []),
        }

    def _classify_role(self, ip, sources, cloud, rdns_domains):
        s = set(sources)
        if is_cloudflare(ip) or cloud == "Cloudflare":
            return "CDN"
        if cloud in ("Fastly", "Akamai", "Imperva", "Sucuri"):
            return "CDN"
        if any("mx" in x for x in s):
            return "MAIL"
        if any("spf" in x for x in s):
            return "MAIL_INFRA"
        if len(rdns_domains) > 10:
            return "SHARED_HOST"
        sub_srcs = [x for x in s if x.startswith("sub:")]
        if sub_srcs:
            sub_name = sub_srcs[0].replace("sub:", "")
            for kw in ("api", "gateway", "rest", "graphql", "ws."):
                if kw in sub_name:
                    return "API"
        if cloud:
            return "CLOUD_HOSTED"
        return "ORIGIN"

    def get_summary(self):
        by_role = {}
        for ip, data in self.ip_data.items():
            role = data["role"]
            by_role.setdefault(role, []).append(ip)
        return by_role

    def origin_candidates(self):
        """Return IPs classified as ORIGIN or CLOUD_HOSTED, sorted by confidence."""
        cands = {
            ip: data for ip, data in self.ip_data.items()
            if data["role"] in ("ORIGIN", "CLOUD_HOSTED", "API")
        }
        return sorted(
            cands.items(),
            key=lambda x: confidence_score(x[1]["sources"]),
            reverse=True,
        )


# ══════════════════════════════════════════════════════════════
#  MAIN ANALYSIS
# ══════════════════════════════════════════════════════════════

def analyze(domain, verbose=False, output_file=None, skip_github=False):
    t0  = time.time()
    col = SubCollector(domain)
    all_ips   = {}    # ip -> set(sources)
    ip_enrich = {}    # ip -> {bgp, ipapi, cloud, rdns}

    def add_ip(ip, src):
        if not is_valid_ip(ip) or is_private(ip):
            return
        all_ips.setdefault(ip, set()).add(src)

    def pprint_ip(ip, src="", provider=None):
        tag   = ip_label(ip, provider)
        extra = f"  {C.DIM}← {src}{C.RESET}" if verbose and src else ""
        print(f"      {tag} {ip}{extra}")

    print(f"\n{C.BOLD}{C.CYAN}[TARGET]{C.RESET} {C.BOLD}{domain}{C.RESET}  "
          f"{C.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.DIM}{'═'*65}{C.RESET}")

    # ── 01. Current DNS A/AAAA
    print(f"\n{C.YELLOW}[01/16]{C.RESET} Mövcud DNS A/AAAA record-ları...")
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            pprint_ip(ip, "current-dns")
            add_ip(ip, "current-dns")
    except Exception as e:
        print(f"       {C.DIM}Xəta: {e}{C.RESET}")

    # ── 02. DNS MX / TXT / SPF / NS
    print(f"\n{C.YELLOW}[02/16]{C.RESET} DNS Records — MX / TXT / SPF / NS (DoH)...")
    dns_data = dns_records_analysis(domain)

    if dns_data["mx"]:
        print(f"        {C.CYAN}MX{C.RESET}: {', '.join(dns_data['mx'])}")
    for ip in dns_data["mx_ips"]:
        pprint_ip(ip, "mx-record")
        add_ip(ip, "mx-record")

    if dns_data["spf_ips"]:
        print(f"        {C.CYAN}SPF ip4{C.RESET}: {', '.join(dns_data['spf_ips'])}")
    for ip in dns_data["spf_ips"]:
        pprint_ip(ip, "spf-record")
        add_ip(ip, "spf-record")

    if verbose and dns_data["ns"]:
        print(f"        {C.DIM}NS: {', '.join(dns_data['ns'])}{C.RESET}")
    if verbose:
        for t in dns_data["txt"][:3]:
            print(f"        {C.DIM}TXT: {t[:90]}{C.RESET}")

    # ── 03. Zone Transfer
    print(f"\n{C.YELLOW}[03/16]{C.RESET} DNS Zone Transfer (AXFR) cəhdi...")
    zt = try_zone_transfer(domain, dns_data["ns"])
    if zt:
        print(f"        {C.GREEN}⚡ Zone Transfer uğurlu! {len(zt)} record{C.RESET}")
        for s in zt[:10]:
            col.add(s)
            print(f"        {C.GREEN}{s}{C.RESET}")
    else:
        print(f"        {C.DIM}Zone Transfer bloklanıb (normal){C.RESET}")

    # ── 04. crt.sh
    print(f"\n{C.YELLOW}[04/16]{C.RESET} crt.sh sertifikat şəffaflığı...")
    before = len(col.subs)
    src_crtsh(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain  (cəmi: {len(col.subs)})")

    # ── 05. CertSpotter
    print(f"\n{C.YELLOW}[05/16]{C.RESET} CertSpotter (SSLMate)...")
    before = len(col.subs)
    src_certspotter(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain")

    # ── 06. AlienVault OTX
    print(f"\n{C.YELLOW}[06/16]{C.RESET} AlienVault OTX passive DNS...")
    before  = len(col.subs)
    otx_ips = src_alienvault(domain, col)
    for ip in otx_ips:
        pprint_ip(ip, "alienvault-otx")
        add_ip(ip, "alienvault-otx")
    print(f"        {len(otx_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 07. HackerTarget
    print(f"\n{C.YELLOW}[07/16]{C.RESET} HackerTarget DNS history...")
    before  = len(col.subs)
    ht_ips  = src_hackertarget(domain, col)
    for ip in ht_ips:
        pprint_ip(ip, "hackertarget")
        add_ip(ip, "hackertarget")
    print(f"        {len(ht_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 08. URLScan.io
    print(f"\n{C.YELLOW}[08/16]{C.RESET} URLScan.io scan tarixçəsi...")
    before  = len(col.subs)
    us_ips  = src_urlscan(domain, col)
    for ip in us_ips:
        pprint_ip(ip, "urlscan.io")
        add_ip(ip, "urlscan.io")
    print(f"        {len(us_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 09. ThreatMiner + Anubis + Wayback
    print(f"\n{C.YELLOW}[09/16]{C.RESET} ThreatMiner / Anubis / Wayback Machine...")
    before = len(col.subs)
    t1 = src_threatminer(domain, col)
    t2 = src_anubis(domain, col)
    t3 = src_wayback(domain, col)
    print(f"        ThreatMiner:{t1}  Anubis:{t2}  Wayback:{t3}"
          f"  →  {len(col.subs)-before} yeni subdomain")

    # ── 10. RapidDNS + BufferOver
    print(f"\n{C.YELLOW}[10/16]{C.RESET} RapidDNS / BufferOver TLS...")
    before = len(col.subs)
    src_rapiddns(domain, col)
    src_bufferover(domain, col)
    print(f"        {len(col.subs)-before} yeni subdomain əlavə edildi")

    # ── 11. Subdomain Resolve
    passive_subs   = col.result()
    brute_list     = brute_subs(domain)
    all_to_resolve = sorted(set(passive_subs + brute_list))

    print(f"\n{C.YELLOW}[11/16]{C.RESET} Subdomain resolve (parallel 60 thread)...")
    print(f"        Passive:{len(passive_subs)}  Brute:{len(brute_list)}"
          f"  Cəmi unikal:{len(all_to_resolve)}")

    sub_resolved = resolve_all(all_to_resolve, workers=60)
    print(f"        {len(sub_resolved)} aktiv subdomain resolve olundu")

    non_cf_subs = []
    for sub, ips in sorted(sub_resolved.items()):
        for ip in ips:
            add_ip(ip, f"sub:{sub}")
            if not is_cloudflare(ip) and not is_private(ip):
                non_cf_subs.append((sub, ip))

    if non_cf_subs:
        seen = set()
        print(f"\n        {C.GREEN}{C.BOLD}⚡ CF-dən kənar subdomain IP-ləri:{C.RESET}")
        for sub, ip in non_cf_subs[:30]:
            if ip not in seen:
                print(f"          {C.GREEN}{ip:<20}{C.RESET} ← {sub}")
                seen.add(ip)
    else:
        print(f"        {C.DIM}Bütün aktiv subdomain-lər Cloudflare arxasındadır{C.RESET}")

    # ── 12. Shodan InternetDB
    print(f"\n{C.YELLOW}[12/16]{C.RESET} Shodan InternetDB (non-CF IP-lər)...")
    shodan_cache = {}
    real_list = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
    for ip in real_list[:15]:
        d = shodan_info(ip)
        if d:
            shodan_cache[ip] = d
            ports = d.get("ports", [])
            vulns = d.get("vulns", [])
            tags  = d.get("tags",  [])
            v_str = f"  {C.RED}CVE:{len(vulns)}{C.RESET}" if vulns else ""
            print(f"      {C.CYAN}{ip:<20}{C.RESET} ports:{ports}  tags:{tags}{v_str}")
            add_ip(ip, "shodan-idb")

    # ─────────────────────────────────────────────────────────
    #  NEW PHASE 13: TLS DEEP ANALYSIS
    # ─────────────────────────────────────────────────────────
    print(f"\n{C.YELLOW}[13/16]{C.RESET} TLS Deep Analysis — sertifikat + SAN + cipher...")
    tls_result = tls_analyze(domain)
    tls_sans   = []

    if tls_result.get("error"):
        print(f"        {C.DIM}TLS xəta: {tls_result['error']}{C.RESET}")
    else:
        print(f"        CN: {C.CYAN}{tls_result['cn']}{C.RESET}  "
              f"Issuer: {tls_result['issuer']}")
        print(f"        Version: {tls_result['version']}  Cipher: {tls_result['cipher']}")
        if tls_result["weak"]:
            print(f"        {C.RED}⚠  ZƏYF TLS konfiqurasiyası aşkarlandı!{C.RESET}")
        if tls_result["not_after"]:
            print(f"        Expire: {C.DIM}{tls_result['not_after']}{C.RESET}")

        tls_sans = list(set(tls_result["sans"]))
        if tls_sans:
            print(f"        SANs ({len(tls_sans)}): "
                  f"{C.DIM}{', '.join(tls_sans[:8])}{C.RESET}")
            # Resolve SANs → IPs
            san_pairs = tls_san_to_ips(tls_sans, domain)
            new_from_san = 0
            for san, ip in san_pairs:
                if not is_cloudflare(ip):
                    add_ip(ip, "tls-san")
                    new_from_san += 1
                    if verbose:
                        print(f"        {C.GREEN}SAN IP: {ip}{C.RESET} ← {san}")
            if new_from_san:
                print(f"        {C.GREEN}{new_from_san} yeni non-CF IP TLS SAN-dan{C.RESET}")

    # ─────────────────────────────────────────────────────────
    #  NEW PHASE 14: TECHNOLOGY + JS ENDPOINTS + FAVICON
    # ─────────────────────────────────────────────────────────
    print(f"\n{C.YELLOW}[14/16]{C.RESET} Technology Detection + JS Endpoint Scan + Favicon...")
    tech_found    = {}
    js_endpoints  = []
    fav_info      = {}

    html_body, resp_headers = http_get_with_headers(f"https://{domain}", timeout=15)
    if not html_body:
        html_body, resp_headers = http_get_with_headers(f"http://{domain}", timeout=15)

    if html_body:
        tech_found = detect_technology(html_body, resp_headers)
        if tech_found:
            tech_names = ", ".join(tech_found.keys())
            print(f"        {C.CYAN}Tech stack:{C.RESET} {tech_names}")
        else:
            print(f"        {C.DIM}Tech fingerprint: müəyyən edilmədi{C.RESET}")

        js_endpoints = extract_js_endpoints(f"https://{domain}", html_body)
        if js_endpoints:
            print(f"        {C.CYAN}JS Endpoints ({len(js_endpoints)}):{C.RESET} "
                  f"{C.DIM}{', '.join(js_endpoints[:5])}{C.RESET}")
        else:
            print(f"        {C.DIM}JS endpoint tapılmadı{C.RESET}")
    else:
        print(f"        {C.DIM}HTTP əlçatımsız — skip{C.RESET}")

    fav_info = favicon_hash(domain)
    if fav_info:
        print(f"        {C.CYAN}Favicon:{C.RESET} mmh3={fav_info['mmh3']}  "
              f"size={fav_info['size']}B  "
              f"{C.DIM}{fav_info['shodan_query']}{C.RESET}")
    else:
        print(f"        {C.DIM}Favicon tapılmadı{C.RESET}")

    # ─────────────────────────────────────────────────────────
    #  NEW PHASE 15: BGP/ASN + CLOUD + REVERSE IP ENRICHMENT
    # ─────────────────────────────────────────────────────────
    print(f"\n{C.YELLOW}[15/16]{C.RESET} BGP/ASN + Cloud Classify + Reverse IP (non-CF)...")
    real_ips = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]

    for ip in real_ips[:12]:
        bgp   = bgpview_lookup(ip)
        iapi  = ipapi_info(ip)
        asn   = bgp.get("asn", "")
        org   = bgp.get("asn_name", "") or iapi.get("org", "")
        cloud = classify_cloud(asn, org)
        rdns  = reverse_ip_lookup(ip)

        ip_enrich[ip] = {
            "bgp":   bgp,
            "ipapi": iapi,
            "cloud": cloud,
            "rdns":  rdns,
        }

        cloud_tag = f"  {C.YELLOW}[{cloud}]{C.RESET}" if cloud else ""
        rdns_tag  = f"  {C.DIM}shared:{len(rdns)} domains{C.RESET}" if rdns else ""
        hosting   = f"  {C.MAGENTA}[HOSTING]{C.RESET}" if iapi.get("hosting") else ""
        proxy_tag = f"  {C.RED}[PROXY]{C.RESET}" if iapi.get("proxy") else ""

        print(f"      {C.CYAN}{ip:<20}{C.RESET} "
              f"AS={asn} {C.DIM}{org[:30]}{C.RESET}"
              f"{cloud_tag}{rdns_tag}{hosting}{proxy_tag}")

        if rdns and verbose:
            for d in rdns[:5]:
                print(f"         {C.DIM}↳ {d}{C.RESET}")

    # ─────────────────────────────────────────────────────────
    #  NEW PHASE 16: GITHUB LEAK DETECTION
    # ─────────────────────────────────────────────────────────
    leak_findings = []
    if not skip_github:
        print(f"\n{C.YELLOW}[16/16]{C.RESET} GitHub Leak Detection (safe mode)...")
        leak_findings = github_leak_scan(domain)
        if leak_findings:
            print(f"        {C.RED}⚠  {len(leak_findings)} potensial sızıntı tapıldı:{C.RESET}")
            for lf in leak_findings[:5]:
                print(f"        {C.RED}▶{C.RESET} {lf['repo']} — {lf['file']}")
                print(f"          {C.DIM}{lf['url']}{C.RESET}")
                add_ip("github-leak", lf["repo"])   # track as metadata only
        else:
            print(f"        {C.GREEN}Açıq sızıntı əlaməti tapılmadı{C.RESET}")
    else:
        print(f"\n{C.YELLOW}[16/16]{C.RESET} GitHub Leak Detection — {C.DIM}skip (--no-github){C.RESET}")

    # ══════════════════════════════════════════════════════════
    #  CORRELATION ENGINE — classify + deduplicate
    # ══════════════════════════════════════════════════════════
    engine = CorrelationEngine(domain)
    for ip, srcs in all_ips.items():
        if is_private(ip):
            continue
        enrich = ip_enrich.get(ip, {})
        engine.add_ip(
            ip, srcs,
            bgp   = enrich.get("bgp"),
            ipapi = enrich.get("ipapi"),
            rdns  = enrich.get("rdns"),
            cloud = enrich.get("cloud"),
        )

    # ──────────────────────────────────────────────
    #  NƏTİCƏ
    # ──────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*65}")
    print(f"  ✦  NƏTİCƏ — {domain}  ({elapsed:.1f}s)")
    print(f"{'═'*65}{C.RESET}")

    # Infrastructure role breakdown
    role_summary = engine.get_summary()
    if verbose:
        print(f"\n  {C.CYAN}Infrastructure Breakdown:{C.RESET}")
        for role, ips in role_summary.items():
            print(f"    {C.DIM}{role:<14}{C.RESET} {', '.join(ips[:4])}")

    real_cands  = engine.origin_candidates()
    cf_ips_list = [ip for ip in all_ips if is_cloudflare(ip)]

    if real_cands:
        print(f"\n{C.GREEN}{C.BOLD}  ⚡ Potensial REAL IP-lər ({len(real_cands)}):{C.RESET}")
        for ip, data in real_cands[:20]:
            sources = data["sources"]
            info    = ip_info(ip)
            bgp     = data.get("bgp") or {}
            iapi    = data.get("ipapi") or {}
            cloud   = data.get("cloud")
            rdns    = data.get("rdns_domains") or []
            sd      = shodan_cache.get(ip, {})
            ports   = sd.get("ports", [])
            vulns   = sd.get("vulns", [])
            conf    = confidence_score(sources)
            xval    = cross_validated(sources)
            bar     = "█" * min(conf, 10)
            bcol    = C.GREEN if conf >= 5 else C.YELLOW if conf >= 2 else C.DIM
            xval_str = f" {C.GREEN}✓ CROSS-VALIDATED{C.RESET}" if xval else \
                       f" {C.YELLOW}⚠ single source{C.RESET}"

            tier_flags = []
            for src in set(sources):
                tier, _ = source_trust(src)
                if tier == "DIRECT":
                    tier_flags.append(f"{C.GREEN}DIRECT{C.RESET}")
                    break

            print(f"\n  {C.GREEN}{C.BOLD}▶ {ip}{C.RESET}{xval_str}")
            print(f"    {C.DIM}Role    :{C.RESET} {data['role']}")
            asn_str = bgp.get("asn", info["org"])
            print(f"    {C.DIM}ASN     :{C.RESET} {asn_str} | {info['city']}, {info['country']}")
            if cloud:
                print(f"    {C.DIM}Cloud   :{C.RESET} {C.YELLOW}{cloud}{C.RESET}")
            if info["hostname"]:
                print(f"    {C.DIM}rDNS    :{C.RESET} {info['hostname']}")
            if iapi.get("hosting"):
                print(f"    {C.DIM}Hosting :{C.RESET} {C.MAGENTA}Datacenter/VPS{C.RESET}")
            if bgp.get("prefix"):
                print(f"    {C.DIM}Prefix  :{C.RESET} {bgp['prefix']} ({bgp.get('rir','')})")
            if rdns:
                print(f"    {C.DIM}Rev-IP  :{C.RESET} {len(rdns)} co-hosted domain(s)")
            print(f"    {C.DIM}Mənbələr:{C.RESET} {', '.join(list(set(sources))[:6])}")
            if ports:
                print(f"    {C.DIM}Portlar :{C.RESET} {ports}")
            if vulns:
                print(f"    {C.RED}CVE     :{C.RESET} {list(vulns)[:5]}")
            print(f"    {C.DIM}Güvən   :{C.RESET} {bcol}{bar}{C.RESET} ({conf} xal)")
    else:
        print(f"\n{C.YELLOW}  ⚠  Real IP tapılmadı.{C.RESET}")
        print(f"  {C.DIM}Sistem düzgün qurulub — ya da heç vaxt ifşa olunmayıb.{C.RESET}")

    # Tech summary
    if tech_found:
        print(f"\n  {C.CYAN}Tech Stack:{C.RESET} {', '.join(tech_found.keys())}")

    # Favicon hint
    if fav_info:
        print(f"  {C.CYAN}Favicon Hash:{C.RESET} {fav_info['mmh3']}"
              f"  {C.DIM}(Shodan: {fav_info['shodan_query']}){C.RESET}")

    # Leak hint
    if leak_findings:
        print(f"  {C.RED}GitHub Leaks:{C.RESET} {len(leak_findings)} repo(s) tapıldı")

    print(f"\n  {C.DIM}Cloudflare IP-ləri: {', '.join(cf_ips_list[:6])}{C.RESET}")
    print(f"  {C.DIM}Subdomain: {len(sub_resolved)} aktiv / {len(all_to_resolve)} yoxlanıldı{C.RESET}")
    print(f"  {C.DIM}TLS SANs: {len(tls_sans)}{C.RESET}")
    print(f"  {C.DIM}JS Endpoints: {len(js_endpoints)}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'═'*65}{C.RESET}\n")

    # ── Build result dict
    result = {
        "domain":      domain,
        "scan_time":   datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 2),
        "real_candidates": {
            ip: {
                "sources":          list(data["sources"]),
                "confidence":       confidence_score(data["sources"]),
                "cross_validated":  cross_validated(data["sources"]),
                "role":             data["role"],
                "cloud_provider":   data.get("cloud"),
                "bgp":              data.get("bgp") or {},
                "shodan":           shodan_cache.get(ip, {}),
                "rdns_count":       len(data.get("rdns_domains") or []),
            }
            for ip, data in real_cands
        },
        "cloudflare_ips":     cf_ips_list,
        "infrastructure_map": role_summary,
        "subdomains": {
            "total_checked": len(all_to_resolve),
            "active":        len(sub_resolved),
            "non_cf":        [{"sub": s, "ip": ip} for s, ip in non_cf_subs[:100]],
        },
        "dns_records": {
            "mx":      dns_data["mx"],
            "spf_ips": dns_data["spf_ips"],
            "ns":      dns_data["ns"],
        },
        "tls": {
            "cn":         tls_result.get("cn", ""),
            "issuer":     tls_result.get("issuer", ""),
            "sans_count": len(tls_sans),
            "sans":       tls_sans[:20],
            "version":    tls_result.get("version", ""),
            "cipher":     tls_result.get("cipher", ""),
            "weak":       tls_result.get("weak", False),
        },
        "technology":    list(tech_found.keys()),
        "js_endpoints":  js_endpoints[:20],
        "favicon":       fav_info,
        "github_leaks":  [
            {"repo": lf["repo"], "file": lf["file"], "url": lf["url"]}
            for lf in leak_findings
        ],
    }

    if output_file:
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"{C.GREEN}[+] Nəticə saxlandı: {output_file}{C.RESET}\n")

    return result


# ──────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────
def main():
    banner()
    ap = argparse.ArgumentParser(
        description="CF-Hunter v4: Advanced Cloudflare Real IP Intelligence",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("domain",
        help="Hədəf domain  (məs: example.com  ya da  https://example.com/path)")
    ap.add_argument("-o", "--output",
        help="Nəticəni JSON faylına yaz  (məs: -o result.json)")
    ap.add_argument("-v", "--verbose",
        action="store_true",
        help="Ətraflı çıxış (BGP, reverse-IP domains, TXT record-lar)")
    ap.add_argument("--no-github",
        action="store_true",
        help="GitHub leak detection-u atla")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split("/")[0].split("?")[0]

    if not re.match(r'^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$', domain):
        print(f"{C.RED}[!] Yanlış domain formatı: {domain}{C.RESET}")
        sys.exit(1)

    analyze(
        domain,
        verbose=args.verbose,
        output_file=args.output,
        skip_github=args.no_github,
    )


if __name__ == "__main__":
    main()
