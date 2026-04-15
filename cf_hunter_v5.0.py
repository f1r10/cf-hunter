#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         CF-HUNTER v5.0 @f1r10 — Advanced Cloudflare IP Intelligence     ║
║  Verify Engine · Header/SNI Probe · Response Fingerprint · Risk Scoring ║
║  BGP/ASN · TLS/SAN · Tech Detect · JS Scan · Favicon · Leak Detect      ║
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
from urllib.parse import quote, urlparse
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
{C.RESET}{C.DIM}  Cloudflare Real IP Intelligence v5.0 @f1r10
  Verify Engine | Fingerprint Diff | Smart Scoring | Correlation | JSON Export{C.RESET}
""")


# ──────────────────────────────────────────────────────────────
#  Source reliability
# ──────────────────────────────────────────────────────────────
SOURCE_TRUST = {
    "current-dns":   ("DIRECT", 3),
    "mx-record":     ("DIRECT", 2),
    "spf-record":    ("DIRECT", 1),
    "zone-transfer": ("DIRECT", 3),
    "tls-san":       ("DIRECT", 3),
    "http-verify":   ("DIRECT", 4),
    "https-verify":  ("DIRECT", 4),
    "sni-verify":    ("DIRECT", 5),
    "content-match": ("DIRECT", 5),
    "urlscan.io":    ("VERIFIED_API", 2),
    "alienvault-otx":("VERIFIED_API", 2),
    "shodan-idb":    ("VERIFIED_API", 2),
    "bgpview":       ("VERIFIED_API", 2),
    "ipinfo":        ("VERIFIED_API", 2),
    "crtsh":         ("VERIFIED_API", 2),
    "certspotter":   ("VERIFIED_API", 2),
    "hackertarget":  ("VERIFIED_API", 2),
    "github-leak":   ("VERIFIED_API", 2),
    "rapiddns":      ("SCRAPED", 1),
    "bufferover":    ("SCRAPED", 1),
    "wayback":       ("SCRAPED", 1),
    "threatminer":   ("SCRAPED", 1),
    "anubis":        ("SCRAPED", 1),
    "reverse-ip":    ("SCRAPED", 1),
    "favicon-match": ("SCRAPED", 1),
}


def source_trust(src):
    if src.startswith("sub:"):
        return ("DIRECT", 2)
    for key, val in SOURCE_TRUST.items():
        if key in src:
            return val
    return ("SCRAPED", 1)


# ──────────────────────────────────────────────────────────────
#  Cloudflare CIDR + provider fingerprints
# ──────────────────────────────────────────────────────────────
CF_RANGES = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
    "2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32",
    "2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
]
CF_NETS = [ipaddress.ip_network(x, strict=False) for x in CF_RANGES]

CLOUD_ASN_MAP = {
    "AS16509": "AWS", "AS14618": "AWS", "AS8987": "AWS",
    "AS15169": "GCP", "AS396982": "GCP", "AS19527": "GCP",
    "AS8075": "Azure", "AS8069": "Azure",
    "AS13335": "Cloudflare", "AS209242": "Cloudflare",
    "AS54113": "Fastly",
    "AS20940": "Akamai", "AS16625": "Akamai",
    "AS14061": "DigitalOcean",
    "AS20473": "Vultr",
    "AS63949": "Linode",
    "AS16276": "OVH",
    "AS24940": "Hetzner",
    "AS19551": "Imperva",
    "AS30148": "Sucuri",
    "AS40934": "Fortinet",
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
    "fortinet": "Fortinet",
}

EDGE_PROVIDERS = {"Cloudflare", "Fastly", "Akamai", "Imperva", "Sucuri", "Fortinet"}


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
    asn_key = asn.split()[0].upper() if asn else ""
    if asn_key in CLOUD_ASN_MAP:
        return CLOUD_ASN_MAP[asn_key]
    org_lower = (org or "").lower()
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
#  HTTP helpers
# ──────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CF-Hunter/5.0",
    "Accept": "application/json, text/html, */*",
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
                time.sleep(1.0)
    return None


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
            return None
    return None


def http_get_with_headers(url, timeout=14):
    try:
        req = Request(url, headers=_HEADERS)
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            body = r.read().decode("utf-8", errors="replace")
            return body, dict(r.headers), getattr(r, "status", 200)
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return body, dict(e.headers or {}), e.code
    except Exception:
        return None, {}, None


# ──────────────────────────────────────────────────────────────
#  Low-level verifier engine
# ──────────────────────────────────────────────────────────────
def recv_all(sock, cap=65536):
    sock.settimeout(5)
    chunks = []
    total = 0
    while total < cap:
        try:
            data = sock.recv(min(4096, cap - total))
        except socket.timeout:
            break
        except Exception:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def http_probe_ip(ip, host, scheme="http", port=None, path="/"):
    result = {
        "scheme": scheme,
        "ip": ip,
        "host": host,
        "ok": False,
        "status": None,
        "server": "",
        "location": "",
        "title": "",
        "body_hash": "",
        "headers": {},
        "sample": "",
        "error": "",
        "cf_like": False,
        "squid_like": False,
    }
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        p = port or (443 if scheme == "https" else 80)
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(6)
        sock.connect((ip, p))
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_HEADERS['User-Agent']}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)
        raw = recv_all(sock)
        sock.close()
        if not raw:
            result["error"] = "empty response"
            return result

        text = raw.decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if lines:
            m = re.search(r"HTTP/\d\.\d\s+(\d+)", lines[0])
            if m:
                result["status"] = int(m.group(1))
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        result["headers"] = headers
        result["server"] = headers.get("server", "")
        result["location"] = headers.get("location", "")
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        result["title"] = title_m.group(1).strip()[:200] if title_m else ""
        result["sample"] = re.sub(r"\s+", " ", body[:500]).strip()
        result["body_hash"] = hashlib.sha256(body[:8192].encode("utf-8", errors="ignore")).hexdigest()[:16]

        server_l = result["server"].lower()
        body_l = body.lower()
        result["cf_like"] = (
            "cloudflare" in server_l or
            "cf-ray" in headers or
            "attention required" in body_l or
            "checking your browser" in body_l
        )
        result["squid_like"] = (
            "squid" in server_l or
            "generated by" in body_l and "squid" in body_l or
            "invalid url" in body_l and "cache administrator" in body_l
        )
        result["ok"] = True
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def normalize_headers(headers):
    bad = {"date", "set-cookie", "cf-ray", "report-to", "nel", "alt-svc", "content-length"}
    return {k.lower(): v for k, v in headers.items() if k.lower() not in bad}


def fingerprint_response(probe):
    if not probe or not probe.get("ok"):
        return {"status": None, "server": "", "title": "", "body_hash": "", "header_keys": []}
    hdrs = normalize_headers(probe.get("headers", {}))
    return {
        "status": probe.get("status"),
        "server": probe.get("server", "")[:80],
        "title": probe.get("title", "")[:120],
        "body_hash": probe.get("body_hash", ""),
        "header_keys": sorted(list(hdrs.keys()))[:20],
    }


def compare_fingerprints(a, b):
    score = 0
    reasons = []
    if not a or not b:
        return 0, reasons
    if a.get("status") and b.get("status") and a["status"] == b["status"]:
        score += 2
        reasons.append("status match")
    if a.get("title") and b.get("title") and a["title"] == b["title"]:
        score += 4
        reasons.append("title match")
    if a.get("body_hash") and b.get("body_hash") and a["body_hash"] == b["body_hash"]:
        score += 6
        reasons.append("body hash match")
    ak = set(a.get("header_keys", []))
    bk = set(b.get("header_keys", []))
    if ak and bk:
        inter = len(ak & bk)
        if inter >= 5:
            score += 3
            reasons.append(f"header overlap {inter}")
        elif inter >= 2:
            score += 1
            reasons.append(f"header overlap {inter}")
    return score, reasons


def verify_candidate(ip, domain, baseline_http=None, baseline_https=None):
    http_r = http_probe_ip(ip, domain, scheme="http")
    https_r = http_probe_ip(ip, domain, scheme="https")

    verdict = {
        "ip": ip,
        "http": fingerprint_response(http_r),
        "https": fingerprint_response(https_r),
        "raw_http": http_r,
        "raw_https": https_r,
        "score": 0,
        "confidence_label": "LOW",
        "verdict": "UNCONFIRMED",
        "reasons": [],
    }

    if http_r.get("ok") and http_r.get("status"):
        verdict["score"] += 2
        verdict["reasons"].append(f"http:{http_r['status']}")
    if https_r.get("ok") and https_r.get("status"):
        verdict["score"] += 3
        verdict["reasons"].append(f"https:{https_r['status']}")

    if http_r.get("cf_like") or https_r.get("cf_like"):
        verdict["score"] -= 8
        verdict["reasons"].append("cloudflare-like response")
    if http_r.get("squid_like") or https_r.get("squid_like"):
        verdict["score"] -= 6
        verdict["reasons"].append("squid/proxy response")

    s1, r1 = compare_fingerprints(baseline_http or {}, verdict["http"])
    s2, r2 = compare_fingerprints(baseline_https or {}, verdict["https"])
    if s1 > 0:
        verdict["score"] += s1
        verdict["reasons"].append("http baseline match")
        verdict["reasons"].extend(r1)
    if s2 > 0:
        verdict["score"] += s2
        verdict["reasons"].append("https baseline match")
        verdict["reasons"].extend(r2)

    if verdict["https"].get("body_hash") and baseline_https and verdict["https"]["body_hash"] == baseline_https.get("body_hash"):
        verdict["verdict"] = "LIKELY_ORIGIN"
    elif verdict["score"] >= 8:
        verdict["verdict"] = "LIKELY_ORIGIN"
    elif verdict["score"] >= 3:
        verdict["verdict"] = "POSSIBLE"
    else:
        verdict["verdict"] = "EDGE_OR_PROXY"

    if verdict["score"] >= 10:
        verdict["confidence_label"] = "HIGH"
    elif verdict["score"] >= 5:
        verdict["confidence_label"] = "MEDIUM"
    else:
        verdict["confidence_label"] = "LOW"
    return verdict


# ──────────────────────────────────────────────────────────────
#  Collectors / enrichers
# ──────────────────────────────────────────────────────────────
class SubCollector:
    def __init__(self, domain):
        self.domain = domain
        self.subs = set()

    def add(self, raw):
        s = raw.strip().lower().lstrip("*.")
        if s.endswith(f".{self.domain}") and s != self.domain:
            self.subs.add(s)

    def result(self):
        return sorted(self.subs)


def src_crtsh(domain, col):
    for url in [f"https://crt.sh/?q=%.{domain}&output=json", f"https://crt.sh/?q={domain}&output=json"]:
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
        f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
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
    d = http_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12)
    if d:
        for e in d.get("passive_dns", []):
            a = e.get("address", "")
            if is_valid_ip(a) and a not in ips:
                ips.append(a)
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
    data = http_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=15)
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
    data = http_json(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=12)
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
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    data = http_json(url, timeout=20)
    n = 0
    if data and len(data) > 1:
        pat = re.compile(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')')
        for row in data[1:]:
            if row:
                m = pat.search(row[0])
                if m:
                    col.add(m.group(1))
                    n += 1
    return n


def bgpview_lookup(ip):
    d = http_json(f"https://api.bgpview.io/ip/{ip}", timeout=10)
    if not d or d.get("status") != "ok":
        return {}
    data = d.get("data", {})
    result = {"asn": "", "asn_name": "", "prefix": "", "rir": "", "country": ""}
    prefixes = data.get("prefixes", [])
    if prefixes:
        p = prefixes[0]
        asn_info = p.get("asn", {})
        result["asn"] = f"AS{asn_info.get('asn', '')}"
        result["asn_name"] = asn_info.get("name", "")
        result["prefix"] = p.get("prefix", "")
        result["rir"] = p.get("rir_allocation", {}).get("rir_name", "")
        result["country"] = p.get("country_codes", {}).get("whois_country_code", "")
    return result


def ipapi_info(ip):
    d = http_json(f"http://ip-api.com/json/{ip}?fields=status,org,isp,country,city,hosting,proxy,mobile", timeout=8)
    if d and d.get("status") == "success":
        return {
            "org": d.get("org", ""),
            "isp": d.get("isp", ""),
            "country": d.get("country", ""),
            "city": d.get("city", ""),
            "hosting": d.get("hosting", False),
            "proxy": d.get("proxy", False),
            "mobile": d.get("mobile", False),
        }
    return {}


def ip_info(ip):
    d = http_json(f"https://ipinfo.io/{ip}/json", timeout=8)
    if d:
        return {"org": d.get("org", "?"), "city": d.get("city", "?"), "country": d.get("country", "?"), "hostname": d.get("hostname", "")}
    return {"org": "?", "city": "?", "country": "?", "hostname": ""}


def reverse_ip_lookup(ip):
    raw = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12)
    if not raw or "error" in raw.lower() or "API count" in raw:
        return []
    return [d.strip() for d in raw.strip().split("\n") if d.strip()][:50]


def tls_analyze(hostname, port=443, timeout=8):
    result = {"cn": "", "sans": [], "issuer": "", "not_after": "", "cipher": "", "version": "", "weak": False, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["version"] = ssock.version() or ""
                result["cipher"] = cipher[0] if cipher else ""
                for field in cert.get("subject", []):
                    for k, v in field:
                        if k == "commonName":
                            result["cn"] = v
                for field in cert.get("issuer", []):
                    for k, v in field:
                        if k == "organizationName":
                            result["issuer"] = v
                for entry in cert.get("subjectAltName", []):
                    if entry[0] == "DNS":
                        result["sans"].append(entry[1].lstrip("*."))
                result["not_after"] = cert.get("notAfter", "")
                if result["version"] in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
                    result["weak"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def tls_san_to_ips(sans, domain):
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


TECH_PATTERNS = {
    "Apache": [r'Server:\s*Apache', r'<address>Apache'],
    "Nginx": [r'Server:\s*nginx'],
    "LiteSpeed": [r'Server:\s*LiteSpeed'],
    "IIS": [r'Server:\s*Microsoft-IIS'],
    "PHP": [r'X-Powered-By:\s*PHP', r'\.php\b', r'PHPSESSID'],
    "ASP.NET": [r'X-Powered-By:\s*ASP\.NET', r'__VIEWSTATE', r'\.aspx\b'],
    "Django": [r'csrfmiddlewaretoken'],
    "Laravel": [r'laravel_session', r'XSRF-TOKEN'],
    "WordPress": [r'/wp-content/', r'/wp-includes/', r'wp-login\.php'],
    "React": [r'__reactFiber', r'_reactRootContainer', r'react-app'],
    "Next.js": [r'__NEXT_DATA__', r'/_next/static/'],
    "Vue.js": [r'__vue__', r'data-v-'],
    "Angular": [r'ng-version', r'ng-app', r'angular\.js'],
    "Cloudflare": [r'CF-Ray:', r'cf-cache-status'],
    "Varnish": [r'X-Varnish:', r'Via:.*varnish'],
    "Fastly": [r'X-Served-By:.*cache', r'Fastly-Restarts:'],
    "reCAPTCHA": [r'google\.com/recaptcha', r'g-recaptcha'],
}


def detect_technology(body="", headers=None):
    headers = headers or {}
    found = {}
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    combined = header_str + "\n" + (body or "")
    for tech, patterns in TECH_PATTERNS.items():
        hits = []
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                hits.append(pat)
        if hits:
            found[tech] = hits
    return found


_JS_ENDPOINT_RE = re.compile(r"""(?:['\"`])((?:/[a-zA-Z0-9_\-./]+){1,5}(?:\?[^'\"`\s]*)?)(?:['\"`])""", re.VERBOSE)
_JS_URL_RE = re.compile(r"""(?:url|endpoint|api|href|action)\s*[:=]\s*['\"`]([^'\"`\s]{5,100})['\"`]""", re.IGNORECASE)


def extract_js_endpoints(base_url, html, max_scripts=5):
    endpoints = set()
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
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
    return sorted([ep for ep in endpoints if any(kw in ep.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/auth/", "/admin", "/config"])])[:50]


import base64 as _b64


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h = seed
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
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h - 2**32 if h >= 2**31 else h


def favicon_hash(domain):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/favicon.ico"
        data = http_get_bytes(url, timeout=8)
        if data and len(data) > 10:
            b64 = _b64.encodebytes(data).decode()
            mmh = _murmur3_32(b64.encode())
            md5 = hashlib.md5(data).hexdigest()
            return {"url": url, "size": len(data), "mmh3": mmh, "md5": md5, "shodan_query": f"http.favicon.hash:{mmh}"}
    return {}


GITHUB_SAFE_QUERIES = [
    "{domain}", "{domain} password", "{domain} config", "{domain} api_key"
]


def github_leak_scan(domain):
    findings = []
    seen_repos = set()
    for q_template in GITHUB_SAFE_QUERIES:
        q = quote(q_template.format(domain=domain))
        url = f"https://api.github.com/search/code?q={q}&per_page=10"
        data = http_json(url, timeout=12)
        if not data or "items" not in data:
            break
        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            fname = item.get("name", "")
            furl = item.get("html_url", "")
            if repo and repo not in seen_repos:
                seen_repos.add(repo)
                findings.append({"repo": repo, "file": fname, "url": furl, "query": q_template.format(domain=domain)})
        time.sleep(1.0)
    return findings


def doh_query(name, rtype):
    data = http_json(f"https://dns.google/resolve?name={quote(name)}&type={rtype}", timeout=10)
    return data.get("Answer", []) if data else []


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
                    ip = str(net.network_address)
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


WORDLIST = [
    "www","www2","www3","web","mail","smtp","mx","webmail","admin","panel","cpanel","whm","plesk",
    "dev","staging","stage","test","beta","api","api2","api-v1","api-v2","rest","graphql","gateway",
    "cdn","static","assets","img","media","upload","downloads","storage","db","redis","mongo","elastic",
    "secure","auth","sso","app","mobile","m","monitor","status","metrics","forum","blog","shop","pay",
    "support","help","wiki","ftp","sftp","ssh","backup","prod","production","common"
]


def brute_subs(domain):
    return sorted(set(f"{w}.{domain}" for w in WORDLIST))


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


def shodan_info(ip):
    d = http_json(f"https://internetdb.shodan.io/{ip}", timeout=8)
    if d and "detail" not in str(d).lower():
        return d
    return None


# ──────────────────────────────────────────────────────────────
#  Scoring and correlation
# ──────────────────────────────────────────────────────────────
def confidence_score(sources, cloud=None, verify=None, rdns_count=0):
    s = set(sources)
    total = 0
    direct = 0
    verified = 0
    for src in s:
        tier, weight = source_trust(src)
        total += weight
        if tier == "DIRECT":
            direct += 1
        elif tier == "VERIFIED_API":
            verified += 1
    if any("sub:" in x for x in s):
        total += 1
    if direct >= 2:
        total += 3
    elif direct >= 1 and verified >= 1:
        total += 2
    if verify:
        total += verify.get("score", 0)
    if cloud in EDGE_PROVIDERS:
        total -= 8
    elif cloud in {"AWS", "GCP", "Azure"}:
        total -= 1
    if rdns_count >= 20:
        total -= 4
    elif rdns_count >= 8:
        total -= 2
    return total


def cross_validated(sources, verify=None):
    s = set(sources)
    direct = sum(1 for src in s if source_trust(src)[0] == "DIRECT")
    if verify and verify.get("verdict") == "LIKELY_ORIGIN":
        return True
    return direct >= 1 or len(s) >= 2


class CorrelationEngine:
    def __init__(self, domain):
        self.domain = domain
        self.ip_data = {}

    def add_ip(self, ip, sources, bgp=None, ipapi=None, rdns=None, cloud=None, verify=None):
        if not is_valid_ip(ip) or is_private(ip):
            return
        self.ip_data[ip] = {
            "sources": list(sources),
            "bgp": bgp or {},
            "ipapi": ipapi or {},
            "cloud": cloud,
            "rdns_domains": rdns or [],
            "verify": verify or {},
            "role": self._classify_role(ip, sources, cloud, rdns or [], verify or {}),
        }

    def _classify_role(self, ip, sources, cloud, rdns_domains, verify):
        s = set(sources)
        if is_cloudflare(ip) or cloud == "Cloudflare":
            return "CDN"
        if cloud in EDGE_PROVIDERS:
            return "EDGE"
        if verify and verify.get("verdict") == "LIKELY_ORIGIN":
            return "ORIGIN"
        if any("mx" in x for x in s):
            return "MAIL"
        if any("spf" in x for x in s):
            return "MAIL_INFRA"
        if len(rdns_domains) > 10:
            return "SHARED_HOST"
        sub_srcs = [x for x in s if x.startswith("sub:")]
        if sub_srcs:
            sub_name = sub_srcs[0].replace("sub:", "")
            if any(kw in sub_name for kw in ("api", "gateway", "rest", "graphql", "ws.")):
                return "API"
        if cloud:
            return "CLOUD_HOSTED"
        return "ORIGIN_CANDIDATE"

    def get_summary(self):
        by_role = {}
        for ip, data in self.ip_data.items():
            role = data["role"]
            by_role.setdefault(role, []).append(ip)
        return by_role

    def origin_candidates(self):
        cands = {
            ip: data for ip, data in self.ip_data.items()
            if data["role"] in ("ORIGIN", "ORIGIN_CANDIDATE", "CLOUD_HOSTED", "API")
        }
        return sorted(
            cands.items(),
            key=lambda x: confidence_score(x[1]["sources"], cloud=x[1].get("cloud"), verify=x[1].get("verify"), rdns_count=len(x[1].get("rdns_domains") or [])),
            reverse=True,
        )


# ──────────────────────────────────────────────────────────────
#  Main analysis
# ──────────────────────────────────────────────────────────────
def analyze(domain, verbose=False, output_file=None, skip_github=False, skip_verify=False, workers=10):
    t0 = time.time()
    col = SubCollector(domain)
    all_ips = {}
    ip_enrich = {}
    verify_results = {}

    def add_ip(ip, src):
        if not is_valid_ip(ip) or is_private(ip):
            return
        all_ips.setdefault(ip, set()).add(src)

    def pprint_ip(ip, src="", provider=None):
        tag = ip_label(ip, provider)
        extra = f"  {C.DIM}← {src}{C.RESET}" if verbose and src else ""
        print(f"      {tag} {ip}{extra}")

    print(f"\n{C.BOLD}{C.CYAN}[TARGET]{C.RESET} {C.BOLD}{domain}{C.RESET}  {C.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.DIM}{'═'*70}{C.RESET}")

    print(f"\n{C.YELLOW}[01/18]{C.RESET} Mövcud DNS A/AAAA record-ları...")
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            pprint_ip(ip, "current-dns")
            add_ip(ip, "current-dns")
    except Exception as e:
        print(f"       {C.DIM}Xəta: {e}{C.RESET}")

    print(f"\n{C.YELLOW}[02/18]{C.RESET} DNS Records — MX / TXT / SPF / NS (DoH)...")
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

    print(f"\n{C.YELLOW}[03/18]{C.RESET} DNS Zone Transfer (AXFR) cəhdi...")
    zt = try_zone_transfer(domain, dns_data["ns"])
    if zt:
        print(f"        {C.GREEN}⚡ Zone Transfer uğurlu! {len(zt)} record{C.RESET}")
        for s in zt[:10]:
            col.add(s)
    else:
        print(f"        {C.DIM}Zone Transfer bloklanıb (normal){C.RESET}")

    print(f"\n{C.YELLOW}[04/18]{C.RESET} crt.sh sertifikat şəffaflığı...")
    before = len(col.subs)
    src_crtsh(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain  (cəmi: {len(col.subs)})")

    print(f"\n{C.YELLOW}[05/18]{C.RESET} CertSpotter (SSLMate)...")
    before = len(col.subs)
    src_certspotter(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain")

    print(f"\n{C.YELLOW}[06/18]{C.RESET} AlienVault OTX passive DNS...")
    before = len(col.subs)
    otx_ips = src_alienvault(domain, col)
    for ip in otx_ips:
        pprint_ip(ip, "alienvault-otx")
        add_ip(ip, "alienvault-otx")
    print(f"        {len(otx_ips)} IP, {len(col.subs)-before} yeni subdomain")

    print(f"\n{C.YELLOW}[07/18]{C.RESET} HackerTarget DNS history...")
    before = len(col.subs)
    ht_ips = src_hackertarget(domain, col)
    for ip in ht_ips:
        pprint_ip(ip, "hackertarget")
        add_ip(ip, "hackertarget")
    print(f"        {len(ht_ips)} IP, {len(col.subs)-before} yeni subdomain")

    print(f"\n{C.YELLOW}[08/18]{C.RESET} URLScan.io scan tarixçəsi...")
    before = len(col.subs)
    us_ips = src_urlscan(domain, col)
    for ip in us_ips:
        pprint_ip(ip, "urlscan.io")
        add_ip(ip, "urlscan.io")
    print(f"        {len(us_ips)} IP, {len(col.subs)-before} yeni subdomain")

    print(f"\n{C.YELLOW}[09/18]{C.RESET} ThreatMiner / Anubis / Wayback Machine...")
    before = len(col.subs)
    t1 = src_threatminer(domain, col)
    t2 = src_anubis(domain, col)
    t3 = src_wayback(domain, col)
    print(f"        ThreatMiner:{t1}  Anubis:{t2}  Wayback:{t3}  →  {len(col.subs)-before} yeni subdomain")

    print(f"\n{C.YELLOW}[10/18]{C.RESET} RapidDNS / BufferOver TLS...")
    before = len(col.subs)
    src_rapiddns(domain, col)
    src_bufferover(domain, col)
    print(f"        {len(col.subs)-before} yeni subdomain əlavə edildi")

    passive_subs = col.result()
    brute_list = brute_subs(domain)
    all_to_resolve = sorted(set(passive_subs + brute_list))
    print(f"\n{C.YELLOW}[11/18]{C.RESET} Subdomain resolve (parallel)...")
    print(f"        Passive:{len(passive_subs)}  Brute:{len(brute_list)}  Cəmi unikal:{len(all_to_resolve)}")
    sub_resolved = resolve_all(all_to_resolve, workers=60)
    print(f"        {len(sub_resolved)} aktiv subdomain resolve olundu")
    non_cf_subs = []
    for sub, ips in sorted(sub_resolved.items()):
        for ip in ips:
            add_ip(ip, f"sub:{sub}")
            if not is_cloudflare(ip) and not is_private(ip):
                non_cf_subs.append((sub, ip))
    if non_cf_subs:
        print(f"\n        {C.GREEN}{C.BOLD}⚡ CF-dən kənar subdomain IP-ləri:{C.RESET}")
        seen = set()
        for sub, ip in non_cf_subs[:30]:
            if ip not in seen:
                print(f"          {C.GREEN}{ip:<20}{C.RESET} ← {sub}")
                seen.add(ip)

    print(f"\n{C.YELLOW}[12/18]{C.RESET} Shodan InternetDB (non-CF IP-lər)...")
    shodan_cache = {}
    real_list = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
    for ip in real_list[:20]:
        d = shodan_info(ip)
        if d:
            shodan_cache[ip] = d
            print(f"      {C.CYAN}{ip:<20}{C.RESET} ports:{d.get('ports', [])}  tags:{d.get('tags', [])}")
            add_ip(ip, "shodan-idb")

    print(f"\n{C.YELLOW}[13/18]{C.RESET} TLS Deep Analysis — sertifikat + SAN + cipher...")
    tls_result = tls_analyze(domain)
    tls_sans = []
    if tls_result.get("error"):
        print(f"        {C.DIM}TLS xəta: {tls_result['error']}{C.RESET}")
    else:
        print(f"        CN: {C.CYAN}{tls_result['cn']}{C.RESET}  Issuer: {tls_result['issuer']}")
        print(f"        Version: {tls_result['version']}  Cipher: {tls_result['cipher']}")
        tls_sans = list(set(tls_result["sans"]))
        san_pairs = tls_san_to_ips(tls_sans, domain)
        for san, ip in san_pairs:
            if not is_cloudflare(ip):
                add_ip(ip, "tls-san")
                if verbose:
                    print(f"        {C.GREEN}SAN IP: {ip}{C.RESET} ← {san}")

    print(f"\n{C.YELLOW}[14/18]{C.RESET} Technology Detection + JS Endpoint Scan + Favicon...")
    html_body, resp_headers, _ = http_get_with_headers(f"https://{domain}", timeout=15)
    if not html_body:
        html_body, resp_headers, _ = http_get_with_headers(f"http://{domain}", timeout=15)
    tech_found = detect_technology(html_body or "", resp_headers or {}) if html_body else {}
    js_endpoints = extract_js_endpoints(f"https://{domain}", html_body) if html_body else []
    fav_info = favicon_hash(domain)
    if tech_found:
        print(f"        {C.CYAN}Tech stack:{C.RESET} {', '.join(tech_found.keys())}")
    else:
        print(f"        {C.DIM}Tech fingerprint: müəyyən edilmədi{C.RESET}")
    if js_endpoints:
        print(f"        {C.CYAN}JS Endpoints ({len(js_endpoints)}):{C.RESET} {', '.join(js_endpoints[:5])}")
    if fav_info:
        print(f"        {C.CYAN}Favicon:{C.RESET} mmh3={fav_info['mmh3']}  size={fav_info['size']}B")

    print(f"\n{C.YELLOW}[15/18]{C.RESET} BGP/ASN + Cloud Classify + Reverse IP (non-CF)...")
    real_ips = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
    for ip in real_ips[:20]:
        bgp = bgpview_lookup(ip)
        iapi = ipapi_info(ip)
        asn = bgp.get("asn", "")
        org = bgp.get("asn_name", "") or iapi.get("org", "")
        cloud = classify_cloud(asn, org)
        rdns = reverse_ip_lookup(ip)
        ip_enrich[ip] = {"bgp": bgp, "ipapi": iapi, "cloud": cloud, "rdns": rdns}
        cloud_tag = f"  {C.YELLOW}[{cloud}]{C.RESET}" if cloud else ""
        rdns_tag = f"  {C.DIM}shared:{len(rdns)} domains{C.RESET}" if rdns else ""
        print(f"      {C.CYAN}{ip:<20}{C.RESET} AS={asn} {C.DIM}{org[:35]}{C.RESET}{cloud_tag}{rdns_tag}")

    print(f"\n{C.YELLOW}[16/18]{C.RESET} Baseline fingerprint (public domain response)...")
    baseline_http_raw = http_probe_ip(domain, domain, scheme="http") if False else None
    baseline_https_raw = http_probe_ip(domain, domain, scheme="https") if False else None
    pub_http, pub_h, pub_s = http_get_with_headers(f"http://{domain}", timeout=12)
    pub_https, pub_hs, pub_ss = http_get_with_headers(f"https://{domain}", timeout=12)
    baseline_http = fingerprint_response({"ok": pub_http is not None, "status": pub_s, "server": pub_h.get('Server', ''), "title": re.search(r'<title[^>]*>(.*?)</title>', pub_http or '', re.I | re.S).group(1).strip()[:200] if pub_http and re.search(r'<title[^>]*>(.*?)</title>', pub_http, re.I | re.S) else '', "body_hash": hashlib.sha256((pub_http or '')[:8192].encode()).hexdigest()[:16], "headers": {k.lower(): v for k, v in (pub_h or {}).items()}})
    baseline_https = fingerprint_response({"ok": pub_https is not None, "status": pub_ss, "server": pub_hs.get('Server', ''), "title": re.search(r'<title[^>]*>(.*?)</title>', pub_https or '', re.I | re.S).group(1).strip()[:200] if pub_https and re.search(r'<title[^>]*>(.*?)</title>', pub_https, re.I | re.S) else '', "body_hash": hashlib.sha256((pub_https or '')[:8192].encode()).hexdigest()[:16], "headers": {k.lower(): v for k, v in (pub_hs or {}).items()}})
    print(f"        HTTP status: {baseline_http.get('status')}  HTTPS status: {baseline_https.get('status')}")
    if baseline_https.get('title'):
        print(f"        HTTPS title: {baseline_https.get('title')[:80]}")

    print(f"\n{C.YELLOW}[17/18]{C.RESET} Verify Engine — Host header + SNI + fingerprint diff...")
    if skip_verify:
        print(f"        {C.DIM}skip (--skip-verify){C.RESET}")
    else:
        verify_targets = []
        for ip in real_ips:
            enrich = ip_enrich.get(ip, {})
            cloud = enrich.get("cloud")
            if cloud == "Cloudflare":
                continue
            verify_targets.append(ip)
        verify_targets = verify_targets[:max(1, workers * 3)]
        print(f"        {len(verify_targets)} namizəd yoxlanılır...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(verify_candidate, ip, domain, baseline_http, baseline_https): ip for ip in verify_targets}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    res = fut.result()
                    verify_results[ip] = res
                    if res["verdict"] == "LIKELY_ORIGIN":
                        add_ip(ip, "content-match")
                    elif res["https"].get("status"):
                        add_ip(ip, "https-verify")
                    elif res["http"].get("status"):
                        add_ip(ip, "http-verify")
                    label = C.GREEN if res['verdict'] == 'LIKELY_ORIGIN' else C.YELLOW if res['verdict'] == 'POSSIBLE' else C.DIM
                    print(f"      {label}{ip:<20}{C.RESET} {res['verdict']:<12} score={res['score']:<3} {', '.join(res['reasons'][:4])}")
                except Exception as e:
                    print(f"      {C.RED}{ip:<20}{C.RESET} verify-error {e}")

    print(f"\n{C.YELLOW}[18/18]{C.RESET} GitHub Leak Detection (safe mode)...")
    leak_findings = []
    if skip_github:
        print(f"        {C.DIM}skip (--no-github){C.RESET}")
    else:
        leak_findings = github_leak_scan(domain)
        if leak_findings:
            print(f"        {C.RED}⚠  {len(leak_findings)} potensial sızıntı tapıldı{C.RESET}")
        else:
            print(f"        {C.GREEN}Açıq sızıntı əlaməti tapılmadı{C.RESET}")

    engine = CorrelationEngine(domain)
    for ip, srcs in all_ips.items():
        if is_private(ip):
            continue
        enrich = ip_enrich.get(ip, {})
        engine.add_ip(ip, srcs, bgp=enrich.get("bgp"), ipapi=enrich.get("ipapi"), rdns=enrich.get("rdns"), cloud=enrich.get("cloud"), verify=verify_results.get(ip))

    elapsed = time.time() - t0
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*70}")
    print(f"  ✦  NƏTİCƏ — {domain}  ({elapsed:.1f}s)")
    print(f"{'═'*70}{C.RESET}")

    role_summary = engine.get_summary()
    if verbose:
        print(f"\n  {C.CYAN}Infrastructure Breakdown:{C.RESET}")
        for role, ips in role_summary.items():
            print(f"    {C.DIM}{role:<16}{C.RESET} {', '.join(ips[:5])}")

    real_cands = engine.origin_candidates()
    cf_ips_list = [ip for ip in all_ips if is_cloudflare(ip)]
    if real_cands:
        print(f"\n{C.GREEN}{C.BOLD}  ⚡ Potensial REAL IP-lər ({len(real_cands)}):{C.RESET}")
        for ip, data in real_cands[:20]:
            info = ip_info(ip)
            bgp = data.get("bgp") or {}
            iapi = data.get("ipapi") or {}
            cloud = data.get("cloud")
            rdns = data.get("rdns_domains") or []
            verify = data.get("verify") or {}
            ports = (shodan_cache.get(ip) or {}).get("ports", [])
            conf = confidence_score(data["sources"], cloud=cloud, verify=verify, rdns_count=len(rdns))
            xval = cross_validated(data["sources"], verify=verify)
            bar = "█" * max(0, min(10, conf if conf > 0 else 0))
            bcol = C.GREEN if conf >= 8 else C.YELLOW if conf >= 3 else C.DIM
            xval_str = f" {C.GREEN}✓ CROSS-VALIDATED{C.RESET}" if xval else f" {C.YELLOW}⚠ weak{C.RESET}"
            print(f"\n  {C.GREEN}{C.BOLD}▶ {ip}{C.RESET}{xval_str}")
            print(f"    {C.DIM}Role    :{C.RESET} {data['role']}")
            print(f"    {C.DIM}ASN     :{C.RESET} {bgp.get('asn', info['org'])} | {info['city']}, {info['country']}")
            if cloud:
                print(f"    {C.DIM}Cloud   :{C.RESET} {cloud}")
            if info.get("hostname"):
                print(f"    {C.DIM}rDNS    :{C.RESET} {info['hostname']}")
            if iapi.get("hosting"):
                print(f"    {C.DIM}Hosting :{C.RESET} Datacenter/VPS")
            if rdns:
                print(f"    {C.DIM}Rev-IP  :{C.RESET} {len(rdns)} co-hosted domain(s)")
            print(f"    {C.DIM}Mənbələr:{C.RESET} {', '.join(list(set(data['sources']))[:8])}")
            if verify:
                print(f"    {C.DIM}Verify  :{C.RESET} {verify.get('verdict')} / {verify.get('confidence_label')} / score={verify.get('score')}")
                if verify.get("reasons"):
                    print(f"    {C.DIM}Səbəb   :{C.RESET} {', '.join(verify['reasons'][:6])}")
            if ports:
                print(f"    {C.DIM}Portlar :{C.RESET} {ports}")
            print(f"    {C.DIM}Güvən   :{C.RESET} {bcol}{bar}{C.RESET} ({conf} xal)")
    else:
        print(f"\n{C.YELLOW}  ⚠  Real IP tapılmadı.{C.RESET}")

    verdicts = {ip: r['verdict'] for ip, r in verify_results.items()}
    likely = [ip for ip, v in verdicts.items() if v == 'LIKELY_ORIGIN']
    possible = [ip for ip, v in verdicts.items() if v == 'POSSIBLE']
    edgeish = [ip for ip, v in verdicts.items() if v == 'EDGE_OR_PROXY']
    print(f"\n  {C.CYAN}Verify summary:{C.RESET} likely={len(likely)} possible={len(possible)} edge/proxy={len(edgeish)}")
    print(f"  {C.DIM}Cloudflare IP-ləri: {', '.join(cf_ips_list[:6])}{C.RESET}")
    print(f"  {C.DIM}Subdomain: {len(sub_resolved)} aktiv / {len(all_to_resolve)} yoxlanıldı{C.RESET}")
    print(f"  {C.DIM}TLS SANs: {len(tls_sans)} | JS Endpoints: {len(js_endpoints)}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'═'*70}{C.RESET}\n")

    result = {
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 2),
        "real_candidates": {
            ip: {
                "sources": list(data["sources"]),
                "confidence": confidence_score(data["sources"], cloud=data.get("cloud"), verify=data.get("verify"), rdns_count=len(data.get("rdns_domains") or [])),
                "cross_validated": cross_validated(data["sources"], verify=data.get("verify")),
                "role": data["role"],
                "cloud_provider": data.get("cloud"),
                "bgp": data.get("bgp") or {},
                "verify": data.get("verify") or {},
                "shodan": shodan_cache.get(ip, {}),
                "rdns_count": len(data.get("rdns_domains") or []),
            }
            for ip, data in real_cands
        },
        "verify_summary": {
            "likely_origin": likely,
            "possible": possible,
            "edge_or_proxy": edgeish,
            "details": verify_results,
        },
        "cloudflare_ips": cf_ips_list,
        "infrastructure_map": role_summary,
        "subdomains": {
            "total_checked": len(all_to_resolve),
            "active": len(sub_resolved),
            "non_cf": [{"sub": s, "ip": ip} for s, ip in non_cf_subs[:100]],
        },
        "dns_records": {"mx": dns_data["mx"], "spf_ips": dns_data["spf_ips"], "ns": dns_data["ns"]},
        "tls": {
            "cn": tls_result.get("cn", ""),
            "issuer": tls_result.get("issuer", ""),
            "sans_count": len(tls_sans),
            "sans": tls_sans[:20],
            "version": tls_result.get("version", ""),
            "cipher": tls_result.get("cipher", ""),
            "weak": tls_result.get("weak", False),
        },
        "technology": list(tech_found.keys()),
        "js_endpoints": js_endpoints[:20],
        "favicon": fav_info,
        "github_leaks": [{"repo": lf["repo"], "file": lf["file"], "url": lf["url"]} for lf in leak_findings],
    }
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"{C.GREEN}[+] Nəticə saxlandı: {output_file}{C.RESET}\n")
    return result


def main():
    banner()
    ap = argparse.ArgumentParser(description="CF-Hunter v5: Advanced Cloudflare Real IP Intelligence")
    ap.add_argument("domain", help="Hədəf domain")
    ap.add_argument("-o", "--output", help="JSON faylına yaz")
    ap.add_argument("-v", "--verbose", action="store_true", help="Ətraflı çıxış")
    ap.add_argument("--no-github", action="store_true", help="GitHub leak detection-u atla")
    ap.add_argument("--skip-verify", action="store_true", help="Host-header/SNI verify mərhələsini atla")
    ap.add_argument("--verify-workers", type=int, default=10, help="Verify mərhələsi üçün worker sayı")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split('?')[0]
    if not re.match(r'^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$', domain):
        print(f"{C.RED}[!] Yanlış domain formatı: {domain}{C.RESET}")
        sys.exit(1)

    analyze(
        domain,
        verbose=args.verbose,
        output_file=args.output,
        skip_github=args.no_github,
        skip_verify=args.skip_verify,
        workers=max(1, min(args.verify_workers, 50)),
    )


if __name__ == "__main__":
    main()
