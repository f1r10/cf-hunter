#!/usr/bin/env python3
"""
CF-HUNTER v6 SAFE @f1r10
Authorized security posture auditor for Cloudflare-protected assets.

Nə edir:
- v5 recon + verify məntiqini saxlayır
- təhlükəsiz attack-surface discovery əlavə edir
- security headers, robots.txt, sitemap.xml, common panel exposure,
  safe-sensitive-path checks, TLS/meta fingerprint yoxlayır
- risk scoring və JSON report verir

Nə ETMİR:
- bypass automation
- bruteforce
- auth bypass
- exploit chaining
- destructive fuzzing

Yalnız icazəli sistemlər üçün istifadə edin.
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
from urllib.request import Request, urlopen
from urllib.error import HTTPError
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
{C.RESET}{C.DIM}  CF-HUNTER v6 SAFE — Recon + Verify + Posture Audit{C.RESET}
""")

# ──────────────────────────────────────────────────────────────
#  Trust / provider data
# ──────────────────────────────────────────────────────────────
SOURCE_TRUST = {
    "current-dns":   ("DIRECT", 3),
    "mx-record":     ("DIRECT", 2),
    "spf-record":    ("DIRECT", 1),
    "zone-transfer": ("DIRECT", 3),
    "tls-san":       ("DIRECT", 3),
    "http-verify":   ("DIRECT", 4),
    "https-verify":  ("DIRECT", 4),
    "content-match": ("DIRECT", 5),
    "urlscan.io":    ("VERIFIED_API", 2),
    "alienvault-otx":("VERIFIED_API", 2),
    "shodan-idb":    ("VERIFIED_API", 2),
    "crtsh":         ("VERIFIED_API", 2),
    "certspotter":   ("VERIFIED_API", 2),
    "hackertarget":  ("VERIFIED_API", 2),
    "wayback":       ("SCRAPED", 1),
    "threatminer":   ("SCRAPED", 1),
    "anubis":        ("SCRAPED", 1),
    "rapiddns":      ("SCRAPED", 1),
    "bufferover":    ("SCRAPED", 1),
}


def source_trust(src):
    if src.startswith("sub:"):
        return ("DIRECT", 2)
    for key, val in SOURCE_TRUST.items():
        if key in src:
            return val
    return ("SCRAPED", 1)


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
    "AS16509": "AWS", "AS14618": "AWS", "AS15169": "GCP", "AS8075": "Azure",
    "AS13335": "Cloudflare", "AS209242": "Cloudflare", "AS54113": "Fastly",
    "AS20940": "Akamai", "AS14061": "DigitalOcean", "AS20473": "Vultr",
    "AS63949": "Linode", "AS16276": "OVH", "AS24940": "Hetzner",
    "AS19551": "Imperva", "AS30148": "Sucuri", "AS40934": "Fortinet",
}

CLOUD_ORG_KEYWORDS = {
    "amazon": "AWS", "aws": "AWS", "google": "GCP", "gcp": "GCP",
    "microsoft": "Azure", "azure": "Azure", "cloudflare": "Cloudflare",
    "fastly": "Fastly", "akamai": "Akamai", "digitalocean": "DigitalOcean",
    "vultr": "Vultr", "linode": "Linode", "ovh": "OVH", "hetzner": "Hetzner",
    "incapsula": "Imperva", "imperva": "Imperva", "sucuri": "Sucuri", "fortinet": "Fortinet",
}

EDGE_PROVIDERS = {"Cloudflare", "Fastly", "Akamai", "Imperva", "Sucuri", "Fortinet"}


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


def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in CF_NETS)
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


_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CF-Hunter/6.0-safe",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


def http_get(url, timeout=12, retries=1):
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=_HEADERS)
            with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception:
            if attempt < retries:
                time.sleep(0.8)
    return None


def http_json(url, timeout=12):
    raw = http_get(url, timeout=timeout)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None


def http_get_with_headers(url, timeout=12):
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
#  Baseline / verify
# ──────────────────────────────────────────────────────────────
def recv_all(sock, cap=65536):
    sock.settimeout(5)
    chunks = []
    total = 0
    while total < cap:
        try:
            data = sock.recv(min(4096, cap - total))
        except Exception:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def http_probe_ip(ip, host, scheme="http", port=None, path="/"):
    result = {
        "scheme": scheme, "ip": ip, "host": host, "ok": False, "status": None,
        "server": "", "title": "", "body_hash": "", "headers": {}, "sample": "",
        "error": "", "cf_like": False, "squid_like": False,
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
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {_HEADERS['User-Agent']}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
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
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        result["title"] = title_m.group(1).strip()[:200] if title_m else ""
        result["sample"] = re.sub(r"\s+", " ", body[:500]).strip()
        result["body_hash"] = hashlib.sha256(body[:8192].encode()).hexdigest()[:16]
        server_l = result["server"].lower()
        body_l = body.lower()
        result["cf_like"] = "cloudflare" in server_l or "cf-ray" in headers or "attention required" in body_l
        result["squid_like"] = "squid" in server_l or ("generated by" in body_l and "squid" in body_l)
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
        "score": 0,
        "verdict": "UNCONFIRMED",
        "confidence_label": "LOW",
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
    verdict["score"] += s1 + s2
    verdict["reasons"].extend(r1 + r2)
    if verdict["https"].get("body_hash") and baseline_https and verdict["https"]["body_hash"] == baseline_https.get("body_hash"):
        verdict["verdict"] = "LIKELY_ORIGIN"
    elif verdict["score"] >= 8:
        verdict["verdict"] = "LIKELY_ORIGIN"
    elif verdict["score"] >= 3:
        verdict["verdict"] = "POSSIBLE"
    else:
        verdict["verdict"] = "EDGE_OR_PROXY"
    verdict["confidence_label"] = "HIGH" if verdict["score"] >= 10 else "MEDIUM" if verdict["score"] >= 5 else "LOW"
    return verdict


# ──────────────────────────────────────────────────────────────
#  Passive collectors
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


def src_certspotter(domain, col):
    data = http_json(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=15)
    if data and isinstance(data, list):
        for cert in data:
            for name in cert.get("dns_names", []):
                col.add(name)


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


def src_wayback(domain, col):
    data = http_json(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500", timeout=20)
    if data and len(data) > 1:
        pat = re.compile(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')')
        for row in data[1:]:
            if row:
                m = pat.search(row[0])
                if m:
                    col.add(m.group(1))


def src_threatminer(domain, col):
    data = http_json(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=12)
    if data:
        for s in data.get("results", []):
            col.add(s)


def src_anubis(domain, col):
    data = http_json(f"https://jldc.me/anubis/subdomains/{domain}", timeout=12)
    if data and isinstance(data, list):
        for s in data:
            col.add(s)


def src_rapiddns(domain, col):
    raw = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15)
    if raw:
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        for s in re.findall(pattern, raw):
            col.add(s)


def src_bufferover(domain, col):
    data = http_json(f"https://tls.bufferover.run/dns?q=.{domain}", timeout=10)
    if data:
        for line in data.get("Results", []) or []:
            parts = line.split(",")
            if len(parts) >= 4:
                col.add(parts[3].strip())


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
        return {"org": d.get("org", ""), "isp": d.get("isp", ""), "country": d.get("country", ""), "city": d.get("city", ""), "hosting": d.get("hosting", False), "proxy": d.get("proxy", False), "mobile": d.get("mobile", False)}
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


WORDLIST = [
    "www","mail","admin","panel","cpanel","whm","api","api2","gateway","static","assets",
    "cdn","forum","blog","shop","pay","secure","auth","login","app","m","mobile","common",
    "status","metrics","help","support","wiki","ftp","backup","dev","staging","prod"
]


def brute_subs(domain):
    return sorted(set(f"{w}.{domain}" for w in WORDLIST))


def _resolve_one(sub):
    try:
        return sub, list({i[4][0] for i in socket.getaddrinfo(sub, None, proto=socket.IPPROTO_TCP)})
    except Exception:
        return sub, []


def resolve_all(subs, workers=50):
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
#  SAFE posture checks
# ──────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "XFO",
    "x-content-type-options": "XCTO",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

SAFE_PANEL_PATHS = [
    "/admin", "/login", "/user/login", "/dashboard", "/cpanel", "/whm", "/phpmyadmin"
]

SAFE_SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/server-status", "/nginx_status", "/crossdomain.xml", "/clientaccesspolicy.xml"
]


def classify_path_exposure(path, status, headers, body):
    body_l = (body or "").lower()
    server = (headers or {}).get("server", "")
    title_m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    title = title_m.group(1).strip()[:120] if title_m else ""
    findings = []
    severity = "info"

    if status in (200, 401, 403):
        findings.append("reachable")
    if path in ("/server-status", "/nginx_status") and status == 200:
        severity = "high"
        findings.append("status endpoint exposed")
    if "phpmyadmin" in path and status in (200, 401):
        severity = "medium"
        findings.append("admin interface visible")
    if any(k in body_l for k in ["apache server status", "active connections", "nginx stub status"]):
        severity = "high"
        findings.append("operational metrics exposed")
    if any(k in title.lower() for k in ["login", "admin", "dashboard", "phpmyadmin", "cpanel"]):
        severity = "medium" if severity == "info" else severity
        findings.append(f"title: {title}")
    if "index of /" in body_l:
        severity = "high"
        findings.append("directory listing")
    if "server-status" in path and server:
        findings.append(f"server:{server}")
    return {"path": path, "status": status, "title": title, "severity": severity, "findings": findings}


def fetch_path(base_url, path, timeout=8):
    body, headers, status = http_get_with_headers(base_url.rstrip("/") + path, timeout=timeout)
    return classify_path_exposure(path, status, headers, body)


def security_headers_report(headers):
    norm = {k.lower(): v for k, v in (headers or {}).items()}
    present = {}
    missing = []
    for hk, label in SECURITY_HEADERS.items():
        if hk in norm:
            present[label] = norm[hk]
        else:
            missing.append(label)
    return {"present": present, "missing": missing}


def quick_http_meta(base_url):
    body, headers, status = http_get_with_headers(base_url, timeout=10)
    title = ""
    if body:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = m.group(1).strip()[:120] if m else ""
    return {
        "status": status,
        "server": (headers or {}).get("Server", "") or (headers or {}).get("server", ""),
        "title": title,
        "headers": headers or {},
        "body_hash": hashlib.sha256((body or "")[:8192].encode()).hexdigest()[:16],
    }


def run_safe_posture_checks(domain, max_workers=10):
    base_https = f"https://{domain}"
    base_http = f"http://{domain}"
    meta_https = quick_http_meta(base_https)
    meta_http = quick_http_meta(base_http)
    hdr_report = security_headers_report(meta_https["headers"] if meta_https.get("headers") else meta_http.get("headers"))

    targets = SAFE_PANEL_PATHS + SAFE_SENSITIVE_PATHS
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(fetch_path, base_https, p) for p in targets]
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                pass

    interesting = [r for r in results if r["status"] in (200, 401, 403)]
    high = [r for r in interesting if r["severity"] == "high"]
    medium = [r for r in interesting if r["severity"] == "medium"]
    info = [r for r in interesting if r["severity"] == "info"]

    risk = 0
    if meta_https.get("status") in (200, 301, 302):
        risk += 1
    risk += len(high) * 4
    risk += len(medium) * 2
    risk += max(0, len(hdr_report["missing"]) - 2)
    if meta_https.get("server"):
        risk += 1

    level = "LOW"
    if risk >= 12:
        level = "HIGH"
    elif risk >= 6:
        level = "MEDIUM"

    return {
        "https_meta": meta_https,
        "http_meta": meta_http,
        "security_headers": hdr_report,
        "interesting_paths": sorted(interesting, key=lambda x: (x["severity"], x["path"]), reverse=True),
        "risk_score": risk,
        "risk_level": level,
    }


# ──────────────────────────────────────────────────────────────
#  Correlation / scoring
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
    return (verify and verify.get("verdict") == "LIKELY_ORIGIN") or direct >= 1 or len(s) >= 2


class CorrelationEngine:
    def __init__(self, domain):
        self.domain = domain
        self.ip_data = {}
    def add_ip(self, ip, sources, bgp=None, ipapi=None, rdns=None, cloud=None, verify=None):
        if not is_valid_ip(ip) or is_private(ip):
            return
        self.ip_data[ip] = {
            "sources": list(sources), "bgp": bgp or {}, "ipapi": ipapi or {}, "rdns_domains": rdns or [],
            "cloud": cloud, "verify": verify or {}, "role": self._classify_role(ip, sources, cloud, rdns or [], verify or {})
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
        if len(rdns_domains) > 10:
            return "SHARED_HOST"
        if any(x.startswith("sub:") for x in s):
            return "ORIGIN_CANDIDATE"
        if cloud:
            return "CLOUD_HOSTED"
        return "ORIGIN_CANDIDATE"
    def get_summary(self):
        out = {}
        for ip, data in self.ip_data.items():
            out.setdefault(data["role"], []).append(ip)
        return out
    def origin_candidates(self):
        cands = {ip: d for ip, d in self.ip_data.items() if d["role"] in ("ORIGIN", "ORIGIN_CANDIDATE", "CLOUD_HOSTED")}
        return sorted(cands.items(), key=lambda x: confidence_score(x[1]["sources"], cloud=x[1].get("cloud"), verify=x[1].get("verify"), rdns_count=len(x[1].get("rdns_domains") or [])), reverse=True)


# ──────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────
def analyze(domain, verbose=False, output_file=None, skip_verify=False, verify_workers=10, posture_workers=10):
    t0 = time.time()
    col = SubCollector(domain)
    all_ips = {}
    ip_enrich = {}
    verify_results = {}

    def add_ip(ip, src):
        if is_valid_ip(ip) and not is_private(ip):
            all_ips.setdefault(ip, set()).add(src)

    print(f"\n{C.BOLD}{C.CYAN}[TARGET]{C.RESET} {C.BOLD}{domain}{C.RESET}  {C.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.DIM}{'═'*72}{C.RESET}")

    print(f"\n{C.YELLOW}[01/17]{C.RESET} Current DNS...")
    try:
        for info in socket.getaddrinfo(domain, None):
            add_ip(info[4][0], "current-dns")
            print(f"      {info[4][0]}")
    except Exception as e:
        print(f"      {C.DIM}{e}{C.RESET}")

    print(f"\n{C.YELLOW}[02/17]{C.RESET} Passive subdomain sources...")
    src_crtsh(domain, col)
    src_certspotter(domain, col)
    otx_ips = src_alienvault(domain, col)
    ht_ips = src_hackertarget(domain, col)
    us_ips = src_urlscan(domain, col)
    src_wayback(domain, col)
    src_threatminer(domain, col)
    src_anubis(domain, col)
    src_rapiddns(domain, col)
    src_bufferover(domain, col)
    for ip in otx_ips: add_ip(ip, "alienvault-otx")
    for ip in ht_ips: add_ip(ip, "hackertarget")
    for ip in us_ips: add_ip(ip, "urlscan.io")
    print(f"      passive subdomains: {len(col.subs)}")

    print(f"\n{C.YELLOW}[03/17]{C.RESET} DNS Records...")
    dns_data = {"mx": [], "mx_ips": [], "spf_ips": [], "ns": [], "txt": []}
    try:
        for a in http_json(f"https://dns.google/resolve?name={quote(domain)}&type=MX", timeout=10).get("Answer", []) if http_json(f"https://dns.google/resolve?name={quote(domain)}&type=MX", timeout=10) else []:
            raw = a.get("data", "")
            mx_host = raw.split()[-1].rstrip(".") if raw else ""
            if mx_host and mx_host not in dns_data["mx"]:
                dns_data["mx"].append(mx_host)
                try:
                    for info in socket.getaddrinfo(mx_host, None):
                        ip = info[4][0]
                        if is_valid_ip(ip) and ip not in dns_data["mx_ips"]:
                            dns_data["mx_ips"].append(ip)
                except Exception:
                    pass
    except Exception:
        pass
    for ip in dns_data["mx_ips"]:
        add_ip(ip, "mx-record")
    print(f"      MX IP count: {len(dns_data['mx_ips'])}")

    print(f"\n{C.YELLOW}[04/17]{C.RESET} Resolve subdomains...")
    all_to_resolve = sorted(set(col.result() + brute_subs(domain)))
    sub_resolved = resolve_all(all_to_resolve, workers=50)
    non_cf_subs = []
    for sub, ips in sub_resolved.items():
        for ip in ips:
            add_ip(ip, f"sub:{sub}")
            if not is_cloudflare(ip) and not is_private(ip):
                non_cf_subs.append((sub, ip))
    print(f"      active subdomains: {len(sub_resolved)} | non-CF IP pairs: {len(non_cf_subs)}")

    print(f"\n{C.YELLOW}[05/17]{C.RESET} Shodan InternetDB...")
    shodan_cache = {}
    real_ips = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
    for ip in real_ips[:20]:
        d = shodan_info(ip)
        if d:
            shodan_cache[ip] = d
            add_ip(ip, "shodan-idb")
    print(f"      enriched IPs: {len(shodan_cache)}")

    print(f"\n{C.YELLOW}[06/17]{C.RESET} TLS analysis...")
    tls_result = tls_analyze(domain)
    tls_sans = list(set(tls_result.get("sans", []))) if not tls_result.get("error") else []
    for san, ip in tls_san_to_ips(tls_sans, domain):
        if not is_cloudflare(ip):
            add_ip(ip, "tls-san")
    print(f"      TLS SANs: {len(tls_sans)}")

    print(f"\n{C.YELLOW}[07/17]{C.RESET} ASN / cloud / reverse-IP enrichment...")
    for ip in [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)][:20]:
        bgp = bgpview_lookup(ip)
        iapi = ipapi_info(ip)
        cloud = classify_cloud(bgp.get("asn", ""), bgp.get("asn_name", "") or iapi.get("org", ""))
        rdns = reverse_ip_lookup(ip)
        ip_enrich[ip] = {"bgp": bgp, "ipapi": iapi, "cloud": cloud, "rdns": rdns}
    print(f"      enriched candidates: {len(ip_enrich)}")

    print(f"\n{C.YELLOW}[08/17]{C.RESET} Public baseline fingerprint...")
    pub_http_body, pub_http_headers, pub_http_status = http_get_with_headers(f"http://{domain}", timeout=10)
    pub_https_body, pub_https_headers, pub_https_status = http_get_with_headers(f"https://{domain}", timeout=10)
    baseline_http = {
        "status": pub_http_status,
        "title": (re.search(r'<title[^>]*>(.*?)</title>', pub_http_body or '', re.I | re.S).group(1).strip()[:120] if pub_http_body and re.search(r'<title[^>]*>(.*?)</title>', pub_http_body, re.I | re.S) else ''),
        "body_hash": hashlib.sha256((pub_http_body or '')[:8192].encode()).hexdigest()[:16],
        "header_keys": sorted(list(normalize_headers({k.lower(): v for k, v in (pub_http_headers or {}).items()}).keys()))[:20],
    }
    baseline_https = {
        "status": pub_https_status,
        "title": (re.search(r'<title[^>]*>(.*?)</title>', pub_https_body or '', re.I | re.S).group(1).strip()[:120] if pub_https_body and re.search(r'<title[^>]*>(.*?)</title>', pub_https_body, re.I | re.S) else ''),
        "body_hash": hashlib.sha256((pub_https_body or '')[:8192].encode()).hexdigest()[:16],
        "header_keys": sorted(list(normalize_headers({k.lower(): v for k, v in (pub_https_headers or {}).items()}).keys()))[:20],
    }
    print(f"      baseline HTTPS status: {baseline_https['status']}")

    print(f"\n{C.YELLOW}[09/17]{C.RESET} Verify Engine...")
    if skip_verify:
        print(f"      {C.DIM}skip{C.RESET}")
    else:
        verify_targets = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)][:max(verify_workers * 3, 1)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=verify_workers) as ex:
            futs = {ex.submit(verify_candidate, ip, domain, baseline_http, baseline_https): ip for ip in verify_targets}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    res = fut.result()
                    verify_results[ip] = res
                    if res["verdict"] == "LIKELY_ORIGIN":
                        add_ip(ip, "content-match")
                    elif res["https"].get("status"):
                        add_ip(ip, "https-verify")
                    elif res["http"].get("status"):
                        add_ip(ip, "http-verify")
                    print(f"      {ip:<20} {res['verdict']:<12} score={res['score']}")
                except Exception as e:
                    print(f"      {ip:<20} verify-error {e}")

    print(f"\n{C.YELLOW}[10/17]{C.RESET} Safe posture audit...")
    posture = run_safe_posture_checks(domain, max_workers=posture_workers)
    print(f"      risk: {posture['risk_level']} ({posture['risk_score']}) | interesting paths: {len(posture['interesting_paths'])}")

    engine = CorrelationEngine(domain)
    for ip, srcs in all_ips.items():
        enrich = ip_enrich.get(ip, {})
        engine.add_ip(ip, srcs, bgp=enrich.get("bgp"), ipapi=enrich.get("ipapi"), rdns=enrich.get("rdns"), cloud=enrich.get("cloud"), verify=verify_results.get(ip))

    print(f"\n{C.YELLOW}[11/17]{C.RESET} Summaries...")
    role_summary = engine.get_summary()
    real_cands = engine.origin_candidates()
    print(f"      roles: {', '.join(f'{k}={len(v)}' for k, v in role_summary.items())}")

    elapsed = time.time() - t0
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*72}")
    print(f"  ✦  NƏTİCƏ — {domain}  ({elapsed:.1f}s)")
    print(f"{'═'*72}{C.RESET}")

    if real_cands:
        print(f"\n{C.GREEN}{C.BOLD}  ⚡ Potensial REAL IP-lər ({len(real_cands)}):{C.RESET}")
        for ip, data in real_cands[:15]:
            info = ip_info(ip)
            verify = data.get("verify") or {}
            conf = confidence_score(data["sources"], cloud=data.get("cloud"), verify=verify, rdns_count=len(data.get("rdns_domains") or []))
            print(f"\n  {C.GREEN}{C.BOLD}▶ {ip}{C.RESET}")
            print(f"    {C.DIM}Role    :{C.RESET} {data['role']}")
            print(f"    {C.DIM}ASN     :{C.RESET} {(data.get('bgp') or {}).get('asn', info['org'])} | {info['city']}, {info['country']}")
            if data.get("cloud"):
                print(f"    {C.DIM}Cloud   :{C.RESET} {data['cloud']}")
            if verify:
                print(f"    {C.DIM}Verify  :{C.RESET} {verify.get('verdict')} / {verify.get('confidence_label')} / score={verify.get('score')}")
            print(f"    {C.DIM}Mənbələr:{C.RESET} {', '.join(list(set(data['sources']))[:8])}")
            print(f"    {C.DIM}Güvən   :{C.RESET} {conf}")
    else:
        print(f"\n{C.YELLOW}  ⚠  Real IP tapılmadı.{C.RESET}")

    print(f"\n  {C.CYAN}Posture risk:{C.RESET} {posture['risk_level']} ({posture['risk_score']})")
    missing_hdr = posture['security_headers']['missing']
    if missing_hdr:
        print(f"  {C.CYAN}Missing security headers:{C.RESET} {', '.join(missing_hdr)}")
    if posture['interesting_paths']:
        print(f"  {C.CYAN}Interesting paths:{C.RESET}")
        for item in posture['interesting_paths'][:10]:
            print(f"    - {item['path']} [{item['status']}] {item['severity']} :: {', '.join(item['findings'][:3])}")

    print(f"{C.BOLD}{C.MAGENTA}{'═'*72}{C.RESET}\n")

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
            "details": verify_results,
            "likely_origin": [ip for ip, r in verify_results.items() if r.get("verdict") == "LIKELY_ORIGIN"],
            "possible": [ip for ip, r in verify_results.items() if r.get("verdict") == "POSSIBLE"],
            "edge_or_proxy": [ip for ip, r in verify_results.items() if r.get("verdict") == "EDGE_OR_PROXY"],
        },
        "infrastructure_map": role_summary,
        "subdomains": {
            "checked": len(all_to_resolve),
            "active": len(sub_resolved),
            "non_cf": [{"sub": s, "ip": ip} for s, ip in non_cf_subs[:100]],
        },
        "tls": tls_result,
        "posture": posture,
    }

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"{C.GREEN}[+] JSON saxlandı: {output_file}{C.RESET}")

    return result


def main():
    banner()
    ap = argparse.ArgumentParser(description="CF-HUNTER v6 SAFE")
    ap.add_argument("domain", help="Hədəf domain")
    ap.add_argument("-o", "--output", help="JSON faylı")
    ap.add_argument("-v", "--verbose", action="store_true", help="Ətraflı çıxış")
    ap.add_argument("--skip-verify", action="store_true", help="verify mərhələsini atla")
    ap.add_argument("--verify-workers", type=int, default=10, help="verify worker sayı")
    ap.add_argument("--posture-workers", type=int, default=10, help="safe posture worker sayı")
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
        skip_verify=args.skip_verify,
        verify_workers=max(1, min(args.verify_workers, 50)),
        posture_workers=max(1, min(args.posture_workers, 50)),
    )


if __name__ == "__main__":
    main()
