#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF-HUNTER v7.2 SAFE @f1r10
v5 + v6 birləşdirilmiş, daha güclü, lakin təhlükəsiz Cloudflare-origin və exposure auditoru.

NƏ EDİR
- Passive recon (crt.sh, CertSpotter, URLScan, AlienVault, HackerTarget, Wayback, ThreatMiner, Anubis, RapidDNS, BufferOver)
- DNS/MX/SPF/NS analizi
- TLS SAN, TLS versiya/cipher analizi
- Technology fingerprint, JS endpoint extraction, favicon hash
- Baseline + multi-path verify engine
- Safe posture audit (headers, panels, public sensitive paths)
- Found IP safe audit (non-intrusive)
- Cache + TTL + state/resume
- Discovery confidence + origin confidence split scoring
- Prioritized non-CF exposure, anomaly detection, Markdown report
- --full rejimində maksimum təhlükəsiz coverage

NƏ ETMİR
- bruteforce
- auth bypass
- exploit automation
- destructive fuzzing
- stealth / bypass
- payload-based active exploitation

Yalnız icazəli sistemlər üçün istifadə edin.
"""

import sys
import os
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
import base64
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────────────────────
# Terminal rənglər
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
{C.RESET}{C.DIM}  CF-HUNTER v7.2 SAFE — Safer, Smarter, Stronger Analysis{C.RESET}
""")

# ──────────────────────────────────────────────────────────────
# Cache
# ──────────────────────────────────────────────────────────────
class Cache:
    def __init__(self, enabled=True, ttl=21600, cache_dir=".cfhunter_cache"):
        self.enabled = enabled
        self.ttl = ttl
        self.cache_dir = Path(cache_dir)
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{h}.json"

    def get(self, key):
        if not self.enabled:
            return None
        p = self._key_path(key)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if time.time() - data.get("ts", 0) > self.ttl:
                return None
            return data.get("value")
        except Exception:
            return None

    def set(self, key, value):
        if not self.enabled:
            return
        p = self._key_path(key)
        try:
            p.write_text(json.dumps({"ts": time.time(), "value": value}, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

# ──────────────────────────────────────────────────────────────
# Provider / trust
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
    "multi-path-match": ("DIRECT", 5),
    "urlscan.io":    ("VERIFIED_API", 2),
    "alienvault-otx":("VERIFIED_API", 2),
    "shodan-idb":    ("VERIFIED_API", 2),
    "crtsh":         ("VERIFIED_API", 2),
    "certspotter":   ("VERIFIED_API", 2),
    "hackertarget":  ("VERIFIED_API", 2),
    "bgpview":       ("VERIFIED_API", 2),
    "ipinfo":        ("VERIFIED_API", 2),
    "github-leak":   ("VERIFIED_API", 2),
    "wayback":       ("SCRAPED", 1),
    "threatminer":   ("SCRAPED", 1),
    "anubis":        ("SCRAPED", 1),
    "rapiddns":      ("SCRAPED", 1),
    "bufferover":    ("SCRAPED", 1),
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

PRIORITY_SUBDOMAIN_HINTS = {
    "admin": 5, "panel": 5, "cpanel": 5, "whm": 5, "grafana": 5, "kibana": 5,
    "jenkins": 5, "gitlab": 5, "api": 4, "gateway": 4, "auth": 4, "sso": 4,
    "mail": 4, "webmail": 4, "mx": 4, "dev": 3, "stage": 3, "staging": 3,
    "test": 2, "beta": 2, "status": 3, "monitor": 3, "metrics": 3,
}
DEFAULT_VERIFY_PATHS = ["/", "/robots.txt", "/favicon.ico", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"]
FULL_VERIFY_PATHS = ["/", "/robots.txt", "/favicon.ico", "/sitemap.xml", "/security.txt", "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml"]

class StateStore:
    def __init__(self, domain, enabled=True, state_dir=".cfhunter_state"):
        self.enabled = enabled
        self.domain = domain
        self.state_dir = Path(state_dir)
        if self.enabled:
            self.state_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain)
        self.path = self.state_dir / f"{safe}.json"

    def load(self):
        if not self.enabled or not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save(self, data):
        if not self.enabled:
            return
        try:
            self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

def rank_subdomain(sub):
    host = sub.split(".")[0].lower()
    score = 0
    for k, v in PRIORITY_SUBDOMAIN_HINTS.items():
        if k in host:
            score = max(score, v)
    return score

def analyze_provider_anomaly(sub_to_ips, domain, ip_enrich):
    anomalies = []
    for sub, ips in sub_to_ips.items():
        if not ips:
            continue
        providers = set()
        for ip in ips:
            enrich = ip_enrich.get(ip, {})
            provider = enrich.get("cloud") or "Unknown"
            if not is_cloudflare(ip) and not is_private(ip):
                providers.add(provider)
        if not providers:
            continue
        prio = rank_subdomain(sub)
        if prio >= 4:
            anomalies.append({
                "subdomain": sub,
                "priority": prio,
                "providers": sorted(providers),
                "reason": "yüksək həssas host non-CF infrastrukturda görünür"
            })
        elif len(providers) > 1:
            anomalies.append({
                "subdomain": sub,
                "priority": prio,
                "providers": sorted(providers),
                "reason": "eyni host üçün müxtəlif provider izləri var"
            })
    anomalies.sort(key=lambda x: (x["priority"], len(x["providers"])), reverse=True)
    return anomalies[:50]

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

# ──────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CF-Hunter/7.2-safe",
    "Accept": "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

PROBE_TIMEOUT = 6
PROBE_RETRIES = 2
PROBE_BACKOFF = 0.8
PROBE_USER_AGENTS = [
    _HEADERS["User-Agent"],
    "curl/8.5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]

def http_get(url, timeout=12, retries=1, cache=None):
    cache_key = f"GET_TEXT::{url}::{timeout}"
    if cache:
        hit = cache.get(cache_key)
        if hit is not None:
            return hit
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=_HEADERS)
            with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                body = r.read().decode("utf-8", errors="replace")
                if cache:
                    cache.set(cache_key, body)
                return body
        except Exception:
            if attempt < retries:
                time.sleep(0.8)
    return None

def http_get_bytes(url, timeout=10, cache=None):
    cache_key = f"GET_BYTES::{url}::{timeout}"
    if cache:
        hit = cache.get(cache_key)
        if hit is not None:
            try:
                return base64.b64decode(hit.encode())
            except Exception:
                pass
    try:
        req = Request(url, headers=_HEADERS)
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            data = r.read()
            if cache:
                cache.set(cache_key, base64.b64encode(data).decode())
            return data
    except Exception:
        return None

def http_json(url, timeout=12, retries=1, cache=None):
    raw = http_get(url, timeout=timeout, retries=retries, cache=cache)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None

def http_get_with_headers(url, timeout=12, cache=None):
    cache_key = f"GET_HDR::{url}::{timeout}"
    if cache:
        hit = cache.get(cache_key)
        if hit is not None:
            return tuple(hit)
    try:
        req = Request(url, headers=_HEADERS)
        with urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            body = r.read().decode("utf-8", errors="replace")
            result = (body, dict(r.headers), getattr(r, "status", 200))
            if cache:
                cache.set(cache_key, result)
            return result
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        result = (body, dict(e.headers or {}), e.code)
        if cache:
            cache.set(cache_key, result)
        return result
    except Exception:
        return (None, {}, None)

def follow_redirects(url, limit=5, timeout=10):
    chain = []
    current = url
    for _ in range(limit):
        body, headers, status = http_get_with_headers(current, timeout=timeout)
        chain.append({"url": current, "status": status, "location": (headers or {}).get("Location") or (headers or {}).get("location", "")})
        loc = (headers or {}).get("Location") or (headers or {}).get("location", "")
        if status in (301, 302, 303, 307, 308) and loc:
            if loc.startswith("//"):
                parsed = urlparse(current)
                current = parsed.scheme + ":" + loc
            elif loc.startswith("/"):
                parsed = urlparse(current)
                current = f"{parsed.scheme}://{parsed.netloc}{loc}"
            elif loc.startswith("http"):
                current = loc
            else:
                parsed = urlparse(current)
                base = f"{parsed.scheme}://{parsed.netloc}"
                current = base + "/" + loc
        else:
            break
    return chain

# ──────────────────────────────────────────────────────────────
# Low-level verify
# ──────────────────────────────────────────────────────────────

def body_bucket(text):
    n = len(text or "")
    if n == 0:
        return "0"
    if n < 256:
        return "tiny"
    if n < 2048:
        return "small"
    if n < 16384:
        return "medium"
    return "large"

def error_class(err):
    s = (err or "").lower()
    if not s:
        return "none"
    if "timed out" in s or "timeout" in s:
        return "timeout"
    if "network is unreachable" in s:
        return "network-unreachable"
    if "handshake" in s or "_ssl" in s or "tls" in s:
        return "tls"
    if "empty response" in s:
        return "empty"
    if "refused" in s:
        return "refused"
    return "other"

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
        "scheme": scheme,
        "ip": ip,
        "host": host,
        "path": path,
        "ok": False,
        "status": None,
        "server": "",
        "location": "",
        "title": "",
        "body_hash": "",
        "headers": {},
        "sample": "",
        "error": "",
        "error_class": "",
        "body_bucket": "0",
        "set_cookie": False,
        "powered_by": "",
        "attempts": 0,
        "cf_like": False,
        "squid_like": False,
    }
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    p = port or (443 if scheme == "https" else 80)
    last_error = ""
    for attempt in range(PROBE_RETRIES + 1):
        ua = PROBE_USER_AGENTS[min(attempt, len(PROBE_USER_AGENTS) - 1)]
        result["attempts"] += 1
        try:
            sock = socket.socket(fam, socket.SOCK_STREAM)
            sock.settimeout(PROBE_TIMEOUT + attempt)
            sock.connect((ip, p))
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            sock.sendall(req)
            raw = recv_all(sock)
            try:
                sock.close()
            except Exception:
                pass
            if not raw:
                last_error = "empty response"
                if attempt < PROBE_RETRIES:
                    time.sleep(PROBE_BACKOFF * (attempt + 1))
                    continue
                result["error"] = last_error
                result["error_class"] = error_class(last_error)
                return result

            text_raw = raw.decode("utf-8", errors="replace")
            head, _, body = text_raw.partition("\r\n\r\n")
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
            result["body_bucket"] = body_bucket(body)
            result["set_cookie"] = "set-cookie" in headers
            result["powered_by"] = headers.get("x-powered-by", "")[:80]
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
                ("generated by" in body_l and "squid" in body_l) or
                ("invalid url" in body_l and "cache administrator" in body_l)
            )
            result["ok"] = True
            result["error_class"] = "none"
            return result
        except Exception as e:
            last_error = str(e)
            if attempt < PROBE_RETRIES:
                time.sleep(PROBE_BACKOFF * (attempt + 1))
                continue
    result["error"] = last_error
    result["error_class"] = error_class(last_error)
    return result

def normalize_headers(headers):
    bad = {"date", "set-cookie", "cf-ray", "report-to", "nel", "alt-svc", "content-length"}
    return {k.lower(): v for k, v in headers.items() if k.lower() not in bad}


def fingerprint_response(probe):
    if not probe or not probe.get("ok"):
        return {
            "status": None,
            "server": "",
            "title": "",
            "body_hash": "",
            "header_keys": [],
            "location": "",
            "body_bucket": "0",
            "set_cookie": False,
            "powered_by": "",
            "error_class": probe.get("error_class", "") if probe else "",
        }
    hdrs = normalize_headers(probe.get("headers", {}))
    location = probe.get("location", "")
    if location:
        try:
            parsed = urlparse(location)
            location = (parsed.netloc or parsed.path or location)[:80]
        except Exception:
            location = location[:80]
    return {
        "status": probe.get("status"),
        "server": probe.get("server", "")[:80],
        "title": probe.get("title", "")[:120],
        "body_hash": probe.get("body_hash", ""),
        "header_keys": sorted(list(hdrs.keys()))[:20],
        "location": location,
        "body_bucket": probe.get("body_bucket", "0"),
        "set_cookie": bool(probe.get("set_cookie")),
        "powered_by": probe.get("powered_by", ""),
        "error_class": probe.get("error_class", ""),
    }


def compare_fingerprints(a, b):
    score = 0
    reasons = []
    if not a or not b:
        return score, reasons
    if a.get("status") and b.get("status") and a["status"] == b["status"]:
        score += 2
        reasons.append("status match")
    if a.get("title") and b.get("title") and a["title"] == b["title"]:
        score += 4
        reasons.append("title match")
    if a.get("body_hash") and b.get("body_hash") and a["body_hash"] == b["body_hash"]:
        score += 6
        reasons.append("body hash match")
    if a.get("location") and b.get("location") and a["location"] == b["location"]:
        score += 2
        reasons.append("redirect target match")
    if a.get("body_bucket") and b.get("body_bucket") and a["body_bucket"] == b["body_bucket"]:
        score += 1
        reasons.append("body size bucket match")
    if a.get("set_cookie") == b.get("set_cookie"):
        score += 1
        reasons.append("cookie behavior match")
    if a.get("powered_by") and b.get("powered_by") and a["powered_by"] == b["powered_by"]:
        score += 2
        reasons.append("powered-by match")
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

DEFAULT_VERIFY_PATHS = ["/", "/robots.txt", "/favicon.ico", "/sitemap.xml"]

def build_public_baselines(domain, paths=None, cache=None):
    paths = paths or DEFAULT_VERIFY_PATHS
    base = {"http": {}, "https": {}}
    for scheme in ("http", "https"):
        for path in paths:
            body, headers, status = http_get_with_headers(f"{scheme}://{domain}{path}", timeout=10, cache=cache)
            title = ""
            if body:
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                title = m.group(1).strip()[:120] if m else ""
            fp = {
                "status": status,
                "server": (headers or {}).get("Server", "") or (headers or {}).get("server", ""),
                "title": title,
                "body_hash": hashlib.sha256((body or "")[:8192].encode()).hexdigest()[:16],
                "header_keys": sorted(list(normalize_headers({k.lower(): v for k, v in (headers or {}).items()}).keys()))[:20],
            }
            base[scheme][path] = fp
    return base


def verify_candidate_multi(ip, domain, baselines, paths=None):
    paths = paths or DEFAULT_VERIFY_PATHS
    verdict = {
        "ip": ip,
        "score": 0,
        "verdict": "UNCONFIRMED",
        "confidence_label": "LOW",
        "reasons": [],
        "paths": {"http": {}, "https": {}},
        "matches": 0,
        "errors": {"timeout": 0, "tls": 0, "empty": 0, "network-unreachable": 0, "other": 0},
        "ok_count": 0,
    }
    for scheme in ("http", "https"):
        for path in paths:
            probe = http_probe_ip(ip, domain, scheme=scheme, path=path)
            fp = fingerprint_response(probe)
            verdict["paths"][scheme][path] = fp
            ecls = probe.get("error_class") or "other"
            if ecls != "none":
                verdict["errors"][ecls] = verdict["errors"].get(ecls, 0) + 1
            if probe.get("ok") and probe.get("status"):
                verdict["ok_count"] += 1
                verdict["score"] += 1 if scheme == "http" else 2
            if probe.get("cf_like"):
                verdict["score"] -= 4
                verdict["reasons"].append(f"{scheme}{path}: cloudflare-like")
            if probe.get("squid_like"):
                verdict["score"] -= 3
                verdict["reasons"].append(f"{scheme}{path}: proxy-like")
            bs = (baselines.get(scheme) or {}).get(path, {})
            s, rs = compare_fingerprints(bs, fp)
            if s > 0:
                verdict["score"] += s
                verdict["matches"] += 1
                verdict["reasons"].append(f"{scheme}{path}: baseline match")
                verdict["reasons"].extend([f"{scheme}{path}: {x}" for x in rs])

    if verdict["matches"] >= 2:
        verdict["score"] += 4
        verdict["reasons"].append("multi-path corroboration")

    timeoutish = verdict["errors"].get("timeout", 0) + verdict["errors"].get("tls", 0) + verdict["errors"].get("empty", 0)
    if verdict["matches"] >= 3 or verdict["score"] >= 16:
        verdict["verdict"] = "LIKELY_ORIGIN"
    elif verdict["matches"] >= 1 or verdict["score"] >= 7:
        verdict["verdict"] = "POSSIBLE"
    elif timeoutish >= max(2, len(paths) // 2) and verdict["ok_count"] == 0:
        verdict["verdict"] = "LIKELY_BLOCKED_ORIGIN"
        verdict["reasons"].append("non-matching but consistently blocked/timed out")
    else:
        verdict["verdict"] = "EDGE_OR_PROXY"

    if verdict["score"] >= 18:
        verdict["confidence_label"] = "HIGH"
    elif verdict["score"] >= 9 or verdict["verdict"] == "LIKELY_BLOCKED_ORIGIN":
        verdict["confidence_label"] = "MEDIUM"
    else:
        verdict["confidence_label"] = "LOW"
    return verdict

# ──────────────────────────────────────────────────────────────
# Collectors / enrichers# ──────────────────────────────────────────────────────────────
# Collectors / enrichers
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

def src_crtsh(domain, col, cache=None):
    for url in [f"https://crt.sh/?q=%.{domain}&output=json", f"https://crt.sh/?q={domain}&output=json"]:
        data = http_json(url, timeout=20, cache=cache)
        if not data:
            continue
        for entry in data:
            for field in ("name_value", "common_name"):
                for line in entry.get(field, "").replace(",", "\n").split("\n"):
                    col.add(line.strip())

def src_certspotter(domain, col, cache=None):
    data = http_json(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", timeout=15, cache=cache)
    if data and isinstance(data, list):
        for cert in data:
            for name in cert.get("dns_names", []):
                col.add(name)

def src_alienvault(domain, col, cache=None):
    ips = []
    d = http_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=12, cache=cache)
    if d:
        for e in d.get("passive_dns", []):
            a = e.get("address", "")
            if is_valid_ip(a) and a not in ips:
                ips.append(a)
    return ips

def src_hackertarget(domain, col, cache=None):
    ips = []
    raw = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12, cache=cache)
    if raw and "error" not in raw.lower() and "API count" not in raw:
        for line in raw.strip().split("\n"):
            parts = line.split(",")
            if len(parts) >= 2:
                col.add(parts[0].strip())
                ip = parts[1].strip()
                if is_valid_ip(ip) and ip not in ips:
                    ips.append(ip)
    return ips

def src_urlscan(domain, col, cache=None):
    ips = []
    data = http_json(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=15, cache=cache)
    if data:
        for r in data.get("results", []):
            ip = r.get("page", {}).get("ip", "")
            if is_valid_ip(ip) and ip not in ips:
                ips.append(ip)
            h = r.get("page", {}).get("domain", "")
            if h:
                col.add(h)
    return ips

def src_wayback(domain, col, cache=None):
    data = http_json(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500", timeout=20, cache=cache)
    if data and len(data) > 1:
        pat = re.compile(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')')
        for row in data[1:]:
            if row:
                m = pat.search(row[0])
                if m:
                    col.add(m.group(1))

def src_threatminer(domain, col, cache=None):
    data = http_json(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=12, cache=cache)
    if data:
        for s in data.get("results", []):
            col.add(s)

def src_anubis(domain, col, cache=None):
    data = http_json(f"https://jldc.me/anubis/subdomains/{domain}", timeout=12, cache=cache)
    if data and isinstance(data, list):
        for s in data:
            col.add(s)

def src_rapiddns(domain, col, cache=None):
    raw = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15, cache=cache)
    if raw:
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        for s in re.findall(pattern, raw):
            col.add(s)

def src_bufferover(domain, col, cache=None):
    data = http_json(f"https://tls.bufferover.run/dns?q=.{domain}", timeout=10, cache=cache)
    if data:
        for line in data.get("Results", []) or []:
            parts = line.split(",")
            if len(parts) >= 4:
                col.add(parts[3].strip())

def bgpview_lookup(ip, cache=None):
    d = http_json(f"https://api.bgpview.io/ip/{ip}", timeout=10, cache=cache)
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

def ipapi_info(ip, cache=None):
    d = http_json(f"http://ip-api.com/json/{ip}?fields=status,org,isp,country,city,hosting,proxy,mobile", timeout=8, cache=cache)
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

def ip_info(ip, cache=None):
    d = http_json(f"https://ipinfo.io/{ip}/json", timeout=8, cache=cache)
    if d:
        return {"org": d.get("org", "?"), "city": d.get("city", "?"), "country": d.get("country", "?"), "hostname": d.get("hostname", "")}
    return {"org": "?", "city": "?", "country": "?", "hostname": ""}

def reverse_ip_lookup(ip, cache=None):
    raw = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12, cache=cache)
    if not raw or "error" in raw.lower() or "API count" in raw:
        return []
    return [d.strip() for d in raw.strip().split("\n") if d.strip()][:50]

def shodan_info(ip, cache=None):
    d = http_json(f"https://internetdb.shodan.io/{ip}", timeout=8, cache=cache)
    if d and "detail" not in str(d).lower():
        return d
    return None

def doh_query(name, rtype, cache=None):
    data = http_json(f"https://dns.google/resolve?name={quote(name)}&type={rtype}", timeout=10, cache=cache)
    return data.get("Answer", []) if data else []

def dns_records_analysis(domain, cache=None):
    out = {"mx": [], "mx_ips": [], "spf_ips": [], "ns": [], "txt": []}
    for a in doh_query(domain, "MX", cache=cache):
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
    for a in doh_query(domain, "TXT", cache=cache):
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
    for a in doh_query(domain, "NS", cache=cache):
        ns = a.get("data", "").rstrip(".")
        if ns and ns not in out["ns"]:
            out["ns"].append(ns)
    return out

def try_zone_transfer(domain, ns_list):
    subs = []
    try:
        import dns.query, dns.zone  # type: ignore
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

# ──────────────────────────────────────────────────────────────
# v5 extras
# ──────────────────────────────────────────────────────────────
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

def extract_js_endpoints(base_url, html, max_scripts=5, cache=None):
    endpoints = set()
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html or "", re.IGNORECASE)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for src in script_srcs[:max_scripts]:
        if src.startswith("//"):
            src = parsed.scheme + ":" + src
        elif src.startswith("/"):
            src = base + src
        elif not src.startswith("http"):
            src = base + "/" + src
        js_body = http_get(src, timeout=10, retries=1, cache=cache)
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
    good = [ep for ep in endpoints if any(kw in ep.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/auth/", "/admin", "/config", "/internal"])]
    return sorted(good)[:50]

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

def favicon_hash(domain, cache=None):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/favicon.ico"
        data = http_get_bytes(url, timeout=8, cache=cache)
        if data and len(data) > 10:
            b64 = base64.encodebytes(data).decode()
            mmh = _murmur3_32(b64.encode())
            md5 = hashlib.md5(data).hexdigest()
            return {"url": url, "size": len(data), "mmh3": mmh, "md5": md5, "shodan_query": f"http.favicon.hash:{mmh}"}
    return {}

GITHUB_SAFE_QUERIES = ["{domain}", "{domain} password", "{domain} config", "{domain} api_key"]
def github_leak_scan(domain, cache=None):
    findings = []
    seen_repos = set()
    for q_template in GITHUB_SAFE_QUERIES:
        q = quote(q_template.format(domain=domain))
        url = f"https://api.github.com/search/code?q={q}&per_page=10"
        data = http_json(url, timeout=12, cache=cache)
        if not data or "items" not in data:
            break
        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            fname = item.get("name", "")
            furl = item.get("html_url", "")
            if repo and repo not in seen_repos:
                seen_repos.add(repo)
                findings.append({"repo": repo, "file": fname, "url": furl, "query": q_template.format(domain=domain)})
        time.sleep(0.8)
    return findings

# ──────────────────────────────────────────────────────────────
# v6 posture + found-IP safe audit
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
    "/admin", "/login", "/user/login", "/dashboard", "/cpanel", "/whm", "/phpmyadmin",
    "/grafana", "/jenkins", "/manager/html", "/actuator", "/health", "/status"
]
SAFE_SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/server-status", "/nginx_status", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.git/config", "/.env", "/version"
]

def classify_path_exposure(path, status, headers, body):
    body_l = (body or "").lower()
    server = (headers or {}).get("server", "") if headers else ""
    title_m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    title = title_m.group(1).strip()[:120] if title_m else ""
    findings = []
    severity = "info"
    if status in (200, 401, 403):
        findings.append("reachable")
    if path in ("/server-status", "/nginx_status") and status == 200:
        severity = "high"
        findings.append("status endpoint exposed")
    if path in ("/.git/config", "/.env") and status == 200:
        severity = "high"
        findings.append("sensitive file exposed")
    if "phpmyadmin" in path and status in (200, 401):
        severity = "medium"
        findings.append("admin interface visible")
    if any(k in body_l for k in ["apache server status", "active connections", "nginx stub status"]):
        severity = "high"
        findings.append("operational metrics exposed")
    if any(k in title.lower() for k in ["login", "admin", "dashboard", "phpmyadmin", "cpanel", "grafana", "jenkins"]):
        severity = "medium" if severity == "info" else severity
        findings.append(f"title: {title}")
    if "index of /" in body_l:
        severity = "high"
        findings.append("directory listing")
    if path == "/version" and status == 200 and body_l.strip():
        findings.append("version endpoint exposed")
    if "server-status" in path and server:
        findings.append(f"server:{server}")
    return {"path": path, "status": status, "title": title, "severity": severity, "findings": findings}

def fetch_path(base_url, path, timeout=8, cache=None):
    body, headers, status = http_get_with_headers(base_url.rstrip("/") + path, timeout=timeout, cache=cache)
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

def quick_http_meta(base_url, cache=None):
    body, headers, status = http_get_with_headers(base_url, timeout=10, cache=cache)
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

def run_safe_posture_checks(domain, max_workers=10, cache=None):
    base_https = f"https://{domain}"
    base_http = f"http://{domain}"
    meta_https = quick_http_meta(base_https, cache=cache)
    meta_http = quick_http_meta(base_http, cache=cache)
    hdr_report = security_headers_report(meta_https["headers"] if meta_https.get("headers") else meta_http.get("headers"))
    targets = SAFE_PANEL_PATHS + SAFE_SENSITIVE_PATHS
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(fetch_path, base_https, p, 8, cache) for p in targets]
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                pass
    interesting = [r for r in results if r["status"] in (200, 401, 403)]
    high = [r for r in interesting if r["severity"] == "high"]
    medium = [r for r in interesting if r["severity"] == "medium"]
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
        "redirect_chain_http": follow_redirects(base_http),
        "redirect_chain_https": follow_redirects(base_https),
    }

def safe_ip_audit(ip, host_hint, cache=None):
    result = {
        "ip": ip,
        "ports": {},
        "http_meta": {},
        "https_meta": {},
        "security_headers": {},
        "interesting_paths": [],
        "tls": {},
        "technology": [],
        "redirects": {},
        "risk_score": 0,
        "risk_level": "LOW",
    }
    http_r = http_probe_ip(ip, host_hint, scheme="http", path="/")
    https_r = http_probe_ip(ip, host_hint, scheme="https", path="/")
    result["ports"] = {
        "80": http_r.get("status") is not None,
        "443": https_r.get("status") is not None,
    }
    result["http_meta"] = fingerprint_response(http_r)
    result["https_meta"] = fingerprint_response(https_r)

    hdr_src = https_r.get("headers") or http_r.get("headers") or {}
    result["security_headers"] = security_headers_report(hdr_src)
    body_for_tech = (https_r.get("sample") or "") + "\n"
    result["technology"] = list(detect_technology(body_for_tech, hdr_src).keys())

    # safe path checks directly on IP with host header
    interesting = []
    for path in ["/robots.txt", "/sitemap.xml", "/admin", "/login", "/dashboard", "/server-status", "/nginx_status", "/.git/config", "/.env", "/version"]:
        scheme = "https" if result["ports"]["443"] else "http"
        probe = http_probe_ip(ip, host_hint, scheme=scheme, path=path)
        if probe.get("status") in (200, 401, 403):
            interesting.append(classify_path_exposure(path, probe.get("status"), probe.get("headers"), probe.get("sample")))

    result["interesting_paths"] = interesting
    tls = {}
    try:
        tls = tls_analyze(ip)
    except Exception:
        tls = {}
    result["tls"] = tls
    risk = 0
    risk += len([x for x in interesting if x["severity"] == "high"]) * 4
    risk += len([x for x in interesting if x["severity"] == "medium"]) * 2
    risk += max(0, len(result["security_headers"]["missing"]) - 2)
    if tls.get("weak"):
        risk += 3
    if result["technology"]:
        risk += 1
    result["risk_score"] = risk
    if risk >= 12:
        result["risk_level"] = "HIGH"
    elif risk >= 6:
        result["risk_level"] = "MEDIUM"
    return result

# ──────────────────────────────────────────────────────────────
# Resolution
# ──────────────────────────────────────────────────────────────
WORDLIST = [
    "www","www2","www3","web","mail","smtp","mx","webmail","admin","panel","cpanel","whm","plesk",
    "dev","staging","stage","test","beta","api","api2","api-v1","api-v2","rest","graphql","gateway",
    "cdn","static","assets","img","media","upload","downloads","storage","db","redis","mongo","elastic",
    "secure","auth","sso","app","mobile","m","monitor","status","metrics","forum","blog","shop","pay",
    "support","help","wiki","ftp","sftp","ssh","backup","prod","production","common","grafana","jenkins"
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

# ──────────────────────────────────────────────────────────────
# Scoring / correlation
# ──────────────────────────────────────────────────────────────
def confidence_score(sources, cloud=None, verify=None, rdns_count=0, safe_audit=None, priority=0):
    _, _, total = score_split(sources, cloud=cloud, verify=verify, rdns_count=rdns_count, safe_audit=safe_audit, priority=priority)
    return total

def explain_ip(sources, verify=None, cloud=None, rdns_count=0, safe_audit=None, priority=0):
    reasons = []
    if verify and verify.get("verdict") == "LIKELY_ORIGIN":
        reasons.append("multi-path verify uyğunluğu güclüdür")
    elif verify and verify.get("verdict") == "POSSIBLE":
        reasons.append("qismən multi-path verify uyğunluğu var")
    elif verify and verify.get("verdict") == "LIKELY_BLOCKED_ORIGIN":
        reasons.append("birbaşa cavab vermir, amma origin-blok davranışı göstərə bilər")
    if any(s.startswith("sub:") for s in sources):
        reasons.append("non-CF subdomain üzərindən görünür")
    if "tls-san" in sources:
        reasons.append("TLS SAN əlaqəsi mövcuddur")
    if "mx-record" in sources or "spf-record" in sources:
        reasons.append("mail/DNS infrastrukturu ilə əlaqə var")
    if safe_audit and safe_audit.get("risk_score", 0) >= 8:
        reasons.append("tapılan IP üzərində təhlükəsiz exposure siqnalları var")
    if priority >= 4:
        reasons.append("yüksək həssas host prioriteti daşıyır")
    if cloud in EDGE_PROVIDERS:
        reasons.append("edge/CDN provideri olduğu üçün mənfi siqnal")
    if rdns_count > 20:
        reasons.append("çox shared host görünür")
    return reasons[:6]


def score_split(sources, cloud=None, verify=None, rdns_count=0, safe_audit=None, priority=0):
    s = set(sources)
    discovery = 0
    origin = 0
    direct = 0
    verified = 0
    for src in s:
        tier, weight = source_trust(src)
        discovery += weight
        if tier == "DIRECT":
            direct += 1
        elif tier == "VERIFIED_API":
            verified += 1
    has_sub = any(x.startswith("sub:") for x in s)
    has_mail = ("mx-record" in s or "spf-record" in s)
    if has_sub:
        discovery += 2
        origin += 2
    if direct >= 2:
        discovery += 3
        origin += 2
    elif direct >= 1 and verified >= 1:
        discovery += 2
        origin += 1
    if verify:
        origin += max(0, verify.get("score", 0))
        if verify.get("verdict") == "LIKELY_ORIGIN":
            origin += 5
        elif verify.get("verdict") == "POSSIBLE":
            origin += 2
        elif verify.get("verdict") == "LIKELY_BLOCKED_ORIGIN":
            origin += 1
    if safe_audit:
        risk = safe_audit.get("risk_score", 0)
        discovery += min(4, risk // 3)
    if has_mail and not has_sub:
        origin -= 3
    if priority:
        discovery += min(3, priority)
        origin += min(2, priority)
    if rdns_count:
        penalty = min(5, rdns_count // 8)
        discovery -= penalty
        origin -= penalty
    if cloud in EDGE_PROVIDERS:
        origin -= 8
    elif cloud in {"AWS", "GCP", "Azure", "DigitalOcean", "Vultr", "Hetzner", "OVH", "Linode"}:
        origin += 1
    return discovery, origin, discovery + origin

def build_text_summary(domain, posture, anomalies, origin_candidates):
    lines = []
    lines.append(f"Hədəf: {domain}")
    lines.append(f"Public risk: {posture.get('risk_level')} ({posture.get('risk_score')})")
    lines.append(f"Anomaliya sayı: {len(anomalies)}")
    preferred = None
    for ip, data in origin_candidates:
        if data.get("role") != "mail-related":
            preferred = (ip, data)
            break
    if preferred:
        top = preferred[1]
        lines.append(f"Ən güclü origin namizədi: {preferred[0]} | role={top.get('role')} | score={top.get('confidence_score')}")
    elif origin_candidates:
        lines.append("Güclü origin namizədi yoxdur; yalnız zəif/mail tipli siqnallar qalıb")
    else:
        lines.append("Güclü origin namizədi tapılmadı")
    return " | ".join(lines)

def build_markdown_report(result):
    meta = result.get("meta", {})
    posture = result.get("public_posture", {})
    candidates = result.get("origin_candidates", [])
    anomalies = result.get("anomalies", [])
    lines = []
    lines.append(f"# CF-HUNTER v7.2 SAFE report")
    lines.append("")
    lines.append(f"- Domain: `{meta.get('domain','')}`")
    lines.append(f"- Full mode: `{meta.get('full_mode', False)}`")
    lines.append(f"- Elapsed: `{meta.get('elapsed_seconds','?')}s`")
    lines.append(f"- Generated at: `{meta.get('generated_at','')}`")
    lines.append("")
    lines.append("## Public posture")
    lines.append(f"- Risk: **{posture.get('risk_level','UNKNOWN')}** ({posture.get('risk_score',0)})")
    hdrs = posture.get("security_headers", {})
    missing = hdrs.get("missing", [])
    lines.append(f"- Missing security headers: {', '.join(missing) if missing else 'yoxdur'}")
    lines.append("")
    lines.append("## Prioritet anomaliyalar")
    if anomalies:
        for a in anomalies[:15]:
            lines.append(f"- `{a['subdomain']}` | priority={a['priority']} | providers={', '.join(a['providers'])} | {a['reason']}")
    else:
        lines.append("- Tapılmadı")
    lines.append("")
    lines.append("## Güclü origin namizədləri")
    if candidates:
        for c in candidates[:20]:
            lines.append(f"- `{c['ip']}` | role={c['role']} | confidence={c.get('confidence_score',0)} | discovery={c.get('discovery_score',0)} | origin={c.get('origin_score',0)} | verify={c.get('verify',{}).get('verdict','-')}")
            if c.get("explanation"):
                lines.append(f"  - İzah: {'; '.join(c['explanation'])}")
    else:
        lines.append("- Tapılmadı")
    lines.append("")
    lines.append("## Technology")
    tech = result.get("technology", [])
    lines.append(f"- {', '.join(tech) if tech else 'Tapılmadı'}")
    lines.append("")
    lines.append("## JS endpoints")
    js = result.get("js_endpoints", [])
    for ep in js[:20]:
        lines.append(f"- `{ep}`")
    if not js:
        lines.append("- Tapılmadı")
    return "\n".join(lines)
class CorrelationEngine:
    def __init__(self, domain):
        self.domain = domain
        self.ips = {}

    def add_ip(self, ip, sources, bgp=None, ipapi=None, rdns=None, cloud=None, verify=None, safe_audit=None, priority=0, related_subdomains=None):
        self.ips[ip] = {
            "ip": ip,
            "sources": sorted(set(sources)),
            "bgp": bgp or {},
            "ipapi": ipapi or {},
            "rdns_domains": rdns or [],
            "cloud": cloud,
            "verify": verify or {},
            "safe_audit": safe_audit or {},
            "priority": priority,
            "related_subdomains": related_subdomains or [],
            "role": self.classify_role(ip, sources, cloud, verify, rdns or []),
        }

    def classify_role(self, ip, sources, cloud, verify, rdns):
        s = set(sources)
        if is_cloudflare(ip):
            return "cloudflare-edge"
        if cloud in EDGE_PROVIDERS:
            return "other-edge-or-waf"
        if verify and verify.get("verdict") == "LIKELY_ORIGIN":
            return "likely-origin"
        if verify and verify.get("verdict") == "LIKELY_BLOCKED_ORIGIN" and any(x.startswith("sub:") for x in s):
            return "possible-blocked-origin"
        if any(x.startswith("sub:") for x in s):
            return "subdomain-exposed"
        if "mx-record" in s or "spf-record" in s:
            return "mail-related"
        if rdns and len(rdns) > 25:
            return "shared-host"
        return "candidate"

    def origin_candidates(self):
        ranked = []
        for ip, data in self.ips.items():
            discovery, origin, total = score_split(
                data["sources"],
                cloud=data.get("cloud"),
                verify=data.get("verify"),
                rdns_count=len(data.get("rdns_domains") or []),
                safe_audit=data.get("safe_audit"),
                priority=data.get("priority", 0),
            )
            data["discovery_score"] = discovery
            data["origin_score"] = origin
            data["confidence_score"] = total
            ranked.append((ip, data))
        ranked.sort(key=lambda x: (x[1].get("confidence_score", 0), x[1].get("origin_score", 0)), reverse=True)
        return [x for x in ranked if x[1]["role"] in {"likely-origin", "possible-blocked-origin", "subdomain-exposed", "candidate"} or (x[1]["role"] == "mail-related" and x[1].get("origin_score", 0) >= 6)]

    def get_summary(self):
        out = {}
        for _, data in self.ips.items():
            out.setdefault(data["role"], []).append(data["ip"])
        return out

# ──────────────────────────────────────────────────────────────
# Main analyze
# ──────────────────────────────────────────────────────────────
def analyze(domain, output_file=None, verbose=False, skip_github=False, skip_verify=False,
            verify_workers=10, resolve_workers=60, posture_workers=10, full=False,
            cache_enabled=True, cache_ttl=21600, resume=True, write_md=False,
            probe_timeout=6, probe_retries=2):
    global PROBE_TIMEOUT, PROBE_RETRIES
    PROBE_TIMEOUT = max(3, int(probe_timeout))
    PROBE_RETRIES = max(0, int(probe_retries))
    t0 = time.time()
    cache = Cache(enabled=cache_enabled, ttl=cache_ttl)

    all_ips = {}      # ip -> sources
    sub_to_ips = {}
    verify_results = {}
    ip_enrich = {}
    safe_ip_audits = {}
    source_health = {}
    ip_to_related_subs = {}
    state = StateStore(domain, enabled=resume)
    last_state = state.load()

    def add_ip(ip, source):
        if not is_valid_ip(ip):
            return
        all_ips.setdefault(ip, [])
        all_ips[ip].append(source)

    print(f"{C.YELLOW}[01]{C.RESET} Domain normalizasiya...")
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split('?')[0]
    print(f"      hədəf: {C.CYAN}{domain}{C.RESET}")
    state.save({"stage": "normalized", "domain": domain, "ts": time.time()})

    print(f"\n{C.YELLOW}[02]{C.RESET} Passive subdomain collection...")
    col = SubCollector(domain)
    collectors = [
        ("crtsh", lambda: src_crtsh(domain, col, cache=cache)),
        ("certspotter", lambda: src_certspotter(domain, col, cache=cache)),
        ("wayback", lambda: src_wayback(domain, col, cache=cache)),
        ("threatminer", lambda: src_threatminer(domain, col, cache=cache)),
        ("anubis", lambda: src_anubis(domain, col, cache=cache)),
        ("rapiddns", lambda: src_rapiddns(domain, col, cache=cache)),
        ("bufferover", lambda: src_bufferover(domain, col, cache=cache)),
    ]
    for name, fn in collectors:
        try:
            fn()
            source_health[name] = "ok"
        except Exception as e:
            source_health[name] = f"error: {e}"

    subdomains = col.result()
    print(f"      subdomain sayı: {len(subdomains)}")

    print(f"\n{C.YELLOW}[03]{C.RESET} DNS records analizi...")
    dns_data = dns_records_analysis(domain, cache=cache)
    for ip in dns_data["mx_ips"]:
        add_ip(ip, "mx-record")
    for ip in dns_data["spf_ips"]:
        add_ip(ip, "spf-record")
    if verbose:
        print(f"      MX: {dns_data['mx'][:5]}")
        print(f"      NS: {dns_data['ns'][:5]}")

    print(f"\n{C.YELLOW}[04]{C.RESET} Zone transfer (best-effort)...")
    zt_subs = try_zone_transfer(domain, dns_data["ns"])
    for s in zt_subs:
        col.add(s)
    if zt_subs:
        print(f"      zone transfer nəticəsi: {len(zt_subs)} subdomain")

    print(f"\n{C.YELLOW}[05]{C.RESET} Passive IP mənbələri...")
    for name, fn in [
        ("alienvault-otx", lambda: src_alienvault(domain, col, cache=cache)),
        ("hackertarget", lambda: src_hackertarget(domain, col, cache=cache)),
        ("urlscan.io", lambda: src_urlscan(domain, col, cache=cache)),
    ]:
        try:
            ips = fn() or []
            for ip in ips:
                add_ip(ip, name)
            source_health[name] = f"ok ({len(ips)})"
        except Exception as e:
            source_health[name] = f"error: {e}"

    print(f"\n{C.YELLOW}[06]{C.RESET} Wordlist subdomain expansion + resolve...")
    brute = brute_subs(domain)
    all_subs = sorted(set(col.result() + brute), key=lambda s: (rank_subdomain(s), s), reverse=True)
    resolved = resolve_all(all_subs, workers=resolve_workers)
    for sub, ips in resolved.items():
        sub_to_ips[sub] = ips
        for ip in ips:
            add_ip(ip, f"sub:{sub}")
            ip_to_related_subs.setdefault(ip, []).append(sub)
    non_cf_subs = []
    for sub, ips in sub_to_ips.items():
        if any(not is_cloudflare(ip) and not is_private(ip) for ip in ips):
            non_cf_subs.append(sub)
    print(f"      resolved: {len(sub_to_ips)} | non-CF subdomain: {len(non_cf_subs)}")

    print(f"\n{C.YELLOW}[07]{C.RESET} TLS deep analysis...")
    tls_result = tls_analyze(domain)
    tls_sans = []
    if tls_result.get("error"):
        print(f"      {C.DIM}TLS xəta: {tls_result['error']}{C.RESET}")
    else:
        tls_sans = list(set(tls_result.get("sans", [])))
        san_pairs = tls_san_to_ips(tls_sans, domain)
        for san, ip in san_pairs:
            if not is_cloudflare(ip):
                add_ip(ip, "tls-san")
        print(f"      TLS SAN count: {len(tls_sans)}")

    print(f"\n{C.YELLOW}[08]{C.RESET} Baseline + redirect fingerprint...")
    baselines = build_public_baselines(domain, cache=cache)
    redirect_chain_http = follow_redirects(f"http://{domain}")
    redirect_chain_https = follow_redirects(f"https://{domain}")
    print(f"      baseline hazırlandı | redirect HTTP={len(redirect_chain_http)} HTTPS={len(redirect_chain_https)}")

    print(f"\n{C.YELLOW}[09]{C.RESET} Verify engine (multi-path)...")
    if skip_verify:
        print(f"      {C.DIM}skip{C.RESET}")
    else:
        verify_targets = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
        if not full:
            verify_targets = verify_targets[:max(verify_workers * 4, 1)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=verify_workers) as ex:
            verify_paths = FULL_VERIFY_PATHS if full else DEFAULT_VERIFY_PATHS
            futs = {ex.submit(verify_candidate_multi, ip, domain, baselines, verify_paths): ip for ip in verify_targets}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    res = fut.result()
                    verify_results[ip] = res
                    if res["verdict"] == "LIKELY_ORIGIN":
                        add_ip(ip, "multi-path-match")
                        add_ip(ip, "content-match")
                    elif res["matches"] >= 1:
                        add_ip(ip, "https-verify")
                    print(f"      {ip:<20} {res['verdict']:<12} score={res['score']:<3} matches={res['matches']}")
                except Exception as e:
                    print(f"      {ip:<20} verify-error {e}")

    print(f"\n{C.YELLOW}[10]{C.RESET} Public target posture audit...")
    posture = run_safe_posture_checks(domain, max_workers=posture_workers, cache=cache)
    print(f"      risk: {posture['risk_level']} ({posture['risk_score']}) | interesting paths: {len(posture['interesting_paths'])}")
    state.save({"stage": "posture_done", "domain": domain, "verify_count": len(verify_results), "ts": time.time()})

    print(f"\n{C.YELLOW}[11]{C.RESET} Technology + JS endpoint + favicon...")
    html_body, resp_headers, _ = http_get_with_headers(f"https://{domain}", timeout=15, cache=cache)
    if not html_body:
        html_body, resp_headers, _ = http_get_with_headers(f"http://{domain}", timeout=15, cache=cache)
    tech_found = detect_technology(html_body or "", resp_headers or {}) if html_body else {}
    js_endpoints = extract_js_endpoints(f"https://{domain}", html_body or "", cache=cache) if html_body else []
    fav_info = favicon_hash(domain, cache=cache)
    print(f"      tech={len(tech_found)} js_endpoints={len(js_endpoints)} favicon={'yes' if fav_info else 'no'}")

    leak_findings = []
    if not skip_github:
        print(f"\n{C.YELLOW}[12]{C.RESET} GitHub leak scan (safe query)...")
        try:
            leak_findings = github_leak_scan(domain, cache=cache)
            print(f"      tapıldı: {len(leak_findings)}")
        except Exception as e:
            print(f"      xəta: {e}")

    print(f"\n{C.YELLOW}[13]{C.RESET} Enrichment (BGP/IP intelligence)...")
    real_ips = [ip for ip in all_ips if not is_cloudflare(ip) and not is_private(ip)]
    if not full:
        real_ips = real_ips[:25]
    for ip in real_ips:
        bgp = bgpview_lookup(ip, cache=cache)
        iapi = ipapi_info(ip, cache=cache)
        asn = bgp.get("asn", "")
        org = bgp.get("asn_name", "") or iapi.get("org", "")
        cloud = classify_cloud(asn, org)
        rdns = reverse_ip_lookup(ip, cache=cache)
        shodan = shodan_info(ip, cache=cache)
        ip_enrich[ip] = {"bgp": bgp, "ipapi": iapi, "cloud": cloud, "rdns": rdns, "shodan": shodan}
        if verbose:
            print(f"      {ip:<18} AS={asn:<10} cloud={cloud or '-'} rdns={len(rdns)}")

    anomalies = analyze_provider_anomaly(sub_to_ips, domain, ip_enrich)

    if full:
        print(f"\n{C.YELLOW}[14]{C.RESET} Found-IP full safe audit...")
        audit_targets = [ip for ip in verify_results if verify_results[ip]["verdict"] in {"LIKELY_ORIGIN", "POSSIBLE"}]
        audit_targets = audit_targets[:20]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, posture_workers)) as ex:
            futs = {ex.submit(safe_ip_audit, ip, domain, cache): ip for ip in audit_targets}
            for fut in concurrent.futures.as_completed(futs):
                ip = futs[fut]
                try:
                    safe_ip_audits[ip] = fut.result()
                    print(f"      {ip:<20} risk={safe_ip_audits[ip]['risk_level']} ({safe_ip_audits[ip]['risk_score']})")
                except Exception as e:
                    print(f"      {ip:<20} ip-audit-error {e}")

    engine = CorrelationEngine(domain)
    for ip, srcs in all_ips.items():
        enrich = ip_enrich.get(ip, {})
        relsubs = sorted(set(ip_to_related_subs.get(ip, [])))
        priority = max([rank_subdomain(s) for s in relsubs], default=0)
        engine.add_ip(
            ip, srcs,
            bgp=enrich.get("bgp"),
            ipapi=enrich.get("ipapi"),
            rdns=enrich.get("rdns"),
            cloud=enrich.get("cloud"),
            verify=verify_results.get(ip),
            safe_audit=safe_ip_audits.get(ip),
            priority=priority,
            related_subdomains=relsubs,
        )

    print(f"\n{C.YELLOW}[15]{C.RESET} Summary...")
    role_summary = engine.get_summary()
    real_cands = engine.origin_candidates()
    print(f"      roles: {', '.join(f'{k}={len(v)}' for k, v in role_summary.items())}")
    print(f"      anomaliyalar: {len(anomalies)}")

    elapsed = time.time() - t0
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*72}")
    print(f"  ✦  NƏTİCƏ — {domain}  ({elapsed:.1f}s)")
    print(f"{'═'*72}{C.RESET}")

    if real_cands:
        print(f"\n{C.GREEN}{C.BOLD}  ⚡ Potensial REAL IP-lər ({len(real_cands)}):{C.RESET}")
        for ip, data in real_cands[:15]:
            info = ip_info(ip, cache=cache)
            verify = data.get("verify") or {}
            conf = confidence_score(data["sources"], cloud=data.get("cloud"), verify=verify, rdns_count=len(data.get("rdns_domains") or []), safe_audit=data.get("safe_audit"), priority=data.get("priority", 0))
            print(f"\n  {C.GREEN}{C.BOLD}▶ {ip}{C.RESET}")
            print(f"    {C.DIM}Role    :{C.RESET} {data['role']}")
            print(f"    {C.DIM}ASN     :{C.RESET} {(data.get('bgp') or {}).get('asn', info['org'])} | {info['city']}, {info['country']}")
            if data.get("cloud"):
                print(f"    {C.DIM}Cloud   :{C.RESET} {data['cloud']}")
            if verify:
                print(f"    {C.DIM}Verify  :{C.RESET} {verify.get('verdict')} / {verify.get('confidence_label')} / score={verify.get('score')}")
            if data.get("safe_audit"):
                sa = data["safe_audit"]
                print(f"    {C.DIM}IP audit:{C.RESET} {sa.get('risk_level')} / {sa.get('risk_score')}")
            print(f"    {C.DIM}Mənbələr:{C.RESET} {', '.join(list(set(data['sources']))[:8])}")
            print(f"    {C.DIM}Prioritet:{C.RESET} {data.get('priority', 0)} | discovery={data.get('discovery_score', 0)} | origin={data.get('origin_score', 0)}")
            if data.get("related_subdomains"):
                print(f"    {C.DIM}Hostlar :{C.RESET} {', '.join(data['related_subdomains'][:5])}")
            print(f"    {C.DIM}İzah    :{C.RESET} {'; '.join(explain_ip(data['sources'], verify=verify, cloud=data.get('cloud'), rdns_count=len(data.get('rdns_domains') or []), safe_audit=data.get('safe_audit'), priority=data.get('priority', 0)))}")
            print(f"    {C.DIM}Güvən   :{C.RESET} {conf}")
    else:
        print(f"\n{C.YELLOW}  ⚠  Güclü real origin namizədi tapılmadı.{C.RESET}")

    result = {
        "meta": {
            "tool": "CF-HUNTER v7.2 SAFE",
            "domain": domain,
            "full_mode": full,
            "elapsed_seconds": round(elapsed, 2),
            "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "resume_enabled": resume,
            "analysis_summary": build_text_summary(domain, posture, anomalies, real_cands),
        },
        "source_health": source_health,
        "public_baselines": baselines,
        "redirects": {
            "http": redirect_chain_http,
            "https": redirect_chain_https,
        },
        "dns_records": dns_data,
        "subdomains": {
            "count": len(sub_to_ips),
            "resolved": sub_to_ips,
            "non_cf": sorted(non_cf_subs),
        },
        "tls": {
            "cn": tls_result.get("cn", ""),
            "issuer": tls_result.get("issuer", ""),
            "sans_count": len(tls_sans),
            "sans": tls_sans[:30],
            "version": tls_result.get("version", ""),
            "cipher": tls_result.get("cipher", ""),
            "weak": tls_result.get("weak", False),
            "error": tls_result.get("error"),
        },
        "public_posture": posture,
        "technology": list(tech_found.keys()),
        "js_endpoints": js_endpoints[:30],
        "favicon": fav_info,
        "github_leaks": [{"repo": lf["repo"], "file": lf["file"], "url": lf["url"]} for lf in leak_findings],
        "verify_results": verify_results,
        "candidate_ip_audits": safe_ip_audits,
        "all_ips": {ip: sorted(set(srcs)) for ip, srcs in all_ips.items()},
        "ip_enrichment": ip_enrich,
        "anomalies": anomalies,
        "prioritized_non_cf_subdomains": sorted(non_cf_subs, key=lambda s: (rank_subdomain(s), s), reverse=True)[:50],
        "origin_candidates": [{
            "ip": ip,
            "role": data["role"],
            "confidence_score": data.get("confidence_score", 0),
            "discovery_score": data.get("discovery_score", 0),
            "origin_score": data.get("origin_score", 0),
            "priority": data.get("priority", 0),
            "related_subdomains": data.get("related_subdomains", []),
            "cloud": data.get("cloud"),
            "sources": data["sources"],
            "verify": data.get("verify", {}),
            "safe_audit": data.get("safe_audit", {}),
            "explanation": explain_ip(data["sources"], verify=data.get("verify"), cloud=data.get("cloud"), rdns_count=len(data.get("rdns_domains") or []), safe_audit=data.get("safe_audit"), priority=data.get("priority", 0)),
        } for ip, data in real_cands[:50]],
    }
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n{C.GREEN}[+] JSON saxlandı: {output_file}{C.RESET}")
    if write_md:
        md_path = output_file.rsplit(".", 1)[0] + ".md" if output_file else f"{domain}_cfhunter_v7_2.md"
        Path(md_path).write_text(build_markdown_report(result), encoding="utf-8")
        print(f"{C.GREEN}[+] Markdown saxlandı: {md_path}{C.RESET}")
    state.save({"stage": "done", "domain": domain, "origin_candidates": len(real_cands), "ts": time.time()})
    return result

def main():
    banner()
    ap = argparse.ArgumentParser(description="CF-Hunter v7.2: safer and smarter unified Cloudflare origin intelligence, posture auditor and analyst report engine")
    ap.add_argument("domain", help="Hədəf domain")
    ap.add_argument("-o", "--output", help="JSON faylına yaz")
    ap.add_argument("-v", "--verbose", action="store_true", help="Ətraflı çıxış")
    ap.add_argument("--full", action="store_true", help="Maksimum təhlükəsiz coverage: full verify + found-IP safe audit")
    ap.add_argument("--no-github", action="store_true", help="GitHub leak detection-u atla")
    ap.add_argument("--skip-verify", action="store_true", help="Verify mərhələsini atla")
    ap.add_argument("--verify-workers", type=int, default=12, help="Verify worker sayı")
    ap.add_argument("--resolve-workers", type=int, default=60, help="Resolve worker sayı")
    ap.add_argument("--posture-workers", type=int, default=10, help="Posture/audit worker sayı")
    ap.add_argument("--no-cache", action="store_true", help="Cache-i söndür")
    ap.add_argument("--cache-ttl", type=int, default=21600, help="Cache TTL (saniyə)")
    ap.add_argument("--no-resume", action="store_true", help="Daxili state/resume faylını söndür")
    ap.add_argument("--md-report", action="store_true", help="Markdown report da yarat")
    ap.add_argument("--probe-timeout", type=int, default=6, help="IP probe timeout (saniyə)")
    ap.add_argument("--probe-retries", type=int, default=2, help="IP probe retry sayı")
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split('?')[0]
    if not re.match(r'^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$', domain):
        print(f"{C.RED}[!] Yanlış domain formatı: {domain}{C.RESET}")
        sys.exit(1)

    analyze(
        domain=domain,
        output_file=args.output,
        verbose=args.verbose,
        skip_github=args.no_github,
        skip_verify=args.skip_verify,
        verify_workers=max(1, min(args.verify_workers, 80)),
        resolve_workers=max(1, min(args.resolve_workers, 120)),
        posture_workers=max(1, min(args.posture_workers, 40)),
        full=args.full,
        cache_enabled=not args.no_cache,
        cache_ttl=max(60, args.cache_ttl),
        resume=not args.no_resume,
        write_md=args.md_report,
        probe_timeout=args.probe_timeout,
        probe_retries=args.probe_retries,
    )

if __name__ == "__main__":
    main()
