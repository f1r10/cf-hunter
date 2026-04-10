#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           CF-HUNTER v3.0 @f1r10 — Cloudflare Real IP Finder        ║
║   12+ OSINT mənbəsi | MX/SPF/TXT | Zone Transfer | Retry    ║
║          Yalnız icazəli testlər üçün istifadə edin           ║
╚══════════════════════════════════════════════════════════════╝
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
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote
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
{C.RESET}{C.DIM}        Cloudflare Real IP Finder v3.0 @f1r10 — 12 OSINT Mənbəsi{C.RESET}
""")

# ──────────────────────────────────────────────────────────────
#  Cloudflare CIDR range-ləri
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

def ip_label(ip):
    if is_cloudflare(ip):
        return f"{C.RED}[CF]{C.RESET}    "
    if is_private(ip):
        return f"{C.DIM}[PRIV]{C.RESET}  "
    return f"{C.GREEN}[REAL?]{C.RESET} "

# ──────────────────────────────────────────────────────────────
#  HTTP helper — SSL skip + retry
# ──────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CF-Hunter/3.0",
    "Accept":     "application/json, text/html, */*",
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

def http_json(url, timeout=14, retries=2):
    raw = http_get(url, timeout=timeout, retries=retries)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return None

# ──────────────────────────────────────────────────────────────
#  Subdomain toplama yardımçısı
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
#  OSINT MƏNBƏLƏR
# ══════════════════════════════════════════════════════════════

def src_crtsh(domain, col):
    """crt.sh — sertifikat şəffaflığı (düzəldilmiş parser)"""
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
    """CertSpotter (SSLMate) — sertifikat mənbəyi"""
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
    """AlienVault OTX — passive DNS + URL list"""
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
    """HackerTarget — hostsearch + DNS history"""
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
    """URLScan.io — scan tarixçəsi"""
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
    """ThreatMiner — subdomain siyahısı"""
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
    """Anubis / jldc.me — subdomain DB"""
    data = http_json(f"https://jldc.me/anubis/subdomains/{domain}", timeout=12)
    n = 0
    if data and isinstance(data, list):
        for s in data:
            col.add(s)
            n += 1
    return n


def src_rapiddns(domain, col):
    """RapidDNS — subdomain scraper"""
    raw = http_get(f"https://rapiddns.io/subdomain/{domain}?full=1#result", timeout=15)
    n = 0
    if raw:
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        for s in re.findall(pattern, raw):
            col.add(s)
            n += 1
    return n


def src_bufferover(domain, col):
    """BufferOver TLS — subdomain"""
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
    """Wayback Machine — CDX URL index"""
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


# ──────────────────────────────────────────────────────────────
#  DNS Records — DoH vasitəsilə (MX, TXT/SPF, NS)
# ──────────────────────────────────────────────────────────────
def doh_query(name, rtype):
    """DNS-over-HTTPS — Google"""
    data = http_json(
        f"https://dns.google/resolve?name={quote(name)}&type={rtype}",
        timeout=10,
    )
    if data:
        return data.get("Answer", [])
    return []


def dns_records_analysis(domain):
    out = {"mx": [], "mx_ips": [], "spf_ips": [], "ns": [], "txt": []}

    # MX
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

    # TXT / SPF
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

    # NS
    for a in doh_query(domain, "NS"):
        ns = a.get("data", "").rstrip(".")
        if ns and ns not in out["ns"]:
            out["ns"].append(ns)

    return out


# ──────────────────────────────────────────────────────────────
#  Zone Transfer cəhdi (dnspython varsa)
# ──────────────────────────────────────────────────────────────
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
    "autodiscover","autoconfig","_dmarc","dkim","spf",
]

def brute_subs(domain):
    return sorted(set(f"{w}.{domain}" for w in WORDLIST))


# ──────────────────────────────────────────────────────────────
#  Paralel resolve
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


# ──────────────────────────────────────────────────────────────
#  IP məlumatı
# ──────────────────────────────────────────────────────────────
def ip_info(ip):
    d = http_json(f"https://ipinfo.io/{ip}/json", timeout=8)
    if d:
        return {
            "org":      d.get("org", "?"),
            "city":     d.get("city", "?"),
            "country":  d.get("country", "?"),
            "hostname": d.get("hostname", ""),
        }
    return {"org": "?", "city": "?", "country": "?", "hostname": ""}


# ──────────────────────────────────────────────────────────────
#  Güvən skoru
# ──────────────────────────────────────────────────────────────
def confidence_score(sources):
    s = set(sources)
    score = len(s)
    if any("mx" in x or "spf" in x for x in s): score += 3
    if "urlscan.io" in s:      score += 2
    if "alienvault-otx" in s:  score += 2
    if "hackertarget" in s:    score += 1
    if any("sub:" in x for x in s): score += 1
    return score


# ══════════════════════════════════════════════════════════════
#  ANA ANALİZ
# ══════════════════════════════════════════════════════════════
def analyze(domain, verbose=False, output_file=None):
    t0  = time.time()
    col = SubCollector(domain)
    all_ips = {}   # ip -> set(sources)

    def add_ip(ip, src):
        if not is_valid_ip(ip) or is_private(ip):
            return
        all_ips.setdefault(ip, set()).add(src)

    def pprint_ip(ip, src=""):
        tag   = ip_label(ip)
        extra = f"  {C.DIM}← {src}{C.RESET}" if verbose and src else ""
        print(f"      {tag} {ip}{extra}")

    print(f"\n{C.BOLD}{C.CYAN}[TARGET]{C.RESET} {C.BOLD}{domain}{C.RESET}  "
          f"{C.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.DIM}{'═'*65}{C.RESET}")

    # ── 01. Mövcud DNS
    print(f"\n{C.YELLOW}[01/12]{C.RESET} Mövcud DNS A/AAAA record-ları...")
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            pprint_ip(ip, "current-dns")
            add_ip(ip, "current-dns")
    except Exception as e:
        print(f"       {C.DIM}Xəta: {e}{C.RESET}")

    # ── 02. DNS MX / TXT / SPF / NS
    print(f"\n{C.YELLOW}[02/12]{C.RESET} DNS Records — MX / TXT / SPF / NS (DoH)...")
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
    print(f"\n{C.YELLOW}[03/12]{C.RESET} DNS Zone Transfer (AXFR) cəhdi...")
    zt = try_zone_transfer(domain, dns_data["ns"])
    if zt:
        print(f"        {C.GREEN}⚡ Zone Transfer uğurlu! {len(zt)} record{C.RESET}")
        for s in zt[:10]:
            col.add(s)
            print(f"        {C.GREEN}{s}{C.RESET}")
    else:
        print(f"        {C.DIM}Zone Transfer bloklanıb (normal){C.RESET}")

    # ── 04. crt.sh
    print(f"\n{C.YELLOW}[04/12]{C.RESET} crt.sh sertifikat şəffaflığı...")
    before = len(col.subs)
    src_crtsh(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain tapıldı  "
          f"(cəmi: {len(col.subs)})")

    # ── 05. CertSpotter
    print(f"\n{C.YELLOW}[05/12]{C.RESET} CertSpotter (SSLMate)...")
    before = len(col.subs)
    src_certspotter(domain, col)
    print(f"        {len(col.subs) - before} yeni subdomain tapıldı")

    # ── 06. AlienVault OTX
    print(f"\n{C.YELLOW}[06/12]{C.RESET} AlienVault OTX passive DNS...")
    before = len(col.subs)
    otx_ips = src_alienvault(domain, col)
    for ip in otx_ips:
        pprint_ip(ip, "alienvault-otx")
        add_ip(ip, "alienvault-otx")
    print(f"        {len(otx_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 07. HackerTarget
    print(f"\n{C.YELLOW}[07/12]{C.RESET} HackerTarget DNS history...")
    before = len(col.subs)
    ht_ips = src_hackertarget(domain, col)
    for ip in ht_ips:
        pprint_ip(ip, "hackertarget")
        add_ip(ip, "hackertarget")
    print(f"        {len(ht_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 08. URLScan.io
    print(f"\n{C.YELLOW}[08/12]{C.RESET} URLScan.io scan tarixçəsi...")
    before = len(col.subs)
    us_ips = src_urlscan(domain, col)
    for ip in us_ips:
        pprint_ip(ip, "urlscan.io")
        add_ip(ip, "urlscan.io")
    print(f"        {len(us_ips)} IP, {len(col.subs)-before} yeni subdomain")

    # ── 09. ThreatMiner + Anubis + Wayback
    print(f"\n{C.YELLOW}[09/12]{C.RESET} ThreatMiner / Anubis / Wayback Machine...")
    before = len(col.subs)
    t1 = src_threatminer(domain, col)
    t2 = src_anubis(domain, col)
    t3 = src_wayback(domain, col)
    print(f"        ThreatMiner:{t1}  Anubis:{t2}  Wayback:{t3}"
          f"  →  {len(col.subs)-before} yeni subdomain")

    # ── 10. RapidDNS + BufferOver
    print(f"\n{C.YELLOW}[10/12]{C.RESET} RapidDNS / BufferOver TLS...")
    before = len(col.subs)
    src_rapiddns(domain, col)
    src_bufferover(domain, col)
    print(f"        {len(col.subs)-before} yeni subdomain əlavə edildi")

    # ── 11. Resolve
    passive_subs   = col.result()
    brute_list     = brute_subs(domain)
    all_to_resolve = sorted(set(passive_subs + brute_list))

    print(f"\n{C.YELLOW}[11/12]{C.RESET} Subdomain resolve (parallel 60 thread)...")
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
    print(f"\n{C.YELLOW}[12/12]{C.RESET} Shodan InternetDB (non-CF IP-lər)...")
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

    # ──────────────────────────────────────────────
    #  NƏTİCƏ
    # ──────────────────────────────────────────────
    elapsed = time.time() - t0
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*65}")
    print(f"  ✦  NƏTİCƏ — {domain}  ({elapsed:.1f}s)")
    print(f"{'═'*65}{C.RESET}")

    real_cands = {
        ip: list(srcs)
        for ip, srcs in all_ips.items()
        if not is_cloudflare(ip) and not is_private(ip)
    }
    cf_ips_list = [ip for ip in all_ips if is_cloudflare(ip)]

    if real_cands:
        ranked = sorted(
            real_cands.items(),
            key=lambda x: confidence_score(x[1]),
            reverse=True
        )
        print(f"\n{C.GREEN}{C.BOLD}  ⚡ Potensial REAL IP-lər ({len(real_cands)}):{C.RESET}")
        for ip, sources in ranked[:20]:
            info  = ip_info(ip)
            sd    = shodan_cache.get(ip, {})
            ports = sd.get("ports", [])
            vulns = sd.get("vulns", [])
            conf  = confidence_score(sources)
            bar   = "█" * min(conf, 10)
            bcol  = C.GREEN if conf >= 5 else C.YELLOW if conf >= 2 else C.DIM

            print(f"\n  {C.GREEN}{C.BOLD}▶ {ip}{C.RESET}")
            print(f"    {C.DIM}ASN     :{C.RESET} {info['org']} | {info['city']}, {info['country']}")
            if info["hostname"]:
                print(f"    {C.DIM}rDNS    :{C.RESET} {info['hostname']}")
            print(f"    {C.DIM}Mənbələr:{C.RESET} {', '.join(list(sources)[:5])}")
            if ports:
                print(f"    {C.DIM}Portlar :{C.RESET} {ports}")
            if vulns:
                print(f"    {C.RED}CVE     :{C.RESET} {list(vulns)[:5]}")
            print(f"    {C.DIM}Güvən   :{C.RESET} {bcol}{bar}{C.RESET} ({conf} xal)")
    else:
        print(f"\n{C.YELLOW}  ⚠  Real IP tapılmadı.{C.RESET}")
        print(f"  {C.DIM}Sistem düzgün qurulub — ya da heç vaxt ifşa olunmayıb.{C.RESET}")

    print(f"\n  {C.DIM}Cloudflare IP-ləri: {', '.join(cf_ips_list[:6])}{C.RESET}")
    print(f"  {C.DIM}Subdomain: {len(sub_resolved)} aktiv / {len(all_to_resolve)} yoxlanıldı{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}{'═'*65}{C.RESET}\n")

    result = {
        "domain":      domain,
        "scan_time":   datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 2),
        "real_candidates": {
            ip: {
                "sources":    list(srcs),
                "confidence": confidence_score(list(srcs)),
                "shodan":     shodan_cache.get(ip, {}),
            }
            for ip, srcs in real_cands.items()
        },
        "cloudflare_ips": cf_ips_list,
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
        description="CF-Hunter v3: Cloudflare arxasındakı real IP-ni tap",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("domain",
        help="Hədəf domain  (məs: example.com  ya da  https://example.com/path)")
    ap.add_argument("-o", "--output",
        help="Nəticəni JSON faylına yaz  (məs: -o result.json)")
    ap.add_argument("-v", "--verbose",
        action="store_true",
        help="Ətraflı çıxış (mənbə, TXT record-lar, NS)")
    args = ap.parse_args()

    # Domain təmizlə
    domain = args.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain).split("/")[0].split("?")[0]

    if not re.match(r'^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$', domain):
        print(f"{C.RED}[!] Yanlış domain formatı: {domain}{C.RESET}")
        sys.exit(1)

    analyze(domain, verbose=args.verbose, output_file=args.output)


if __name__ == "__main__":
    main()
