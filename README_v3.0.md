<div align="center">

```
 ██████╗███████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗  █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔══╝  ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Cloudflare Real IP Finder — v3.0**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![OSINT Sources](https://img.shields.io/badge/OSINT%20Sources-12-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)

*Cloudflare arxasında gizlənmiş real server IP-lərini 12 OSINT mənbəsi ilə aşkar edir.*

</div>

---

## Haqqında

CF-Hunter, Cloudflare CDN/proxy arxasında olan hədəf domenlərin **real (origin) IP ünvanlarını** passiv OSINT metodları ilə müəyyən etmək üçün yazılmış Python alətidir.

Alət heç bir aktiv intrusion cəhdi etmir — yalnız açıq mənbələrdən (sertifikat logları, DNS tarixçəsi, arşiv xidmətləri və s.) məlumat toplayır, subdomainləri resolve edir, nəticələri etibarlılıq skoru ilə sıralayır.

> **⚠ Yalnız icazəli testlər üçün.** Bu aləti öz sistemlərinizdə, bug bounty proqramlarında və ya rəsmi icazə aldığınız hədəflərdə istifadə edin. İcazəsiz tarama qeyri-qanuni ola bilər.

---

## Xüsusiyyətlər

- **12 OSINT mənbəsi** paralel olaraq sorğulanır
- **Sertifikat şəffaflığı** — crt.sh və CertSpotter vasitəsilə
- **Passive DNS** — AlienVault OTX, HackerTarget, ThreatMiner, Anubis
- **Arşiv məlumatları** — Wayback Machine CDX, URLScan.io
- **DNS Record analizi** — MX, TXT/SPF ip4 ünvanları, NS (DNS-over-HTTPS ilə)
- **Zone Transfer** cəhdi (dnspython mövcuddursa)
- **Subdomain brute-force** — 150+ sözlük ilə
- **Paralel resolve** — 60 thread, tam subdomain xəritəsi
- **Shodan InternetDB** inteqrasiyası — açıq portlar, CVE-lər
- **IP enrichment** — ipinfo.io vasitəsilə ASN, ölkə, rDNS
- **Güvən skoru** — hər IP üçün mənbə çəkisindən hesablanır
- **JSON çıxışı** — avtomatlaşdırma üçün `-o` flag-i ilə

---

## Tələblər

```
Python 3.8+
```

Standart kitabxanadan başqa heç bir məcburi dependency yoxdur. `dnspython` quraşdırılıbsa zone transfer funksionallığı aktivləşir:

```bash
pip install dnspython   # isteğe bağlı
```

---

## Quraşdırma

```bash
git clone https://github.com/USERNAME/cf-hunter.git
cd cf-hunter
```

Virtual mühit (tövsiyə olunur):

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## İstifadə

### Əsas istifadə

```bash
python3 cf_hunter.py example.com
```

### Ətraflı çıxış (NS, TXT record-lar, mənbə etiketləri)

```bash
python3 cf_hunter.py example.com -v
```

### Nəticəni JSON faylına yaz

```bash
python3 cf_hunter.py example.com -o result.json
```

### Hamısı birlikdə

```bash
python3 cf_hunter.py example.com -v -o result.json
```

URL formatı da qəbul edilir — alət domenə avtomatik çevirir:

```bash
python3 cf_hunter.py https://example.com/some/path
```

---

## Çıxış nümunəsi

```
[TARGET] example.com  2025-01-15 14:32:07
═════════════════════════════════════════════════════════════════

[01/12] Mövcud DNS A/AAAA record-ları...
        [CF]     104.21.18.45
        [CF]     172.67.142.30

[02/12] DNS Records — MX / TXT / SPF / NS (DoH)...
        MX: mail.example.com
        [REAL?]  198.51.100.22  ← mx-record
        SPF ip4: 198.51.100.0

[04/12] crt.sh sertifikat şəffaflığı...
        47 yeni subdomain tapıldı  (cəmi: 47)

[11/12] Subdomain resolve (parallel 60 thread)...
        Passive:89  Brute:150  Cəmi unikal:205
        63 aktiv subdomain resolve olundu

        ⚡ CF-dən kənar subdomain IP-ləri:
          198.51.100.22        ← dev.example.com
          203.0.113.55         ← staging.example.com

═════════════════════════════════════════════════════════════════
  ✦  NƏTİCƏ — example.com  (38.4s)
═════════════════════════════════════════════════════════════════

  ⚡ Potensial REAL IP-lər (2):

  ▶ 198.51.100.22
    ASN     : AS12345 ExampleHosting | Frankfurt, DE
    rDNS    : server1.examplehosting.com
    Mənbələr: mx-record, spf-record, sub:dev.example.com
    Portlar : [22, 80, 443, 8080]
    Güvən   : ████████ (8 xal)

  ▶ 203.0.113.55
    ASN     : AS67890 AnotherDC | Amsterdam, NL
    Mənbələr: sub:staging.example.com, urlscan.io
    Portlar : [22, 443]
    Güvən   : ███ (3 xal)
```

---

## OSINT Mənbələri

| # | Mənbə | Növ | Qeyd |
|---|-------|-----|------|
| 01 | System DNS | A/AAAA | Canlı resolve |
| 02 | DNS-over-HTTPS | MX / TXT / SPF / NS | Google DoH |
| 03 | Zone Transfer | AXFR | dnspython ilə |
| 04 | [crt.sh](https://crt.sh) | Sertifikat CT logları | |
| 05 | [CertSpotter](https://sslmate.com/certspotter/) | Sertifikat CT logları | |
| 06 | [AlienVault OTX](https://otx.alienvault.com) | Passive DNS + URL | |
| 07 | [HackerTarget](https://hackertarget.com) | DNS history | |
| 08 | [URLScan.io](https://urlscan.io) | Scan tarixçəsi | |
| 09 | ThreatMiner / Anubis / Wayback | Subdomain DB + arşiv | |
| 10 | RapidDNS / BufferOver TLS | Subdomain | |
| 11 | Subdomain resolve | Paralel DNS | 60 thread |
| 12 | [Shodan InternetDB](https://internetdb.shodan.io) | Port / CVE | |

---

## Güvən Skoru

Hər potensial real IP üçün mənbə çəkisinə görə bir bal hesablanır:

| Mənbə | Əlavə bal |
|-------|-----------|
| Hər unikal mənbə | +1 |
| MX və ya SPF record-dan gəlirsə | +3 |
| urlscan.io | +2 |
| alienvault-otx | +2 |
| hackertarget | +1 |
| Subdomain resolve | +1 |

5 və yuxarı bal `████` yaşıl, 2-4 arası sarı, 1 isə solğun göstərilir.

---

## JSON Çıxışı Strukturu

`-o result.json` ilə aşağıdakı formatda fayl yaradılır:

```json
{
  "domain": "example.com",
  "scan_time": "2025-01-15T14:32:45",
  "elapsed_sec": 38.4,
  "real_candidates": {
    "198.51.100.22": {
      "sources": ["mx-record", "spf-record", "sub:dev.example.com"],
      "confidence": 8,
      "shodan": { "ports": [22, 80, 443], "vulns": [] }
    }
  },
  "cloudflare_ips": ["104.21.18.45", "172.67.142.30"],
  "subdomains": {
    "total_checked": 205,
    "active": 63,
    "non_cf": [{ "sub": "dev.example.com", "ip": "198.51.100.22" }]
  },
  "dns_records": {
    "mx": ["mail.example.com"],
    "spf_ips": ["198.51.100.0"],
    "ns": ["ns1.cloudflare.com", "ns2.cloudflare.com"]
  }
}
```

---

## Məhdudiyyətlər

- Bəzi OSINT API-ləri rate limit tətbiq edir (xüsusilə crt.sh, HackerTarget). Peş-peş istifadə zamanı gecikmə yarana bilər.
- Heç vaxt ifşa olmamış origin IP-lər (yalnız Cloudflare-dən keçən, heç vaxt birbaşa açılmayan serverlər) tapılmaya bilər — bu alətin deyil, hədəfin düzgün konfiqurasiyasının nəticəsidir.
- Shodan InternetDB pulsuz olduğu üçün bəzi portlar və ya CVE-lər eksik göstərilə bilər.

---

## Töhfə

Pull request-lər açıqdır. Yeni OSINT mənbəsi əlavə edərkən `src_` prefiksi ilə funksiya yaz və `analyze()` içinə inteqrasiya et. Mövcud struktura uyğun `SubCollector` + IP add pattern-i saxla.

---

## Lisenziya

[MIT](LICENSE) — öz məsuliyyətinizdə istifadə edin.

---

<div align="center">
<sub>Yalnız etik, icazəli təhlükəsizlik tədqiqatları üçün hazırlanmışdır.</sub>
</div>
