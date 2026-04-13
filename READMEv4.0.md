# CF-Hunter v4.0

```
 ██████╗███████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗  █████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔══╝  ╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗██║           ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Cloudflare Arxasındakı Real IP-ni Kəşf Edən İntelligence Çərçivəsi**  
`BGP/ASN · TLS/SAN · Texnologiya Tespiti · JS Skan · Favicon · Sızıntı Tespiti · Korrelyasiya Mühərriki`

> ⚠️ **Yalnız icazəli testlər üçün istifadə edin.**  
> Bu alət yalnız sahibi olduğunuz və ya yazılı icazə aldığınız sistemlər üzərində aparılan icazəli penetrasiya testləri, bug bounty proqramları və təhlükəsizlik tədqiqatları üçün nəzərdə tutulmuşdur.

---

## Mündəricat

- [CF-Hunter Nədir?](#cf-hunter-nədir)
- [v4.0-dakı Yeniliklər](#v40-dakı-yeniliklər)
- [Necə İşləyir?](#necə-i̇şləyir)
- [Quraşdırma](#quraşdırma)
- [İstifadə](#i̇stifadə)
- [Skan Fazaları](#skan-fazaları)
- [Kəşfiyyat Modulları](#kəşfiyyat-modulları)
- [Mənbə Etibarlılıq Skoru](#mənbə-etibarlılıq-skoru)
- [Çarpaz Doğrulama Məntiqi](#çarpaz-doğrulama-məntiqi)
- [Korrelyasiya Mühərriki](#korrelyasiya-mühərriki)
- [JSON Çıxış Formatı](#json-çıxış-formatı)
- [Nəticələri Anlamaq](#nəticələri-anlamaq)
- [API Açarları və Sürət Limitləri](#api-açarları-və-sürət-limitləri)
- [Arxitektura](#arxitektura)
- [Hüquqi Məsuliyyət və Etika](#hüquqi-məsuliyyət-və-etika)

---

## CF-Hunter Nədir?

CF-Hunter, **Cloudflare** (və ya digər CDN/reverse-proxy xidmətlərinin) arxasında gizlənən bir veb hədəfin **real mənşə IP ünvanını** aşkar etmək üçün nəzərdə tutulmuş passiv OSINT kəşfiyyat çərçivəsidir.

Kobud güc hücumlarına və ya aktiv istismara əl atmaq əvəzinə, CF-Hunter **16+ passiv və yarı-passiv mənbədən** — sertifikat şəffaflıq jurnalları, DNS tarixçəsi, BGP verilənlər bazaları, TLS sertifikatları, favicon hashləri, JavaScript endpoint analizi və daha çoxundan — əldə edilən məlumatları korrelyasiya edərək hədəfin həqiqi infrastrukturu barədə inamlı bir mənzərə qurur.

v4.0 bu aləti sadə bir IP yığıcısından **çoxqatlı bir kəşfiyyat analitik sisteminə** çevirir: hər bir tapıntını sizə təqdim etməzdən əvvəl təsnifatlandırır, skorlayır və çarpaz doğrulayır.

---

## v4.0-dakı Yeniliklər

| Sahə | v3.0 | v4.0 |
|---|---|---|
| OSINT mənbələri | 12 | 16+ |
| IP zənginləşdirmə | Yalnız ipinfo.io | ipinfo + BGPView + ip-api |
| Bulud tespiti | Yalnız Cloudflare CIDR | ASN + org xəritəsi ilə 12 provayder |
| TLS analizi | Yoxdur | Tam SAN çıxarışı, cipher/versiya, zəiflik tespiti |
| Texnologiya tespiti | Yoxdur | Başlıq + HTML ilə 25+ texnologiya |
| JavaScript skanı | Yoxdur | Skript kəşfi + API endpoint çıxarışı |
| Favicon barmaq izi | Yoxdur | mmh3 hash (Shodan uyğun) |
| GitHub sızıntı tespiti | Yoxdur | Açıq konfiqurasiyalar üçün təhlükəsiz kod axtarışı |
| Əks IP analizi | Yoxdur | Ortaq hostinqdə olan domainlərin tespiti |
| Mənbə skorlaması | Bərabər ağırlıq | DIRECT / VERIFIED_API / SCRAPED pilləri |
| Çarpaz doğrulama | Yoxdur | 2+ müstəqil siqnal tələbi |
| Korrelyasiya mühərriki | Yoxdur | Rol təsnifatı (ORIGIN/CDN/MAIL/API/SHARED) |
| Çıxış | Sadə JSON | Tam kəşfiyyat xəritəsi olan strukturlaşdırılmış JSON |

---

## Necə İşləyir?

```
Hədəf Domain
     │
     ├─ [DNS Qatı]         Cari A/AAAA · MX · SPF · NS · Zone Transfer
     ├─ [Sertifikat Qatı]  crt.sh · CertSpotter · TLS SAN-lar
     ├─ [OSINT Qatı]       AlienVault OTX · HackerTarget · URLScan · ThreatMiner
     │                     Anubis · RapidDNS · BufferOver · Wayback Machine
     ├─ [Aktiv Resolve]    Subdomain brute (200+ söz siyahısı) + passiv siyahı
     ├─ [Shodan]           InternetDB port/zəiflik/etiket məlumatı
     ├─ [TLS Dərini]       Sertifikat SAN-ları · cipher dəsti · zəiflik işarələri
     ├─ [Texnologiya]      HTTP başlıqları + HTML gövdəsi barmaq izi
     ├─ [JS Skanı]         Skript kəşfi · API marşrut çıxarışı
     ├─ [Favicon]          mmh3 hash · Shodan barmaq izi sorğusu
     ├─ [BGP/Şəbəkə]       BGPView ASN · ip-api org/hosting/proxy işarələri
     ├─ [Əks IP]           HackerTarget ortaq domenlərin axtarışı
     └─ [GitHub]           Açıq konfiqurasiyalar üçün təhlükəsiz kod axtarışı
              │
              ▼
     Mənbə Etibarlılıq Skorlayıcısı
     Çarpaz Doğrulama Mühərriki
     Korrelyasiya və Rol Təsnifatçısı
              │
              ▼
     Sıralanmış Nəticələr: ORIGIN · CDN · MAIL · API · SHARED_HOST
```

Hər hansı bir mənbə tərəfindən tapılan hər IP, sizə çatmazdan əvvəl **skorlama boru kəmərindən** keçir. Zəif siqnallı, doğrulanmamış IP-lər daha aşağı sıralanır və ya filtrlənir. Yalnız çarpaz doğrulanmış tapıntılar `✓` işarəsi ilə qeyd olunur.

---

## Quraşdırma

### Tələblər

- Python 3.8+
- Məcburi üçüncü tərəf paketləri yoxdur — tamamilə standart kitabxana (stdlib) ilə işləyir

### Klonla və İşə Sal

```bash
git clone https://github.com/f1r10/cf-hunter.git
cd cf-hunter
python3 cf_hunter_v4.py example.com
```

### Əlavə İmkanlar üçün Opsional Paketlər

```bash
# dnspython — Zone Transfer (AXFR) cəhdlərini aktivləşdirir
pip install dnspython

# mmh3 — yerli C MurmurHash3 (v4 saf Python ehtiyat variantı ehtiva edir, lakin bu daha sürətlidir)
pip install mmh3
```

> Alət bunlar olmadan tam işləyir. `dnspython` yalnız Zone Transfer əlavə edir; saf Python `_murmur3_32` tətbiqi favicon hashini Shodan alqoritmi ilə eyni şəkildə hesablayır.

---

## İstifadə

### Əsas

```bash
python3 cf_hunter_v4.py example.com
```

### JSON çıxışı ilə

```bash
python3 cf_hunter_v4.py example.com -o netice.json
```

### Ətraflı rejim (BGP detalları, əks IP domainləri, TXT record-lar göstərilir)

```bash
python3 cf_hunter_v4.py example.com -v
```

### GitHub sızıntı tespitini atla (daha sürətli, rate-limit-dən qaçınır)

```bash
python3 cf_hunter_v4.py example.com --no-github
```

### Bütün seçimlər

```bash
python3 cf_hunter_v4.py --help
```

```
istifadə: cf_hunter_v4.py [-h] [-o ÇIXIŞ] [-v] [--no-github] domain

mövqeli arqumentlər:
  domain          Hədəf domain (məs: example.com və ya https://example.com/yol)

seçimlər:
  -o, --output    Nəticəni JSON faylına yaz (məs: -o netice.json)
  -v, --verbose   Ətraflı çıxış: BGP detalları, ortaq domenler, TXT record-lar
  --no-github     GitHub sızıntı tespiti fazasını atla
```

### Qəbul edilən domain formatları

```bash
python3 cf_hunter_v4.py example.com
python3 cf_hunter_v4.py https://example.com
python3 cf_hunter_v4.py https://example.com/bezi/yol?q=1    # avtomatik təmizlənir
python3 cf_hunter_v4.py alt.example.com
```

---

## Skan Fazaları

CF-Hunter v4.0 ardıcıl olaraq 16 nömrəli fazanı icra edir:

```
[01/16]  Cari DNS A/AAAA record-ları
[02/16]  DNS MX · TXT · SPF · NS — DNS-over-HTTPS (Google) vasitəsilə
[03/16]  Zone Transfer cəhdi (AXFR) — dnspython tələb olunur
[04/16]  crt.sh sertifikat şəffaflığı
[05/16]  CertSpotter (SSLMate) sertifikat şəffaflığı
[06/16]  AlienVault OTX passiv DNS + URL siyahısı
[07/16]  HackerTarget DNS tarixçəsi + hostsearch
[08/16]  URLScan.io skan tarixçəsi
[09/16]  ThreatMiner + Anubis (jldc.me) + Wayback Machine CDX
[10/16]  RapidDNS + BufferOver TLS
[11/16]  Subdomain resolve — passiv siyahı + brute (200+ söz), 60 thread
[12/16]  Shodan InternetDB — CF-dən kənar IP-lər üçün port, CVE, etiketlər
[13/16]  TLS Dərin Analiz — SAN-lar, cipher, versiya, zəiflik işarələri
[14/16]  Texnologiya Tespiti + JS Endpoint Skanı + Favicon Hash
[15/16]  BGP/ASN Kəşfiyyatı + Bulud Təsnifatı + Əks IP Axtarışı
[16/16]  GitHub Sızıntı Tespiti (təhlükəsiz rejim, açıq API)
```

Bütün fazalardan sonra: **Korrelyasiya Mühərriki** → sıralanmış nəticə çıxışı.

---

## Kəşfiyyat Modulları

### BGP / Şəbəkə Kəşfiyyatı

**BGPView API**-sindən (`api.bgpview.io`) istifadə edərək hər CF-dən kənar IP-ni aşağıdakılara həll edir:

- ASN nömrəsi və təşkilat adı
- IP prefiksi / CIDR bloku
- RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- Qeydiyyat ölkəsi

**ip-api.com** ilə əlavə məlumatlar:

- İnternet provayderinin adı
- Mərkəzi/hosting işarəsi
- Proxy/VPN işarəsi
- Mobil şəbəkə işarəsi

### Bulud və CDN Təsnifatı

Hər IP-ni **12 məlum bulud/CDN provayderinə** qarşı iki qatlı yanaşma ilə təsnif edir:

1. **ASN uyğunluğu** — məlum bulud ASN-lərinə birbaşa axtarış
2. **Org açar söz uyğunluğu** — təşkilat adının qeyri-dəqiq uyğunluğu

Tanınan provayderlər: `AWS · GCP · Azure · Cloudflare · Fastly · Akamai · DigitalOcean · Vultr · Linode · OVH · Hetzner · Imperva`

CDN/proxy provayderləri kimi təsnif edilən IP-lər nəticələrdə **avtomatik olaraq aşağı sıralanır** — bunlar yanlış pozitiv deyil, lakin mənşə serverlər də deyil.

### Əks IP Analizi

Eyni IP-də hostalanmış digər domainləri tapmaq üçün **HackerTarget**-ə sorğu göndərir. Bu, aşağıdakılar üçün istifadə olunur:

- **Ortaq hostinq** tespiti (əgər 10+ əlaqəsiz domain eyni IP-ni paylaşırsa, bu çətin ki, xüsusi mənşə server olsun)
- **Əlaqəli infrastrukturun** müəyyən edilməsi (eyni təşkilatın digər domainləri)

Çoxlu ortaq domenləri olan IP-lər Korrelyasiya Mühərriki tərəfindən `SHARED_HOST` kimi təsnif edilir.

### TLS Dərin Analizi

Birbaşa 443-cü porta qoşulur və TLS əl sıxışmasını yoxlayır:

- **Mövzu CN** — əsas sertifikat host adı
- **Mövzu Alternativ Adları (SAN-lar)** — eyni sertifikatdakı bütün host adları; hər SAN bir IP-yə həll edilir və Cloudflare aralıqlarına qarşı yoxlanılır
- **Yayımlayan** — CA təşkilatı
- **Etibarlılıq tarixi** — bitmə tarixi
- **Cipher dəsti** — tam cipher sətri
- **TLS versiyası** — TLS 1.0, 1.1, SSLv2/3-ü zəif olaraq işarələyir
- **Zəif cipher tespiti** — RC4, DES, 3DES, NULL, EXPORT cipher-lərini işarələyir

SAN-lar yüksək dəyərli mənbədir: əgər `staging.example.com` ilə paylaşılan sertifikat CF-dən kənar IP-yə həll olunarsa, həmin IP **DIRECT** müşahidə kimi qeyd edilir (`ağırlıq 3`).

### Texnologiya Tespiti

Hədəfin HTTP cavabını (başlıqlar + HTML gövdəsi) **25+ nümunəyə** qarşı barmaq izinə alır:

| Kateqoriya | Aşkarlananlar |
|---|---|
| Veb serverlər | Apache, Nginx, LiteSpeed, IIS, Caddy |
| Dillər | PHP, ASP.NET |
| Çərçivələr | Django, Laravel, WordPress, Joomla, Drupal |
| Frontend | React, Next.js, Vue.js, Angular |
| CDN/Proxy | Cloudflare, Varnish, Fastly |
| E-ticarət | Shopify, Magento |
| Səhifə qurucuları | Wix, Squarespace |
| Təhlükəsizlik | ModSecurity, reCAPTCHA |

Nəticələr JSON çıxışında `technology` açarı altında verilir.

### JavaScript Endpoint Kəşfi

1. Ana səhifənin HTML-ni `<script src="...">` teqləri üçün analiz edir
2. Maksimum 5 JS dəstini yükləyir
3. Çıxarmaq üçün iki regex nümunəsi tətbiq edir:
   - API/marşrut formalarına uyğun yol literalları (`/api/`, `/v1/`, `/auth/`, `/graphql`, `/upload`, `/admin` və s.)
   - `url: "/api/users"`, `endpoint: "/rest/v2/..."` kimi açar-dəyər təyinatları

Çıxarılan endpoint-lər **sənədləşdirilməmiş API səthlərini** müəyyən etmək üçün faydalıdır və backend infrastrukturunun nümunələrinə işarə edə bilər.

### Favicon Hash Barmaq İzi

`/favicon.ico` yükləyir və Shodan-ın `http.favicon.hash` indeksi üçün istifadə etdiyi eyni alqoritmdən istifadə edərək **Shodan uyğun MurmurHash3 (32-bit)** hash hesablayır.

Çıxış aşağıdakıları ehtiva edir:

```
Favicon: mmh3=-1234567890  ölçü=1150B  http.favicon.hash:-1234567890
```

Shodan sorğusunu birbaşa `shodan.io/search`-ə yapışdıraraq eyni favicon-u xidmət edən digər serverləri tapa bilərsiniz — tamamilə gizli olduqda belə mənşə IP-lərini və əlaqəli infrastrukturu kəşf etmək üçün etibarlı bir üsul.

### GitHub Sızıntı Tespiti

Hədəf domainin həssas kontekstlərdə təsadüfən açıq qoyulduğu repozitoriyaları tapmaq üçün **GitHub açıq kod axtarış API**-sinə qarşı təhlükəsiz, yalnız oxuma sorğuları yerinə yetirir:

- Sadəcə domain adı
- Domain + `password`
- Domain + `api_key`
- Domain + `secret`
- Domain + `config`

Tapıntılar əl ilə yoxlama üçün repozitoriya adı, fayl adı və birbaşa URL-i ehtiva edir. Skaner daxili gecikmələrlə GitHub-un icazəsiz rate-limitinə riayət edir.

> Qeyd: Bu yalnız **testdir** — skaner fayl məzmununu heç vaxt oxumur, yalnız repozitoriya/fayl adı metadata-sını göstərir.

---

## Mənbə Etibarlılıq Skoru

Hər IP mənbəyi üç etibar pilləsindən birinə təsnif edilir. Pillə, həmin mənbənin inam skoruna verdiyi ağırlığı müəyyən edir.

### Pillələr

| Pillə | Ağırlıq | Nümunələr |
|---|---|---|
| `DIRECT` | 3 | Cari DNS, MX record, SPF record, Zone Transfer, TLS SAN, canlı subdomain resolve |
| `VERIFIED_API` | 2 | URLScan.io, AlienVault OTX, Shodan InternetDB, BGPView, ipinfo.io, crt.sh, CertSpotter, HackerTarget |
| `SCRAPED` | 1 | RapidDNS, BufferOver, Wayback Machine, ThreatMiner, Anubis, Əks IP, Favicon uyğunluğu |

### Skoral bonuslar

Pillə ağırlıqlarına əlavə olaraq aşağıdakı bonuslar tətbiq edilir:

| Şərt | Bonus |
|---|---|
| IP, MX və ya SPF record-da tapılıb | +3 |
| URLScan.io tərəfindən təsdiqlənib | +2 |
| AlienVault OTX tərəfindən təsdiqlənib | +2 |
| HackerTarget tərəfindən təsdiqlənib | +1 |
| IP canlı subdomain resolve vasitəsilə tapılıb | +1 |
| IP, TLS SAN-da tapılıb | +3 |
| 2+ müstəqil DIRECT mənbə | +4 |
| 1 DIRECT + 1 VERIFIED mənbə | +2 |

### Skor şərhi

| Skor | Çubuq | Məna |
|---|---|---|
| 10+ | `██████████` | Çox yüksək inam — çoxlu güclü siqnal |
| 5–9 | `█████` | Yüksək inam — çarpaz doğrulanmış |
| 2–4 | `███` | Orta — araşdırmağa dəyər |
| 1 | `█` | Aşağı — yalnız tək aşağı etibar mənbəyi |

---

## Çarpaz Doğrulama Məntiqi

Hər IP, təsdiqlənmiş kimi işarələnməzdən əvvəl çarpaz doğrulama qaydasına qarşı qiymətləndirilir:

```
ÇARPAZ DOĞRULANMIŞ  ✓  əgər:
   ≥ 2 müstəqil siqnal  (istənilən pillə)
   VƏ YA
   ≥ 1 DIRECT müşahidə   (canlı DNS, MX, SPF, TLS SAN, subdomain resolve)

DOĞRULANMAMIŞ       ⚠  əgər:
   yalnız 1 SCRAPED mənbəsi
```

Çıxışda çarpaz doğrulanmış IP-lər `✓ ÇARPAZ DOĞRULANMIŞ` ilə göstərilir. Tək mənbəli tapıntılar əl ilə yoxlamaq üçün xatırlatma kimi `⚠ tək mənbə` göstərir.

---

## Korrelyasiya Mühərriki

Bütün 16 faza tamamlandıqdan sonra Korrelyasiya Mühərriki kəşf edilmiş hər IP-ni emal edir və ona bir **infrastruktur rolu** təyin edir:

| Rol | Təsnifat Məntiqi |
|---|---|
| `ORIGIN` | CF-dən kənar, buludsuz, tək məqsədli, birdən çox OSINT mənbəsi ilə tapılıb |
| `CDN` | Cloudflare CIDR uyğunluğu, və ya bulud org = Fastly/Akamai/Imperva/Sucuri |
| `MAIL` | Yalnız MX record vasitəsilə tapılıb |
| `MAIL_INFRA` | SPF ip4 record vasitəsilə tapılıb |
| `API` | `api`, `gateway`, `rest`, `ws`, `graphql` ehtiva edən subdomain vasitəsilə həll edilib |
| `SHARED_HOST` | Əks IP 10+ əlaqəsiz ortaq domain qaytarır |
| `CLOUD_HOSTED` | AWS/GCP/Azure/DigitalOcean/s.-də hostalanıb, CDN maskalaması yoxdur |
| `UNKNOWN` | Təsnif etmək üçün məlumat kifayət deyil |

Son nəticə bölməsi yalnız **ORIGIN**, **CLOUD_HOSTED** və **API** namizədlərini göstərir. CDN, MAIL və SHARED_HOST IP-ləri JSON çıxışında qeyd edilir, lakin əsas tapıntılardan kənarlaşdırılır.

Ətraflı rejimdə (`-v`) tam infrastruktur xəritəsi göstərilir:

```
İnfrastruktur Xəritəsi:
  CDN            104.21.x.x, 172.67.x.x
  MAIL           209.85.x.x
  ORIGIN         203.0.113.x
  API            198.51.100.x
  SHARED_HOST    185.230.x.x
```

---

## JSON Çıxış Formatı

```json
{
  "domain": "example.com",
  "scan_time": "2024-01-15T14:32:01.123456",
  "elapsed_sec": 87.4,

  "real_candidates": {
    "203.0.113.42": {
      "sources": ["mx-record", "urlscan.io", "sub:staging.example.com"],
      "confidence": 14,
      "cross_validated": true,
      "role": "ORIGIN",
      "cloud_provider": null,
      "bgp": {
        "asn": "AS12345",
        "asn_name": "Example Hosting Ltd",
        "prefix": "203.0.113.0/24",
        "rir": "RIPE",
        "country": "DE"
      },
      "shodan": {
        "ports": [22, 80, 443],
        "vulns": [],
        "tags": ["self-signed"]
      },
      "rdns_count": 2
    }
  },

  "cloudflare_ips": ["104.21.x.x", "172.67.x.x"],

  "infrastructure_map": {
    "CDN":    ["104.21.x.x", "172.67.x.x"],
    "MAIL":   ["209.85.x.x"],
    "ORIGIN": ["203.0.113.42"]
  },

  "subdomains": {
    "total_checked": 347,
    "active": 23,
    "non_cf": [
      {"sub": "staging.example.com", "ip": "203.0.113.42"}
    ]
  },

  "dns_records": {
    "mx":      ["mail.example.com"],
    "spf_ips": ["203.0.113.10"],
    "ns":      ["ns1.cloudflare.com", "ns2.cloudflare.com"]
  },

  "tls": {
    "cn":         "example.com",
    "issuer":     "Let's Encrypt",
    "sans_count": 3,
    "sans":       ["example.com", "www.example.com", "staging.example.com"],
    "version":    "TLSv1.3",
    "cipher":     "TLS_AES_256_GCM_SHA384",
    "weak":       false
  },

  "technology":   ["Nginx", "PHP", "Laravel", "Cloudflare"],
  "js_endpoints": ["/api/v1/users", "/api/v1/auth/login", "/api/v2/products"],

  "favicon": {
    "url":          "https://example.com/favicon.ico",
    "size":         1150,
    "mmh3":         -1234567890,
    "md5":          "d41d8cd98f00b204e9800998ecf8427e",
    "shodan_query": "http.favicon.hash:-1234567890"
  },

  "github_leaks": [
    {
      "repo": "someuser/infra-configs",
      "file": "production.env",
      "url":  "https://github.com/someuser/infra-configs/blob/main/production.env"
    }
  ]
}
```

---

## Nəticələri Anlamaq

### "Real IP tapıldı" — bu nə deməkdir?

Nəticələrdə görünən IP, həmin domainin Cloudflare mühafizəsindən **əvvəl və ya kənar** olaraq ən azı bir OSINT mənbəsi tərəfindən həmin IP ilə əlaqələndirildiyini bildirir. Ümumi ssenarilər:

| Ssenari | İzahat |
|---|---|
| CF arxasında olmayan staging/dev subdomain | `staging.example.com` birbaşa həll olunur |
| Passiv DNS-də hələ qalan köhnə record | Domain CF-ə keçməzdən əvvəl burada hostalanırdı |
| Eyni hostda olan MX server | Mail serveri CDN-i tamamilə bypass edir |
| SPF record-un mənşə IP-ni sadalaması | E-poçt autentifikasiyası həqiqi IP-ni ifşa edir |
| Ortaq TLS sertifikatı | SAN, birbaşa açıq subdomain ehtiva edir |
| Açıq commit edilmiş konfiqurasiya | GitHub/Bitbucket repozitoriyası IP-ni sızdırır |

### İnam skoru aşağıdır — nəzərə almayım?

Aşağı skor daha az müstəqil mənbənin həmin IP-ni təsdiqlədiyi deməkdir. Bu, yanlış olduğu mənasına gəlmir. Aşağı inamlı tapıntıları əl ilə çarpaz yoxlayın:

1. IP-nin hədəf saytı ilə HTTP-yə cavab verib-vermədiyini yoxlayın
2. Birbaşa giriş üçün `curl -H "Host: example.com" http://<ip>` istifadə edin
3. Əlavə kontekst üçün IP-ni Shodan və ya Censys-də axtarın

### Real IP tapılmadısa nə olur?

Bu, aşağıdakılardan birini bildirir:

- Hədəf həmişə Cloudflare arxasında olub və mənşəyini heç vaxt ifşa etməyib
- CF-ə keçəndən sonra mənşə IP dəyişib (köhnə record-lar silinib)
- Hədəf mənşə IP-ni heç vaxt açmayan Cloudflare Tunnel-dən (Argo) istifadə edir

CF-Hunter-dən "nəticə yoxdur" məzmunlu cavab məlumatlıdır — bu, düzgün qurulmuş CDN konfiqurasiyasına işarə edir.

---

## API Açarları və Sürət Limitləri

CF-Hunter v4.0 standart olaraq yalnız **açıq, icazəsiz API-lərdən** istifadə edir. API açarları tələb olunmur.

| Xidmət | Sürət Limiti | Qeydlər |
|---|---|---|
| crt.sh | Səxavətli | Yüklənmə zamanı bəzən yavaş olur |
| CertSpotter | 100/saat (icazəsiz) | Daha yüksək limitlər üçün sslmate.com-da pulsuz API açarı mövcuddur |
| AlienVault OTX | ~100/gün (icazəsiz) | Daha yüksək limitlər üçün pulsuz API açarı mövcuddur |
| HackerTarget | 100/gün (icazəsiz) | Pulsuz planda məhdudlaşdırılır |
| URLScan.io | 100/gün (icazəsiz) | Pulsuz API açarı mövcuddur |
| BGPView | Açar tələb olunmur | Ağlabatan açıq sürət limiti |
| ip-api.com | 45 sorğu/dəq (icazəsiz) | HTTPS ödənişli plan tələb edir; alət HTTP endpoint-dən istifadə edir |
| Shodan InternetDB | Açar tələb olunmur | Yalnız oxuma port/zəiflik məlumatı |
| GitHub Kod Axtarışı | 10 sorğu/dəq (icazəsiz) | Alət sorğular arasında 1.2 saniyəlik gecikmələr ehtiva edir |

Aləti tez-tez istifadə edirsinizsə, onu təklif edən xidmətlər üçün pulsuz API açarları qurmağı düşünün. Gələcək versiyalar mühit dəyişəni vasitəsilə açar inyeksiyasını dəstəkləyə bilər.

---

## Arxitektura

```
cf_hunter_v4.py
│
├── Yardımçı Qat
│   ├── C                        Terminal rəng kodları
│   ├── http_get / http_json      Yenidən cəhd + SSL bypass ilə HTTP köməkçiləri
│   ├── http_get_with_headers     Gövdə + cavab başlıqlarını qaytarır
│   └── http_get_bytes            Xam baytlar (favicon yükləmə)
│
├── IP Kəşfiyyat Qatı
│   ├── is_cloudflare()           CIDR aralığı yoxlaması
│   ├── is_private()              RFC1918 / loopback yoxlaması
│   ├── classify_cloud()          ASN + org → bulud provayderə
│   ├── ip_info()                 ipinfo.io zənginləşdirməsi
│   ├── bgpview_lookup()          BGPView API
│   ├── ipapi_info()              ip-api.com işarələri
│   └── reverse_ip_lookup()       HackerTarget əks IP
│
├── OSINT Mənbə Qatı (orijinal 12 + yeni)
│   ├── src_crtsh / src_certspotter
│   ├── src_alienvault / src_hackertarget / src_urlscan
│   ├── src_threatminer / src_anubis / src_wayback
│   ├── src_rapiddns / src_bufferover
│   └── shodan_info
│
├── Aktiv Analiz Qatı
│   ├── dns_records_analysis      DoH əsaslı MX/TXT/SPF/NS
│   ├── try_zone_transfer         AXFR (dnspython tələb edir)
│   ├── brute_subs                200 sözdən ibarət subdomain siyahısı
│   └── resolve_all               Paralel DNS həlli (60 thread)
│
├── Dərin Analiz Qatı (v4-də yeni)
│   ├── tls_analyze               TLS sertifikatı · SAN · cipher · zəiflik
│   ├── tls_san_to_ips            SAN → IP həlli
│   ├── detect_technology         Başlıq + HTML barmaq izi
│   ├── extract_js_endpoints      JS skript yükləmə + endpoint regex
│   ├── favicon_hash              mmh3 / md5 favicon barmaq izi
│   └── github_leak_scan          Təhlükəsiz GitHub kod axtarışı
│
├── Skorlama və Doğrulama Qatı (v4-də yeni)
│   ├── SOURCE_TRUST              Mənbə → (pillə, ağırlıq) xəritəsi
│   ├── source_trust()            Mənbə etibarlılığı axtarışı
│   ├── confidence_score()        Ağırlıqlı çox mənbəli skorlama
│   └── cross_validated()         2+ siqnal doğrulama yoxlaması
│
└── Korrelyasiya Mühərriki (v4-də yeni)
    └── CorrelationEngine
        ├── add_ip()              IP-ni metadata ilə qeyd et
        ├── _classify_role()      ORIGIN/CDN/MAIL/API/SHARED_HOST
        ├── get_summary()         Rol → IP qruplaması
        └── origin_candidates()   Sıralanmış CDN-dən kənar IP-lər
```

---

## Hüquqi Məsuliyyət və Etika

CF-Hunter yalnız **passiv və yarı-passiv kəşfiyyat** həyata keçirir:

- Heç bir zəifliyə istismar etmir
- Hücum trafiği göndərmir
- Autentifikasiya bypass-ına cəhd etmir
- Açıq Shodan məlumatlarını oxumaqdan kənar port skanı aparmır
- GitHub sızıntı tespiti yalnız açıq axtarış nəticələrindən istifadə edir (şəxsi repozitoriyalara giriş yoxdur)

**Hər hansı bir hədəfi skanlamadan əvvəl icazəyə sahib olduğunuzdan əmin olmaq məsuliyyəti sizin üzərinizdədir.** İcazəsiz skan Kompüter Saxtakarlığı və Sui-istifadə Qanunu (CFAA), Kompüterin Sui-istifadəsi Qanunu (CMA), GDPR və jurisdiksiyanızdakı müvafiq qanunları poza bilər.

Qanuni istifadə halları:

- Öz infrastrukturunuzda penetrasiya testi
- Açıq scope icazəsi olan bug bounty proqramları
- İmzalanmış müqavilə çərçivəsində təhlükəsizlik auditi
- Öz test domainlərinizdə akademik və ya tədris tədqiqatı

---

*CF-Hunter v4.0 — @f1r10*
