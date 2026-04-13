# AegisRecon Hesabatı

## Meta

- Hədəf: `yer.az`
- Kök: `yer.az`
- Başlama vaxtı: `2026-04-13T09:22:26Z`
- Bitmə vaxtı: `2026-04-13T09:24:12Z`
- Domain sayı: `5`
- IP sayı: `0`
- Safe mode: `True`

## Mənbə etibarlılığı modeli

- `DIRECT_OBSERVATION` → trust `0.95` — Birbaşa müşahidə olunan nəticə
- `VERIFIED_API` → trust `0.75` — Rəsmi və ya etibarlı API nəticəsi
- `SCRAPED_DATA` → trust `0.45` — Scrape edilmiş, daha aşağı etibarlı məlumat

## Əsas tapıntılar

### 1. API surface genişdir: www.yer.az
- Kateqoriya: `Attack Surface`
- Severity: `info`
- Confidence: `1.0`
- Validated: `True`
- Tag-lər: `javascript, endpoint-discovery, api`
- İzah: JavaScript içindən 6 endpoint aşkarlandı.
- Sübutlar:
  - `javascript_parser` / `DIRECT_OBSERVATION` / trust `0.95` — JS/API route aşkarlanması

### 2. API surface genişdir: yer.az
- Kateqoriya: `Attack Surface`
- Severity: `info`
- Confidence: `1.0`
- Validated: `True`
- Tag-lər: `javascript, endpoint-discovery, api`
- İzah: JavaScript içindən 6 endpoint aşkarlandı.
- Sübutlar:
  - `javascript_parser` / `DIRECT_OBSERVATION` / trust `0.95` — JS/API route aşkarlanması

### 3. Certificate reuse aşkarlanıb
- Kateqoriya: `TLS`
- Severity: `info`
- Confidence: `1.0`
- Validated: `True`
- Tag-lər: `tls, certificate-reuse, infrastructure-clustering`
- İzah: Eyni TLS sertifikatı bu hostlarda istifadə olunur: www.yer.az, yer.az
- Sübutlar:
  - `tls_certificate` / `DIRECT_OBSERVATION` / trust `0.95` — Eyni sertifikat birdən çox hostda

### 4. Favicon hash oxşarlığı
- Kateqoriya: `Infrastructure`
- Severity: `info`
- Confidence: `1.0`
- Validated: `True`
- Tag-lər: `favicon, similarity, clustering`
- İzah: Eyni mmh3 favicon izi bu hostlarda görünür: www.yer.az, yer.az
- Sübutlar:
  - `favicon_hash` / `DIRECT_OBSERVATION` / trust `0.95` — Eyni favicon izi

### 5. Mail infrastrukturu aşkarlandı: www.yer.az
- Kateqoriya: `Infrastructure`
- Severity: `info`
- Confidence: `0.955`
- Validated: `True`
- Tag-lər: `mail-server, mx`
- İzah: MX qeydləri tapıldı: 1 mail.yer.az
- Sübutlar:
  - `dns_mx` / `DIRECT_OBSERVATION` / trust `0.95` — MX qeydləri

### 6. Mail infrastrukturu aşkarlandı: yer.az
- Kateqoriya: `Infrastructure`
- Severity: `info`
- Confidence: `0.955`
- Validated: `True`
- Tag-lər: `mail-server, mx`
- İzah: MX qeydləri tapıldı: 1 mail.yer.az
- Sübutlar:
  - `dns_mx` / `DIRECT_OBSERVATION` / trust `0.95` — MX qeydləri

## Domain-lər

### www.yer.az
- IP-lər: `-`
- CNAME: `-`
- MX: `1 mail.yer.az`
- Texnologiyalar: `Nginx`
- Favicon hash: `-1442303106`
- TLS versiya: `TLSv1.3`
- Sertifikat SHA256: `8c9014b43109b758826813ca393ea319b572f8b4762ad3727fd5e07fc25bb1ad`
- SAN sayı: `6`
- Endpoint nümunələri:
  - `https://www.google.com/ccm/geo`
  - `www.gstatic.com/call-tracking/call-tracking_`
  - `www.gstatic.com/gaphone/loader.js`
  - `www.gstatic.com/wcm/loader.js`
  - `//vimeo.com/api/v2/video/`
  - `//vzaar.com/api/videos/`

### yer.az
- IP-lər: `-`
- CNAME: `-`
- MX: `1 mail.yer.az`
- Texnologiyalar: `Nginx`
- Favicon hash: `-1442303106`
- TLS versiya: `TLSv1.3`
- Sertifikat SHA256: `8c9014b43109b758826813ca393ea319b572f8b4762ad3727fd5e07fc25bb1ad`
- SAN sayı: `6`
- Endpoint nümunələri:
  - `https://www.google.com/ccm/geo`
  - `www.gstatic.com/call-tracking/call-tracking_`
  - `www.gstatic.com/gaphone/loader.js`
  - `www.gstatic.com/wcm/loader.js`
  - `//vimeo.com/api/v2/video/`
  - `//vzaar.com/api/videos/`

### yer.az (fqdn) --> mx_record --> mail.yer.az (fqdn)
- IP-lər: `-`
- CNAME: `-`
- MX: `-`
- Texnologiyalar: `-`
- Favicon hash: `None`

### yer.az (fqdn) --> ns_record --> nizami.yer.az (fqdn)
- IP-lər: `-`
- CNAME: `-`
- MX: `-`
- Texnologiyalar: `-`
- Favicon hash: `None`

### yer.az (fqdn) --> ns_record --> ulduz.yer.az (fqdn)
- IP-lər: `-`
- CNAME: `-`
- MX: `-`
- Texnologiyalar: `-`
- Favicon hash: `None`

## IP-lər
