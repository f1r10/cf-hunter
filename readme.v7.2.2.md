# CF-HUNTER v7.2.2 SAFE — Tam İstifadə Bələdçisi

Bu sənəd `cf_hunter_v7.2.2.py` üçün praktik və sadə istifadəyə yönəlib. Məqsəd təkcə flag-ları göstərmək deyil, **hansı ssenaridə hansı command-ı niyə işlətməli olduğunu** aydın izah etməkdir.

---

## 1. Bu alət nə üçündür

CF-HUNTER v7.2.2 Cloudflare arxasında olan və ya CDN/proxy istifadə edən hədəflər üçün:

- passive recon
- DNS/TLS analiz
- non-CF subdomain aşkarlanması
- origin candidate scoring
- təhlükəsiz public posture audit
- analyst-friendly report çıxışı

üçün hazırlanmış təhlükəsiz analiz alətidir.

Bu versiya əvvəlki versiyaların imkanlarını saxlayır və üstünə bunları əlavə edir:

- daha dürüst weighted evidence scoring
- negative evidence scoring
- explanation / səbəb qatları
- executive summary və analyst summary
- CSV, full CSV, Markdown və TXT export
- stage-level checkpoint və resume
- daha detallı timeout/environment diaqnostikası

---

## 2. Nə etmir

Bu alət aşağıdakıları etmir:

- exploit işlətmir
- auth bypass etmir
- bruteforce etmir
- destructive fuzzing etmir
- müdafiə bypass etməyə yönəlmiş avtomatlaşdırma etmir

Yəni bu alət **təhlükəsiz recon + analysis + posture review** üçündür.

---

## 3. Vacib texniki qeyd

`cf_hunter_v7.2.2.py` daxilində baza fayl kimi `cf_hunter_v7.2.1.py` yüklənir.

Kodda bu sətr var:

```python
BASE_PATH = "cf_hunter_v7.2.1.py"
```

Bu o deməkdir ki:

1. `v7.2.1` faylı mövcud olmalıdır
2. Faylı başqa qovluğa köçürəcəksənsə, `BASE_PATH`-i düzəltməlisən

Ən rahat variant:

- `cf_hunter_v7.2.2.py`
- `cf_hunter_v7.2.1.py`

eyni mühitdə saxlanılsın.

---

## 4. Tələblər

Minimum:

- Python 3.10+
- internet çıxışı
- yazma icazəsi olan qovluq

Praktik olaraq bunlar faydalıdır:

- stabil şəbəkə
- IPv4 çıxışı
- mümkün olsa IPv6 çıxışı
- JSON/Markdown fayl yazmaq üçün disk icazəsi

---

## 5. Ən sadə istifadə

Ən sadə nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com
```

Bu nə edir:

- domain-i normallaşdırır
- baza recon mərhələlərini işlədir
- nəticəni terminalda göstərir
- fayla yazmır

Bu nə vaxt uyğundur:

- ilkin baxış
- domain test
- alətin işlədiyini yoxlamaq

---

## 6. Ən vacib flag-lar və nə üçündür

### `domain`
Məcburi parametrdir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com
```

---

### `-o, --output`
JSON report faylı yaradır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com -o report.json
```

Niyə istifadə olunur:

- nəticəni saxlamaq üçün
- sonradan analiz etmək üçün
- report pipeline-a vermək üçün

---

### `-v, --verbose`
Ətraflı çıxış verir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com -v
```

Niyə istifadə olunur:

- mərhələlərin gedişini görmək üçün
- hansı hissənin ləngidiyini anlamaq üçün
- debug üçün

---

### `--full`
Ən geniş və ən dərin təhlükəsiz analiz rejimidir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full -o report.json
```

Niyə istifadə olunur:

- maksimum coverage üçün
- candidate scoring, posture, report və əlavə analiz qatları birlikdə işə düşsün deyə
- bir domain üçün əsas tam scan etmək üçün

Bu nə vaxt seçilməlidir:

- vacib target
- report hazırlayanda
- “bir dəfə amma dolu” scan istəyəndə

---

### `--quick`
Daha sürətli və yüngül rejimdir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --quick -o quick.json
```

Niyə istifadə olunur:

- ilkin triage
- birdən çox domain üzərində qısa yoxlama
- vaxt az olanda

Qeyd:

- ən detallı nəticə üçün yox
- sürətli ilkin qiymətləndirmə üçün

---

### `--recon-only`
Əsasən recon yönümlü rejim.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --recon-only -o recon.json
```

Niyə istifadə olunur:

- passive source toplamaq üçün
- subdomain/IP xəritəsi çıxarmaq üçün
- auditdən çox kəşfiyyat istəyəndə

Bu nə vaxt uyğundur:

- origin hunting başlanğıcı
- hədəfin infra xəritəsini çıxarmaq

---

### `--posture-only`
Yalnız public posture audit yönümlü rejim.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --posture-only -o posture.json
```

Niyə istifadə olunur:

- security headers
- public exposure
- safe path checks
- reportable posture məsələləri

Bu nə vaxt uyğundur:

- bug bounty üçün təhlükəsiz yoxlama
- reportable surface review

---

### `--verify-only`
Yalnız verify mərhələsinə fokuslanır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --verify-only -o verify.json
```

Niyə istifadə olunur:

- candidate-lərin response davranışını yoxlamaq üçün
- tam recon-u təkrar etmədən verify hissəsinə baxmaq üçün

---

### `--no-github`
GitHub leak scan hissəsini söndürür.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-github -o report.json
```

Niyə istifadə olunur:

- scan-i bir az yüngülləşdirmək üçün
- GitHub axtarışını istəməyəndə
- noise azaltmaq üçün

---

### `--skip-verify`
Verify mərhələsini atlayır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --recon-only --skip-verify -o noverify.json
```

Niyə istifadə olunur:

- yalnız passive/topology məlumatı istəyəndə
- verify hissəsinin vaxt aparmasını istəməyəndə

Diqqət:

- nəticə daha az etibarlı olar
- origin confidence aşağı düşər

---

### `--verify-workers`
Verify worker sayını təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --verify-workers 24 -o report.json
```

Niyə istifadə olunur:

- daha çox candidate olduqda verify sürətini artırmaq üçün

Praktik tövsiyə:

- 12 → default, balanslı
- 20–24 → orta/yüksək yük
- 30+ → yalnız stabil şəbəkədə

---

### `--resolve-workers`
DNS/subdomain resolve worker sayını təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --resolve-workers 80 -o report.json
```

Niyə istifadə olunur:

- çox subdomain yoxlamasında sürəti artırmaq üçün

Praktik tövsiyə:

- 60 → normal
- 80–120 → güclü sistemlər üçün

---

### `--posture-workers`
Posture audit worker sayını təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --posture-workers 15 -o report.json
```

Niyə istifadə olunur:

- safe path və posture yoxlamalarını sürətləndirmək üçün

---

### `--no-cache`
Cache-i söndürür.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-cache -o fresh.json
```

Niyə istifadə olunur:

- tam təzə nəticə istəyəndə
- cache nəticəsinə güvənmək istəməyəndə

Nə vaxt istifadə etmək lazımdır:

- əvvəllər scan olunubsa və indi tam fresh nəticə istəyirsənsə

---

### `--cache-ttl`
Cache-in etibarlılıq müddətini saniyə ilə təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --cache-ttl 86400 -o report.json
```

Niyə istifadə olunur:

- eyni target-də tez-tez işləyirsənsə, boş yerə yenidən source çağırmasın deyə

Praktik mənalar:

- `21600` → 6 saat
- `43200` → 12 saat
- `86400` → 24 saat

---

### `--no-resume`
Daxili state/resume mexanizmini söndürür.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-resume -o clean.json
```

Niyə istifadə olunur:

- tam “təmiz” icra istəyəndə
- əvvəlki state-lə qarışmasını istəməyəndə

---

### `--save-state`
Əlavə checkpoint state faylları saxlayır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --save-state -o report.json
```

Niyə istifadə olunur:

- scan uzun çəkirsə
- mərhələləri ayrıca izləmək istəyirsənsə
- sonradan diaqnostika aparmaq istəyirsənsə

Faydalıdır:

- böyük targetlər
- qeyri-sabit şəbəkə
- analyst workflow

---

### `--md-report`
Markdown report yaradır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --md-report -o report.json
```

Niyə istifadə olunur:

- insan oxumağı üçün rahat format əldə etmək
- report drafting üçün hazır material saxlamaq

Qeyd:

- JSON ilə birlikdə istifadə etmək daha yaxşıdır
- `report.json` versən, adətən `report.md` də yaranır

---

### `--export-csv`
Candidate comparison üçün CSV yaradır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --export-csv candidates.csv -o report.json
```

Niyə istifadə olunur:

- candidate-ləri cədvəl şəklində müqayisə etmək üçün
- Excel/Sheets-də açmaq üçün

---

### `--full-csv`
Tam evidence ledger CSV yaradır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --full-csv evidence.csv -o report.json
```

Niyə istifadə olunur:

- bütün siqnalları xam şəkildə çıxarmaq üçün
- analyst-level audit trail saxlamaq üçün

---

### `--export-txt`
Executive və analyst summary üçün sadə text faylı yaradır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --export-txt summary.txt -o report.json
```

Niyə istifadə olunur:

- qısa nəticə paylaşmaq üçün
- ticket və ya note kimi istifadə etmək üçün

---

### `--top`
Top N namizədi saxlayır və çıxışda qısaldır.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --top 10 -o report.json
```

Niyə istifadə olunur:

- böyük nəticədə yalnız ən güclü namizədləri saxlamaq üçün
- report-u təmiz saxlamaq üçün

---

### `--explain <ip>`
Müəyyən IP üçün səbəb izahını göstərir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --explain 154.197.121.1 -o report.json
```

Niyə istifadə olunur:

- “bu IP niyə yüksəlib?” sualına cavab almaq üçün
- scoring-i başa düşmək üçün
- false positive-i ayırmaq üçün

---

### `--probe-timeout`
IP probe timeout dəyərini təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --probe-timeout 10 -o report.json
```

Niyə istifadə olunur:

- yavaş cavab verən targetlərdə vaxtı artırmaq üçün
- daha dəqiq verify üçün

Praktik tövsiyə:

- 6 → normal
- 8–10 → yavaş mühit üçün
- çox yüksək dəyərlər → scan-i həddən artıq uzada bilər

---

### `--probe-retries`
Probe retry sayını təyin edir.

Nümunə:

```bash
python3 cf_hunter_v7.2.2.py example.com --full --probe-retries 3 -o report.json
```

Niyə istifadə olunur:

- bir dəfəlik timeout-ları daha ədalətli qiymətləndirmək üçün
- zəif şəbəkə hallarında daha düzgün nəticə almaq üçün

---

## 7. Ssenariyə görə hazır command-lar

### Ssenari 1 — Təkcə alətin işlədiyini yoxlamaq istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com -v
```

Niyə bu command:

- ən sadə başlayışdır
- verbose açıqdır, mərhələləri görürsən
- fayl yaratmadan ilkin test edirsən

---

### Ssenari 2 — Vacib target üçün tam scan istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

Niyə bu command:

- `--full` ən geniş coverage verir
- `-v` proses görünür
- `-o report.json` strukturlaşdırılmış əsas report verir
- `--md-report` insan üçün oxunaqlı report yaradır
- `--export-csv` candidate müqayisəsi verir
- `--full-csv` bütün evidence-ləri çıxarır
- `--export-txt` qısa summary çıxarır

Bu nə vaxt ən yaxşı seçimdir:

- bir domain üçün əsas final scan
- report hazırlamaq
- analyst review etmək

---

### Ssenari 3 — Vaxt azdır, sürətli triage lazımdır

```bash
python3 cf_hunter_v7.2.2.py example.com --quick -o quick.json
```

Niyə bu command:

- yüngül rejimdir
- ilkin qərar üçün yaxşıdır
- böyük target siyahısında ilk mərhələ kimi uyğundur

Bu nə vaxt uyğundur:

- birdən çox target var
- əvvəlcə qısa süzmə edirsən

---

### Ssenari 4 — Sənə əsasən recon lazımdır

```bash
python3 cf_hunter_v7.2.2.py example.com --recon-only -v --export-csv recon_candidates.csv -o recon.json
```

Niyə bu command:

- recon hissəsinə fokuslanır
- CSV candidate müqayisəsi verir
- JSON sonradan işləmək üçün qalır

Bu nə vaxt uyğundur:

- infra/topology çıxarmaq
- origin namizədləri toplamaq
- posture audit ikinci plandadırsa

---

### Ssenari 5 — Sənə əsasən təhlükəsiz posture audit lazımdır

```bash
python3 cf_hunter_v7.2.2.py example.com --posture-only -v --md-report -o posture.json
```

Niyə bu command:

- unnecessary recon qatını azaltmağa kömək edir
- reportable public posture problemlərinə fokuslanır
- Markdown report oxumağı rahat edir

Bu nə vaxt uyğundur:

- bug bounty safe review
- security header və exposure review
- qısa audit report

---

### Ssenari 6 — Namizədləri daha dəqiq verify etmək istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --verify-only -v --probe-timeout 10 --probe-retries 3 -o verify.json
```

Niyə bu command:

- verify hissəsinə fokuslanır
- timeout artırılır
- retry artırılır
- yavaş cavab verən mühitdə daha ədalətli nəticə alırsan

Bu nə vaxt uyğundur:

- əvvəlki scan-də çox timeout olmuşdusa
- candidate-lərin davranışını yenidən ölçmək istəyirsənsə

---

### Ssenari 7 — GitHub hissəsini söndürüb daha təmiz scan istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-github -o report.json
```

Niyə bu command:

- bəzi targetlərdə GitHub hissəsi noise yarada bilər
- daha təmiz nəticə istəyirsənsə uyğundur

---

### Ssenari 8 — Yalnız top nəticələri saxlamaq istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full --top 10 -o top10.json
```

Niyə bu command:

- report-u qısa saxlayır
- zəif namizədlər içində itmirsən

---

### Ssenari 9 — Müəyyən IP-ni izah etmək istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full --explain 154.197.121.1 -o report.json
```

Niyə bu command:

- konkret IP üçün səbəbləri göstərir
- scoring və negative evidence-i başa düşməyə kömək edir

---

### Ssenari 10 — Uzun scan, amma state də saxlamaq istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full --save-state -o report.json
```

Niyə bu command:

- mərhələ checkpoint-ləri saxlanır
- sonradan diaqnostika və təkrar baxış rahat olur

---

### Ssenari 11 — Tam fresh nəticə istəyirsən

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-cache --no-resume -o fresh.json
```

Niyə bu command:

- köhnə cache və state təsirini sıfırlayır
- “təmizdən” scan edir

Bu nə vaxt uyğundur:

- əvvəlki nəticələrə inanmırsansa
- mühit dəyişibsə

---

### Ssenari 12 — Mənə dəqiqlik sürətdən vacibdir

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --probe-timeout 10 --probe-retries 3 --verify-workers 24 --resolve-workers 80 --posture-workers 15 --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

Niyə bu command:

- timeout artırılır → yavaş mühitdə daha ədalətli nəticə
- retry artırılır → təsadüfi timeout-lar azalır
- worker-lər balanslı qaldırılır
- bütün əsas export-lar çıxır

Bu sənin dediyin profil üçün ən yaxşı seçimlərdən biridir.

---

## 8. Praktik tövsiyə olunan command dəstləri

### A. Gündəlik balanslı istifadə

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --verify-workers 18 --resolve-workers 70 --posture-workers 12 --md-report -o report.json
```

Niyə:

- nə çox ağırdır, nə çox zəif
- gündəlik iş üçün balanslıdır

---

### B. Maksimum detal və analyst output

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --probe-timeout 10 --probe-retries 3 --verify-workers 24 --resolve-workers 80 --posture-workers 15 --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt --save-state -o report.json
```

Niyə:

- ən zəngin analyst workflow budur
- JSON + MD + CSV + TXT birlikdə çıxır
- checkpoint də saxlanır

---

### C. Sürətli triage

```bash
python3 cf_hunter_v7.2.2.py example.com --quick --top 10 -o quick.json
```

Niyə:

- sürətli və yığcamdır
- top nəticələri saxlayır

---

### D. Fresh re-run

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-cache --no-resume --probe-timeout 8 --probe-retries 2 -o rerun.json
```

Niyə:

- köhnə state təsirini təmizləyir
- yenidən obyektiv scan verir

---

## 9. Çıxış faylları nə verir

### JSON (`-o report.json`)
Əsas strukturlaşdırılmış nəticədir.

İçində bunlar ola bilər:

- meta
- source_health
- dns_records
- subdomains
- public_posture
- verify_results
- candidate_comparison
- evidence_ledger
- executive_summary
- analyst_summary
- timeout_profile

Bu nə üçün yaxşıdır:

- avtomatlaşdırma
- sonradan emal
- parser yazmaq

---

### Markdown (`--md-report`)
İnsan üçün oxunaqlı report.

Bu nə üçün yaxşıdır:

- manual review
- report drafting
- paylaşım

---

### Candidate CSV (`--export-csv`)
Ən əsas namizədləri cədvəl şəklində verir.

Bu nə üçün yaxşıdır:

- Excel/Sheets
- prioritet sıralama
- analyst müqayisəsi

---

### Full CSV (`--full-csv`)
Bütün evidence ledger-i çıxarır.

Bu nə üçün yaxşıdır:

- dərin audit trail
- scoring səbəblərini xam görmək
- sonradan data analysis etmək

---

### TXT summary (`--export-txt`)
Qısa mətn xülasəsi.

Bu nə üçün yaxşıdır:

- note
- ticket
- qısa paylaşım

---

## 10. Nəticəni necə oxumaq lazımdır

Ən vacib qayda:

- çox candidate çıxması = yaxşı nəticə demək deyil
- yüksək confidence həmişə origin demək deyil
- negative evidence çox vacibdir

Nəyə bax:

1. `candidate_comparison`
2. `evidence_ledger`
3. `timeout_profile`
4. `public_posture`
5. `source_health`
6. `analyst_summary`
7. `--explain <ip>` çıxışı

Praktik olaraq belə yanaş:

- əvvəl executive summary oxu
- sonra top candidate-lərə bax
- sonra explain ilə konkret IP-ləri aç
- sonda full CSV ilə xam evidence-lərə bax

---

## 11. Hansı rejimi nə vaxt işlətməli

| Məqsəd | Tövsiyə olunan rejim |
|---|---|
| İlkin test | sadə və ya `-v` |
| Tam scan | `--full` |
| Sürətli triage | `--quick` |
| Yalnız recon | `--recon-only` |
| Yalnız posture | `--posture-only` |
| Yalnız verify | `--verify-only` |
| Təmiz fresh scan | `--full --no-cache --no-resume` |
| Dərin analyst workflow | `--full` + `--md-report` + `--export-csv` + `--full-csv` + `--export-txt` |
| IP izahı | `--explain <ip>` |

---

## 12. Ən çox verilən praktik suallar

### Domain yerinə URL verə bilərəm?
Bəli, alət URL-ni normallaşdırmağa çalışır, amma ən yaxşısı birbaşa domain verməkdir.

Yaxşı:

```bash
python3 cf_hunter_v7.2.2.py example.com
```

Daha az ideal:

```bash
python3 cf_hunter_v7.2.2.py https://example.com/path
```

---

### Nəticə niyə çox `null` ola bilər?
Səbəblər:

- target cavab vermir
- timeout var
- environment blokludur
- origin birbaşa əlçatmazdır
- IPv6 unreachable-dir

Bu halda `timeout_profile` və `environment_signal` hissəsinə bax.

---

### Nəticə boş çıxsa alət pis işləyib?
Mütləq yox.

Bəzən bu o deməkdir ki:

- hədəf düzgün qorunub
- direct response yoxdur
- source-lar zəif siqnal verib

---

### Mənə sürətdən çox dəqiqlik vacibdir. Nə edim?
Bu command ən uyğunlardan biridir:

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --probe-timeout 10 --probe-retries 3 --verify-workers 24 --resolve-workers 80 --posture-workers 15 --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

---

## 13. Tövsiyə olunan iş axını

### Variant 1 — Sadə analyst workflow

1. `--full` ilə scan et
2. executive summary oxu
3. top candidate-lərə bax
4. `--explain` ilə konkret IP-ləri aç
5. Markdown report-u yoxla

---

### Variant 2 — Dərin workflow

1. `--full` + bütün export-lar ilə scan et
2. `candidate_comparison`-a bax
3. `full-csv` ilə evidence-ləri aç
4. `timeout_profile` və `environment_signal` yoxla
5. `public_posture` hissəsini report üçün istifadə et

---

### Variant 3 — Çox target workflow

1. əvvəl `--quick`
2. maraqlı targetlərdə `--full`
3. lazım gələrsə `--full --no-cache --no-resume` ilə təzədən işlə

---

## 14. Nümunə kommandların qısa siyahısı

### Tam scan

```bash
python3 cf_hunter_v7.2.2.py example.com --full -o report.json
```

### Tam scan + analyst export

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

### Sürətli scan

```bash
python3 cf_hunter_v7.2.2.py example.com --quick -o quick.json
```

### Recon-only

```bash
python3 cf_hunter_v7.2.2.py example.com --recon-only -o recon.json
```

### Posture-only

```bash
python3 cf_hunter_v7.2.2.py example.com --posture-only -o posture.json
```

### Verify-only

```bash
python3 cf_hunter_v7.2.2.py example.com --verify-only -o verify.json
```

### Fresh full scan

```bash
python3 cf_hunter_v7.2.2.py example.com --full --no-cache --no-resume -o fresh.json
```

### IP explain

```bash
python3 cf_hunter_v7.2.2.py example.com --full --explain 154.197.121.1 -o report.json
```

### Dəqiqlik prioritetli scan

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --probe-timeout 10 --probe-retries 3 --verify-workers 24 --resolve-workers 80 --posture-workers 15 --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

---

## 15. Son tövsiyə

Əgər yalnız bir command yadda saxlayacaqsansa, bunu saxla:

```bash
python3 cf_hunter_v7.2.2.py example.com --full -v --probe-timeout 10 --probe-retries 3 --verify-workers 24 --resolve-workers 80 --posture-workers 15 --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

Bu nə üçün ən yaxşı ümumi seçimdir:

- `--full` → maksimum coverage
- `-v` → proses görünür
- timeout/retry → daha ədalətli verify
- worker-lər → balanslı sürət
- MD/CSV/TXT/JSON → həm analyst, həm report, həm arxiv üçün çıxış

---

## 16. Fayl yolları haqqında praktik məsləhət

Ən rahat istifadə üçün ayrıca qovluq aç:

```bash
mkdir -p scans/example
cd scans/example
python3 /path/to/cf_hunter_v7.2.2.py example.com --full -v --md-report --export-csv candidates.csv --full-csv evidence.csv --export-txt summary.txt -o report.json
```

Bu niyə yaxşıdır:

- bütün nəticələr səliqəli qalır
- JSON/MD/CSV/TXT qarışmır
- sonradan arxivləmək asan olur

---

## 17. Yekun

CF-HUNTER v7.2.2 ən yaxşı nəticəni o zaman verir ki:

- məqsədinə uyğun rejim seçəsən
- `--full`-u vacib targetlərdə işlədəsən
- `--explain` və export fayllarını birlikdə istifadə edəsən
- timeout və retry-ni targetə uyğun tənzimləyəsən

Ən praktik yanaşma budur:

- çox target → əvvəl `--quick`
- vacib target → `--full`
- final analiz → JSON + MD + CSV + TXT
- şübhəli namizəd → `--explain <ip>`

