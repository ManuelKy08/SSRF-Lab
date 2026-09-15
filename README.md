# SSRF-Lab

Laboratorium **Server-Side Request Forgery (SSRF)** dengan **5 vektor kerentanan yang jarang diangkat**, masing-masing disusun dari kasus nyata di program Bug Bounty besar. Semua eksekusi exploit dilakukan **oleh server** (bukan browser), biar attacker path-nya realistis.

> 🔬 Lab lokal / Docker-only — jangan pernah di-deploy ke publik.

---

## ✨ Toggle RENTAN / FIXED

Setiap skenario bisa di-switch satu tombol:
- **RENTAN** (default) → kode rawan seperti di produksi yang belum di-patch.
- **FIXED** → versi yang sudah menerapkan mitigasi beneran (jadi pembanding).

## 🧨 5 Vektor Unik

| # | Vektor | Kerentanan | Analog real (BBP) |
|---|--------|------------|-------------------|
| 1 | **Image proxy** (bandwidth saver) menyisip URL user | Fetch tanpa validasi host → tembus `127.0.0.1` | "SSRF on image throttling/thumbnail" |
| 2 | **Avatar dari URL** (register pakai URL) | Scheme tidak difilter → **`file://` local file read** (credential + flag) | SSRF → arbitrary file read |
| 3 | **Content checker** | Denylist IP literal lenyap oleh **redirect + domain attacker** (`r.evil` → loopback) | Redirect-based filter bypass |
| 4 | **Webhook endpoint** | URL callback tak divalidasi → server **men-DO-RING** internal, respon bocor | SSRF via webhook/callback parameter |
| 5 | **Cloud metadata reader** | Filter *legacy* lupa blokir **`169.254.0.0/16`** (link-local) → **IAM credentials** bocor | GCP/AWS metadata SSRF (mis. report $25k) |

**Target internal:** service kedua (port 5091) yang hanya bisa dijangkau dari dalam (di Docker, port internal **tidak** dipublish ke host — jadi SSRF adalah *satu-satunya* jalan masuk).

Flag: `SSRF-LAB{...}`.

## 🚀 Cara menjalankan

### Docker (paling gampang & versi aman)

```bash
git clone https://github.com/ManuelKy08/SSRF-Lab.git
cd SSRF-Lab
docker compose up -d --build
```

Buka http://127.0.0.1:5092

- Tidak butuh Python/Flask ter-install (image `python:3.13-slim`).
- Port yang ke-expose cuma `5092`; internal service port 5091 **berada di dalam container** (invisible dari host) — persis seperti internal service di dunia nyata.
- Tiap `docker compose up` state di-reset ke **RENTAN** (deterministik):

```bash
docker compose down          # stop
docker compose down -v       # stop + bersihkan volume database
docker compose logs -f       # lihat log
```

### Lokal (tanpa Docker)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (bash: source .venv/bin/activate)
pip install -r requirements.txt
python -m app.main              # auto-buka browser → 5092
```

Jalankan dari folder repo. Browser terbuka otomatis di `http://127.0.0.1:5092`; saat lokal, internal service juga bisa diakses langsung di `http://127.0.0.1:5091` (di Docker tidak).

## 🧭 Isi Repo

```
app/            # Flask: routes (lab), models (sqlite), internal (service korban)
templates/      # halaman HTML neon (dashboard, fitur, logs)
static/         # css/js
payloads/       # set request exploit (curl) per skenario
docs/           # penjelasan lab + cheat-sheet audit SSRF
secret.txt      # file lokal yang dibaca exploit file:// (backburner credential)
```

- **Dashboard**: toggle mode + tombol "Jalankan Exploit" untuk semua skenario.
- **Logs**: jejak setiap fetch/request (internal & external) tercatat.
- Payload mentah: lihat `payloads/README.md`. Cheat-sheet audit: `docs/ssrf-cheatsheet.md`.

## ⚠️ Warning
- Lab ini HANYA untuk belajar. Jangan di-expose ke internet/LAN.
- Jangan pernah balas menjalankan lab ini di environment produksi/Firewall-hosted.
- Semua kredensial & flag di repo ini 100% dummy.