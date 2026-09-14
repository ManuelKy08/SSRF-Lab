# SSRF Lab — vektor kerentanan yang jarang diangkat, dikaitkan ke Bug Bounty

Lab Flask lokal yang mendemonstrasikan **Server-Side Request Forgery** lewat 4 input/vendor berbeda yang tidak umum (bukan sekadar `?url=`).

- External (target): `http://127.0.0.1:5092`
- Internal service (korban, hanya 127.0.0.1): `http://127.0.0.1:5091`

## Skenario
1. **Image proxy / bandwidth-saver (s1)** — server diandalkan mem-fetch URL user (resize/screenshot). Tanpa validasi host → `http://127.0.0.1:5091/internal/flag`.
2. **Avatar/upload via file:// (s2)** — register avatar diimplementasi sebagai fetch-from-URL. Scheme tidak difilter → baca file lokal (`secret.txt`): credential server & flag. Kelas bug: SSRF → arbitrary file read.
3. **Redirect-bypass denylist IP (s3)** — filter literal ("127.0.0.1","localhost") tampak aman, tetapi fetcher **mengikuti redirect**. Host publik attacker (di sini `/evil/redirect`) me-302 ke internal → loopback tercapai. Kelas bug: bypass filter IP via redirect (real: CVE SSRF klasik, DNS rebinding dll).
4. **Webhook callback SSRF (s4)** — input "URL callback/webhook" yang dipanggil **oleh server saat trigger**; tidak ada validasi host → server men-DO-RING internal metadata, responnya bocor ke panel admin.

## Yang dipelajari
- Semua "fetch yang dibangun ke fitur" adalah SSRF avenue: image proxy, preview/link unfurl, PDF/thumbnail generator, webhook, avatar-from-URL.
- **Harus**: allowlist protocol (http/https) dan host; resolve IP (bukan banding string) + blokir loopback/private/LAN; non-follow redirect (atau re-validate tiap hop); timeout & limit byte.
- **Denylist IP via string ≠ secure** — trik: IP decimal/hex, IPv6, redirect, DNS rebinding.
- `file://` / `gopher://` membutuhkan allowlist scheme.
- Webhook input sama berbahayanya dengan parameter URL pada proxy.

## Penjelasan
Provider internal (5091) memegang flag `SSRF-LAB{Flag_SSRF_Menusuk_Internal_Service_3321}`. Semua exploit bisa langsung dicoba dari dashboard (tombol "Jalankan Exploit") maupun manual via halaman fitur / `payloads/README.md`.

## Cara jalankan
```
python -m app.main      # dari folder lab — start internal 5091 + lab 5092
```