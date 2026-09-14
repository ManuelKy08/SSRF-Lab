# SSRF — cheat-sheet audit (fokus "vektor tersembunyi")

## Input yang paling sering absen dari validasi SSRF
- Image proxy / thumbnail / resize
- Link "unfurl"/preview (WhatsApp/Slack-style)
- Avatar / profile photo "from URL"
- PDF / HTML report generator internal
- Webhook / callback / notification URL
- Import URL (CSV, RSS, feed, git clone URL, npm/yarn registry mirror)
- `?ref=`, `?next=`, `?image=`, `&callbackUrl=`
- XXE (file:///… dan http://…), SVG→HTML, spreadsheet formula import

## Filter yang gampang dicegat
| Filter | Bypass |
|---|---|
| String "127.0.0.1"/"localhost" diblok | IP decimal/hex (`0x7f000001`), IPv6 `[::1]`, `127.0.0.1.nip.io`, redirect hop |
| Hanya banding .netloc | `http://user@127.0.0.1` / `127.0.0.1:80@evil.com` |
| Block loopback only | `10.0.0.1`, `172.16.x`, `192.168.x`, metadata cloud (`169.254.169.254`), gateway `192.168.1.1` |
| DNS allowlist | DNS yang resolve balik ke internal, DNS rebinding (TTL rendah) |
| No port | port 80 → bypass via `http://127.0.0.1:22` (masuk SSH banner), redis, memcached |

## Mitigasi yang bener
1. Allowlist protocol `http`/`https` (hapus `file`, `gopher`, `dict`).
2. **Resolve** hostname → pastikan IP **di luar** loopback/private/LAN/metadata (re-check saat koneksi, bukan cuma string).
3. Jangan ikuti redirect (atau re-validasi di tiap hop).
4. Timeout + max bytes/response.
5. Gunakan DNS internal sendiri (SSRF-detect / split-horizon).
6. Log & rate-limit endpoint fetch.

## Referensi
- OWASP SSRF; PortSwigger "Blind SSRF with Out-of-band detection"
- Bug bounty: "SSRF on image feature", "Webhook param yields internal metadata"