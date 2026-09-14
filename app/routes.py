import ipaddress
import re
import urllib.parse
import urllib.request
from flask import Blueprint, jsonify, render_template, request

from .models import (all_settings, log, last_logs, last_webhook, save_webhook,
                     set_setting, setting)

bp = Blueprint('lab', __name__)

PRIVATE_NETS = ['127.0.0.1', '127.0.0.0/8', '0.0.0.0', '::1', '10.0.0.0/8',
                '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']

LAB_DNS = {'r.evil': '127.0.0.1'}


def resolve_host(host):
    try:
        import socket
        return socket.gethostbyname(host)
    except Exception:
        return LAB_DNS.get(host, host if host in LAB_DNS else None)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _resolve(netloc):
    host = netloc.rsplit(':', 1)[0] if ':' in netloc else netloc
    host = host if host else netloc
    return host


def _is_private(host_ip):
    try:
        ip = ipaddress.ip_address(host_ip.strip('[]'))
        return any(ip in ipaddress.ip_network(n) for n in PRIVATE_NETS if '/' in n) \
            or host_ip in ('127.0.0.1', '::1', '0.0.0.0')
    except Exception as e:
        return False


def _host_name(url):
    return urllib.parse.urlparse(url).netloc.split(':')[0].split('@')[-1].strip('[]')


def _resolve_ip(hostname, fixed=False):
    return resolve_host(hostname)


def fetch_raw(url, timeout=3, follow_redirect=True, max_bytes=700):
    req = urllib.request.Request(url, headers={'User-Agent': 'ssrf-lab/1.0'})
    opener = urllib.request.build_opener()
    if not follow_redirect:
        opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(max_bytes)
            return {'status': r.status, 'final_url': r.geturl(),
                    'body': raw.decode('utf-8', 'replace')}
    except urllib.error.HTTPError as e:
        return {'status': e.code, 'final_url': url, 'body': ''}
    except Exception as e:
        return {'error': str(e)}


# ---------- page helpers ----------

def _fetch_outcome(url, verdict, raw, desc):
    ok = False
    if raw.get('error'):
        body = 'ERR: ' + raw['error']
    else:
        body = raw.get('body', '') or ''
    if 'SSRF-LAB{' in body:
        ok = True
        body = body.strip()
    return {'url': url, 'verdict': verdict, 'ok': ok, 'body': body,
            'status': raw.get('status', '-'), 'final_url': raw.get('final_url', url), 'desc': desc}


def _check_s1(url):
    host = _host_name(url)
    if setting('s1'):
        verd = 'TIDAK ADA validasi host → SSRF TANPA hambatan'
        raw = fetch_raw(url)
        return _fetch_outcome(url, verd, raw, 'fetch langsung tanpa filter')
    verd = f'filter: hanya izinkan host cdn.corp-test.local (diterima: {host})'
    if host != 'cdn.corp-test.local':
        return {'url': url, 'verdict': verd, 'ok': False, 'body': 'BLOCKED: host bukan allowlist.',
                'status': '-', 'final_url': url, 'desc': 'filter allowlist hostname'}
    raw = fetch_raw(url)
    return _fetch_outcome(url, verd, raw, 'host dalam allowlist')


def _check_s2(url):
    scheme = urllib.parse.urlparse(url).scheme
    if setting('s2'):
        verd = f'scheme "{scheme}" TIDAK diperiksa → file:// / gopher:// dll bisa dibaca server'
        raw = fetch_raw(url, max_bytes=1200)
        return _fetch_outcome(url, verd, raw, 'provider fetch mengikuti scheme apa pun')
    verd = 'filter: hanya http/https yang diturunkan (mencegah file:// dll)'
    if scheme not in ('http', 'https'):
        return {'url': url, 'verdict': verd, 'ok': False,
                'body': f'BLOCKED: scheme "{scheme}" tidak diizinkan (file:// internasional diblokir).',
                'status': '-', 'final_url': url, 'desc': 'filter scheme http(s) only'}
    raw = fetch_raw(url)
    return _fetch_outcome(url, verd, raw, 'scheme http/https')


def _check_s3(url):
    host = _host_name(url)
    block_words = ['127.0.0.1', 'localhost', '0.0.0.0', '10.', '192.168.172', '::1']
    p = urllib.parse.urlparse(url)
    if host in LAB_DNS:
        port = ':' + str(p.port) if p.port else ''
        connect_url = urllib.parse.urlunparse(p._replace(netloc=LAB_DNS[host] + port))
        dns_note = f' ({host} → {LAB_DNS[host]})'
    else:
        connect_url = url
        dns_note = ''
    if setting('s3'):
        verd = 'filter: denylist literal (hanya cek string 127.0.0.1/localhost)'
        if any(w in (host or '') for w in block_words):
            return {'url': url, 'verdict': verd, 'ok': False,
                    'body': f'BLOCKED (denylist string): {host}',
                    'status': '-', 'final_url': url, 'desc': 'kena denylist literal'}
        nom = 'server mengikuti redirect → hop internal '
        raw = fetch_raw(connect_url)
        r = _fetch_outcome(connect_url, verd, raw, nom)
        r['body'] = r['body'] + dns_note if not r.get('error') else r['body']
        return r
    verd = 'filter: resolve host → blokir IP privat/LAN + redirect TIDAK diikuti (NoRedirect)'
    ip = resolve_host(host)
    if ip and _is_private(ip):
        return {'url': url, 'verdict': verd, 'ok': False,
                'body': f'BLOCKED: {host} ({ip}{dns_note}) IP privat/loopback — koneksi batal.',
                'status': '-', 'final_url': url, 'desc': 'resolve + cek privat sebelum connect'}
    raw = fetch_raw(connect_url, follow_redirect=False)
    if 'SSRF-LAB{' in (raw.get('body') or ''):
        raw['body'] = raw['body'].strip()
        return {'url': url, 'verdict': verd, 'ok': True,
                'body': raw.get('body'), 'status': raw.get('status'),
                'final_url': raw.get('final_url'), 'desc': 'host publik aman'}
    return {'url': url, 'verdict': verd, 'ok': False,
            'body': raw.get('body') or ('redirect hop diblokir' if raw.get('status', 0) >= 300 else 'no flag'),
            'status': raw.get('status', '-'), 'final_url': raw.get('final_url', url),
            'desc': 'redirect tidak diikuti → internal tidak ter-exfiltrate'}


def _check_s4(url):
    host = _host_name(url)
    if setting('s4'):
        verd = 'URL callback tidak divalidasi → server bisa meng-call endpoint internal'
        raw = urllib.request.urlopen(urllib.request.Request(
            url, headers={'User-Agent': 'ssrf-lab/1.0'}), timeout=3)
        with raw as r:
            body = r.read(700).decode('utf-8', 'replace')
        ok = 'SSRF-LAB{' in body
        save_webhook(url, r.status if hasattr(r, 'status') else 200, body)
        return {'url': url, 'verdict': verd, 'ok': ok,
                'body': body.strip() if ok else body,
                'status': r.status if hasattr(r, 'status') else 200,
                'final_url': r.geturl(), 'desc': 'eksfiltrasi internal + tersimpan di webhook log'}
    verd = 'filter: webhook wajib https + host tidak privat/LAN'
    if urllib.parse.urlparse(url).scheme != 'https':
        return {'url': url, 'verdict': verd, 'ok': False,
                'body': 'BLOCKED: yang diizinkan hanya URL https.',
                'status': '-', 'final_url': url, 'desc': 'scheme https required'}
    ip = _resolve_ip(host)
    if ip and _is_private(ip):
        return {'url': url, 'verdict': verd, 'ok': False,
                'body': f'BLOCKED: {host} ({ip}) IP privat/LAN.',
                'status': '-', 'final_url': url, 'desc': 'resolve + blokir privat'}
    raw = fetch_raw(url)
    return _fetch_outcome(url, verd, raw, 'host publik https')


CHECKS = {'s1': _check_s1, 's2': _check_s2, 's3': _check_s3, 's4': _check_s4}


# ---------- pages ----------

@bp.route('/')
def index():
    return render_template('index.html', modes=all_settings())


@bp.route('/logs')
def logs():
    return render_template('logs.html', logs=last_logs())


@bp.route('/svc/check-img')
def page_img():
    mode = setting('s1')
    if request.args.get('url'):
        return render_template('result.html', page='check-img', label='Image proxy (bandwidth saver)',
                               mode=mode, r=_check_s1(request.args['url']))
    return render_template('form.html', page='check-img', title='Image proxy (bandwidth saver)',
                           mode=mode, action='/svc/check-img',
                           desc='Fitur server-side yang diminta "preview" dari URL gambar.')


@bp.route('/svc/avatar')
def page_avatar():
    mode = setting('s2')
    if request.args.get('url'):
        return render_template('result.html', page='avatar', label='Avatar dari URL (file://)',
                               mode=mode, r=_check_s2(request.args['url']))
    return render_template('form.html', page='avatar', title='Avatar dari URL', mode=mode,
                           action='/svc/avatar',
                           desc='"Upload avatar" yang diimplementasi sebagai fetch-from-URL oleh server.')


@bp.route('/svc/ping')
def page_ping():
    mode = setting('s3')
    if request.args.get('url'):
        return render_template('result.html', page='ping', label='Content checker (redirect bypass)',
                               mode=mode, r=_check_s3(request.args['url']))
    return render_template('form.html', page='ping', title='Content checker', mode=mode,
                           action='/svc/ping',
                           desc='Tool yang mengecek konten & mengikuti redirect dari URL yang dikirim.')


@bp.route('/svc/webhook')
def page_webhook():
    mode = setting('s4')
    if request.args.get('url'):
        return render_template('result.html', page='webhook', label='Webhook endpoint (SSRF callback)',
                               mode=mode, r=_check_s4(request.args['url']))
    return render_template('form.html', page='webhook', title='Webhook endpoint',
                           mode=mode, action='/svc/webhook',
                           desc='Daftarkan URL callback/webhook yang dipanggil server. Admin melihat responnya di panel.')


@bp.route('/api/state')
def api_state():
    return jsonify(all_settings())


@bp.route('/api/toggle/<sid>', methods=['POST'])
def api_toggle(sid):
    if sid not in ('s1', 's2', 's3', 's4'):
        return jsonify({'error': 'invalid id'}), 400
    data = request.get_json(silent=True) or {}
    if 'vulnerable' in data or 'on' in data:
        v = bool(data.get('vulnerable', data.get('on', True)))
    else:
        v = not setting(sid)
    set_setting(sid, v)
    log('setting', f'{sid} → {"RENTAN" if setting(sid) else "FIXED"}')
    return jsonify({'id': sid, 'vulnerable': setting(sid)})


@bp.route('/api/poc/<sid>', methods=['POST'])
def api_poc(sid):
    if sid not in CHECKS:
        return jsonify({'error': 'invalid id'}), 400
    return jsonify({'id': sid, **poc(sid)})


# ---------- pocs (no self-HTTP, jalankan exploit di dalam proses) ----------

def poc(sid):
    steps = []
    if sid == 's1':
        url = 'http://127.0.0.1:5091/internal/flag'
        steps = ['1. Attacker submit URL internal:', '   ' + url,
                 '2. Proxy server mem-fetch URL tsb tanpa validasi host.',
                 '3. Respon internal service (flag) ikut dikembalikan ke attacker.']
        r = _check_s1(url)
    elif sid == 's2':
        import pathlib
        url = pathlib.Path(r'D:\OPENCODE\ssrf-lab\secret.txt').as_uri()
        steps = ['1. Karena link/avatar di-fetch server tanpa cek scheme, attacker kirim:',
                 '   ' + url,
                 '2. urllib server membuka file:// → isi file lokal dibaca.',
                 '3. Isi secret (bisa credential/flag) tampil ke attacker.']
        r = _check_s2(url)
    elif sid == 's3':
        url = 'http://r.evil:5092/evil/redirect'
        steps = ['1. URL langsung ke internal (127.0.0.1) diblokir denylist literal.',
                 '2. Attacker pakai DOMAIN miliknya (r.evil) yg resolve ke loopback:',
                 '   ' + url,
                 '3. Denylist literal lolos (host "r.evil" bukan string terlarang).',
                 '4. kamu me-302 → fetcher MENGIKUTI redirect → http://127.0.0.1:5091/internal/flag',
                 '5. Flag bocor meski filter awal "lolos".']
        r = _check_s3(url)
    else:
        url = 'http://127.0.0.1:5091/internal/meta?ref=webhook'
        steps = ['1. Attacker daftarkan webhook URL → endpoint internal:',
                 '   ' + url,
                 '2. Saat trigger, server meng-call URL itu (callback SSRF).',
                 '3. Respon internal (meta + secret) tersimpan & tampil.'
                 ' Operator yakin "webhook hanya ke dunia luar" ternyata bukan.']
        r = _check_s4(url)
    out = {'steps': steps, 'r': r, 'ok': r['ok']}
    body = r.get('body') or ''
    m = re.search(r'[A-Z0-9]+-LAB\{[^}]+\}', body)
    if r['ok'] and m:
        out['flag'] = m.group(0)
    return out


# ---------- evil helper for s3 (host publik yang redirect ke internal) ----------

@bp.route('/evil/redirect')
def evil_redirect():
    return '', 302, {'Location': 'http://127.0.0.1:5091/internal/flag'}