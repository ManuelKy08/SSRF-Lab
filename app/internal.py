from flask import Blueprint, jsonify, request
from .models import FLAG, log

bp = Blueprint('internal', __name__)


@bp.route('/')
def home():
    return jsonify({'service': 'internal-corp', 'note': 'hanya bisa diakses dari dalam jaringan (internal).'})


@bp.route('/internal/flag')
def flag():
    log('internal', f'[internal/flag] diakses dari {request.remote_addr}')
    return jsonify({'ok': True, 'service': 'internal-corp', 'flag': FLAG})


@bp.route('/internal/meta')
def meta():
    log('internal', f'[internal/meta] diakses dari {request.remote_addr}')
    return jsonify({
        'ok': True,
        'internal_host': request.host,
        'scheme': request.scheme,
        'path': request.path,
        'query': request.query_string.decode('utf-8', 'replace'),
        'internal_secret': FLAG,
    })


@bp.route('/internal/probe')
def probe():
    q = request.args.get('q', '')
    log('internal', f'[internal/probe] q={q}')
    return jsonify({'pong': q, 'from_internal': True})


# ---- cloud metadata (simulasi 169.254.169.254, hanya di-loopback internal) ----

@bp.route('/latest/meta-data/')
def meta_md():
    log('internal', '[meta] /latest/meta-data/ diakses')
    return jsonify({'instance-id': 'i-0l4b-victim', 'ami-id': 'ami-0abc',
                    'hostname': 'ip-10-0-1-42.ec2.internal',
                    'available': ['iam/security-credentials/']})


@bp.route('/latest/meta-data/iam/security-credentials/')
def meta_creds():
    log('internal', '[meta] IAM security-credentials DIAMBIL dari cloud metadata')
    return jsonify({
        'Code': 'Success',
        'AccessKeyId': 'AKIA-SSRF-LAB-FAKE',
        'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'Token': 'dummy-session-token',
        'Expiration': '2026-12-31T23:59:59Z',
        'RoleArn': 'arn:aws:iam::123456789012:role/lab-ssrf-role',
        'flag': FLAG,
    })