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