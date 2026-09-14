import os
import sqlite3
import time
from contextlib import contextmanager

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, 'database', 'lab.db')

FLAG = 'SSRF-LAB{Flag_SSRF_Menusuk_Internal_Service_3321}'


@contextmanager
def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY,
          vulnerable INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          source TEXT,
          msg TEXT
        );
        CREATE TABLE IF NOT EXISTS webhook_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          url TEXT,
          status INTEGER,
          body TEXT
        );
        ''')


def seed():
    init_db()
    with conn() as c:
        if os.environ.get('LAB_RESET') == '1':
            c.execute('DELETE FROM settings')
        for k in ('s1', 's2', 's3', 's4'):
            c.execute('INSERT OR REPLACE INTO settings(key,vulnerable) VALUES(?,1)', (k,))


def setting(key):
    with conn() as c:
        row = c.execute('SELECT vulnerable FROM settings WHERE key=?', (key,)).fetchone()
        return row['vulnerable'] == 1 if row else True


def set_setting(key, vuln):
    with conn() as c:
        cur = c.execute('UPDATE settings SET vulnerable=? WHERE key=?', (1 if vuln else 0, key))
        if cur.rowcount == 0:
            c.execute('INSERT OR REPLACE INTO settings(key,vulnerable) VALUES(?,?)', (key, 1 if vuln else 0))


def all_settings():
    with conn() as c:
        rows = c.execute('SELECT key, vulnerable FROM settings').fetchall()
        return {r['key']: bool(r['vulnerable']) for r in rows}


def log(source, msg):
    with conn() as c:
        c.execute('INSERT INTO logs(ts,source,msg) VALUES(?,?,?)',
                  (time.strftime('%Y-%m-%d %H:%M:%S'), source, msg))


def last_logs(n=80):
    with conn() as c:
        rows = c.execute('SELECT ts,source,msg FROM logs ORDER BY id DESC LIMIT ?', (n,)).fetchall()
        return [{'ts': r['ts'], 'source': r['source'], 'msg': r['msg']} for r in rows]


def save_webhook(url, status, body):
    with conn() as c:
        c.execute('INSERT INTO webhook_log(ts,url,status,body) VALUES(?,?,?,?)',
                  (time.strftime('%Y-%m-%d %H:%M:%S'), url, status, (body or '')[:500]))


def last_webhook():
    with conn() as c:
        r = c.execute('SELECT * FROM webhook_log ORDER BY id DESC LIMIT 1').fetchone()
        return dict(r) if r else None