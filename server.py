#!/usr/bin/env python3
"""Local dev server for the ThreatIntel dashboard preview.
   Run: python server.py
   Open: http://localhost:8765
"""
import json
import mimetypes
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8765
ROOT = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.join(ROOT, 'media')


def venv_python():
    p = os.path.join(ROOT, 'venv', 'Scripts', 'python.exe') if sys.platform == 'win32' \
        else os.path.join(ROOT, 'venv', 'bin', 'python')
    return p if os.path.exists(p) else sys.executable


def run_script(name):
    try:
        r = subprocess.run(
            [venv_python(), '-X', 'utf8', os.path.join(ROOT, 'scripts', name)],
            cwd=ROOT, capture_output=True, timeout=180,
            env={**os.environ, 'PYTHONPATH': ROOT,
                 'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'},
        )
        stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
        stderr = r.stderr.decode('utf-8', errors='replace').strip() if r.stderr else ''
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith('{') or line.startswith('['):
                return json.loads(line)
        return {'error': stderr or 'empty output'}
    except subprocess.TimeoutExpired:
        return {'error': 'Script timed out (>180s)'}
    except Exception as e:
        return {'error': str(e)}


class Handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors(); self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            return self._json({'status': 'ok'})
        if self.path == '/api/dashboard':
            return self._json(run_script('dashboard_data.py'))
        # Serve static files from media/
        fname = 'preview.html' if self.path in ('/', '/preview.html') else self.path.lstrip('/')
        fpath = os.path.join(MEDIA, fname)
        if os.path.isfile(fpath):
            ct, _ = mimetypes.guess_type(fpath)
            with open(fpath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ct or 'text/plain')
            self.send_header('Content-Length', len(data))
            self._cors(); self.end_headers()
            self.wfile.write(data)
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        if self.path == '/api/launch':
            return self._json(run_script('launch_analysis.py'))
        self._json({'error': 'not found'}, 404)

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self._cors(); self.end_headers()
        self.wfile.write(body)

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def log_message(self, fmt, *args):
        print(f'  {args[0]}  {args[1]}')


if __name__ == '__main__':
    os.chdir(ROOT)
    srv = HTTPServer(('localhost', PORT), Handler)
    print(f'\nThreatIntel server -> http://localhost:{PORT}')
    print('Press Ctrl+C to stop.\n')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
