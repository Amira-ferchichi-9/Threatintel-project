import * as http from 'http';
import * as vscode from 'vscode';
import type { VerdictItem } from './types';

const POLL_MS    = 5_000;
const MAX_STORED = 10;
const API_HOST   = 'localhost';
const API_PORT   = 8000;

export class VerdictPanel implements vscode.Disposable {
    static currentPanel: VerdictPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private _timer: NodeJS.Timeout | undefined;

    static createOrShow(ctx: vscode.ExtensionContext): void {
        if (VerdictPanel.currentPanel) {
            VerdictPanel.currentPanel._panel.reveal(vscode.ViewColumn.Two);
            return;
        }
        const panel = vscode.window.createWebviewPanel(
            'threatintelVerdicts',
            'ThreatIntel — Verdicts',
            vscode.ViewColumn.Two,
            { enableScripts: true, retainContextWhenHidden: true },
        );
        VerdictPanel.currentPanel = new VerdictPanel(panel, ctx);
    }

    private constructor(
        panel: vscode.WebviewPanel,
        private readonly _ctx: vscode.ExtensionContext,
    ) {
        this._panel = panel;
        panel.onDidDispose(() => this.dispose());
        panel.webview.html = this._html();
        this._pushStored();
        this._startPolling();
    }

    private _startPolling(): void {
        this._poll();
        this._timer = setInterval(() => this._poll(), POLL_MS);
    }

    private _poll(): void {
        _fetchVerdicts(MAX_STORED)
            .then(fresh => {
                const stored: VerdictItem[] = this._ctx.globalState.get('threatintel.verdicts', []);
                const merged = _merge(stored, fresh, MAX_STORED);
                this._ctx.globalState.update('threatintel.verdicts', merged);
                this._panel.webview.postMessage({ type: 'update', verdicts: merged });
            })
            .catch(() => { /* server offline — keep last known */ });
    }

    private _pushStored(): void {
        const stored: VerdictItem[] = this._ctx.globalState.get('threatintel.verdicts', []);
        if (stored.length > 0) {
            this._panel.webview.postMessage({ type: 'update', verdicts: stored });
        }
    }

    dispose(): void {
        if (this._timer) { clearInterval(this._timer); }
        VerdictPanel.currentPanel = undefined;
        this._panel.dispose();
    }

    private _html(): string {
        return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatIntel Verdicts</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0A0F1E;color:#e2e8f0;padding:16px;font-size:13px}
h3{color:#8B5CF6;margin-bottom:12px;font-size:15px;display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.card{border:1px solid #1e293b;border-radius:8px;padding:12px;margin-bottom:8px;background:#0F1629}
.subject{font-weight:bold;font-size:13px;margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meta{color:#94a3b8;font-size:11px;margin-bottom:6px}
.verdict-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px}
.badge{padding:2px 8px;border-radius:4px;font-weight:bold;font-size:11px}
.danger {background:#7f1d1d;color:#fca5a5}
.suspect{background:#78350f;color:#fcd34d}
.safe   {background:#14532d;color:#86efac}
.unknown{background:#1e293b;color:#94a3b8}
.rule{color:#f59e0b;font-size:10px}
.score-bar{height:4px;border-radius:2px;background:#1e293b;overflow:hidden;margin-bottom:4px}
.score-fill{height:100%;border-radius:2px;transition:width .4s}
.agents{display:grid;grid-template-columns:repeat(4,1fr);gap:4px;margin-top:4px}
.ab{background:#1e293b;border-radius:4px;padding:4px;text-align:center}
.al{color:#64748b;font-size:9px;text-transform:uppercase}
.av{color:#e2e8f0;font-weight:bold;font-size:12px}
.ts{color:#475569;font-size:10px;margin-top:4px}
.rlink{color:#8B5CF6;font-size:10px;text-decoration:none;margin-top:2px;display:inline-block}
.empty{color:#475569;text-align:center;margin-top:40px;font-size:13px}
</style>
</head>
<body>
<h3><span class="dot"></span>ThreatIntel &mdash; Latest Verdicts</h3>
<div id="root"><p class="empty">Polling every 5s&hellip; run an analysis first.</p></div>
<script>
const vscode = acquireVsCodeApi();
window.addEventListener('message', e => {
  if (e.data.type === 'update') { render(e.data.verdicts); }
  if (e.data.type === 'openReport') { vscode.postMessage(e.data); }
});
function esc(s) { return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function cls(v) {
  if (!v) { return 'unknown'; }
  const u = v.toUpperCase();
  if (u.includes('DANGER'))  { return 'danger';  }
  if (u.includes('SUSPECT') || u.includes('WARN') || u.includes('QUARANT')) { return 'suspect'; }
  if (u.includes('SAIN') || u.includes('SAFE') || u.includes('CLEAN')) { return 'safe'; }
  return 'unknown';
}
function col(n) { return n >= 75 ? '#ef4444' : n >= 40 ? '#f59e0b' : '#22c55e'; }
function render(list) {
  const root = document.getElementById('root');
  if (!list || !list.length) { root.innerHTML = '<p class="empty">No verdicts yet.</p>'; return; }
  root.innerHTML = list.map(v => {
    const score   = v.score ?? v.final ?? 0;
    const agents  = v.agents || {};
    const hasAg   = agents.auth != null || agents.url != null;
    const verdCls = cls(v.verdict);
    return '<div class="card">'
      + '<div class="subject">' + esc(v.subject || '(no subject)') + '</div>'
      + '<div class="meta">From: ' + esc(v.sender || '') + ' &nbsp;|&nbsp; Score: ' + score + '/100</div>'
      + '<div class="verdict-row">'
      + '<span class="badge ' + verdCls + '">' + esc(v.verdict || '—') + '</span>'
      + (v.action  ? '<span style="color:#64748b;font-size:11px">→ ' + esc(v.action) + '</span>' : '')
      + (v.hard_rule ? '<span class="rule">⚠ ' + esc(v.hard_rule) + '</span>' : '')
      + '</div>'
      + '<div class="score-bar"><div class="score-fill" style="width:' + score + '%;background:' + col(score) + '"></div></div>'
      + (hasAg
        ? '<div class="agents">'
          + '<div class="ab"><div class="al">AUTH</div><div class="av">' + (agents.auth  ?? '—') + '</div></div>'
          + '<div class="ab"><div class="al">URL</div><div class="av">'  + (agents.url   ?? '—') + '</div></div>'
          + '<div class="ab"><div class="al">NLP</div><div class="av">'  + (agents.nlp   ?? '—') + '</div></div>'
          + '<div class="ab"><div class="al">SBX</div><div class="av">'  + (agents.sandbox ?? '—') + '</div></div>'
          + '</div>'
        : '')
      + (v.report_url ? '<a class="rlink" href="#" onclick="vscode.postMessage({type:\'openReport\',url:\'' + esc(v.report_url) + '\'});return false;">📄 View Report</a>' : '')
      + '<div class="ts">' + esc(v.timestamp || '') + '</div>'
      + '</div>';
  }).join('');
}
</script>
</body>
</html>`;
    }
}

function _fetchVerdicts(limit: number): Promise<VerdictItem[]> {
    return new Promise((resolve, reject) => {
        const req = http.get(
            {
                host: API_HOST,
                port: API_PORT,
                path: `/verdicts/latest?limit=${limit}`,
                timeout: 3000,
            },
            res => {
                let body = '';
                res.on('data', chunk => { body += chunk; });
                res.on('end', () => {
                    try {
                        const data = JSON.parse(body) as { verdicts: VerdictItem[] };
                        resolve(data.verdicts ?? []);
                    } catch (e) {
                        reject(e);
                    }
                });
            },
        );
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });
}

function _merge(stored: VerdictItem[], fresh: VerdictItem[], max: number): VerdictItem[] {
    const seen   = new Set<string>();
    const result: VerdictItem[] = [];
    for (const item of [...fresh, ...stored]) {
        const key = item.email_id ?? item.id ?? item.timestamp ?? JSON.stringify(item).slice(0, 40);
        if (!seen.has(key)) {
            seen.add(key);
            result.push(item);
        }
        if (result.length >= max) { break; }
    }
    return result;
}
