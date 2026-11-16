import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { addEntry, removeEntry, readBlacklist } from './blacklist';
import { runScript } from './pythonRunner';

// ── Helpers ────────────────────────────────────────────────────────────────

function nonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

// ── Panel ──────────────────────────────────────────────────────────────────

export class DashboardPanel {
    public static currentPanel: DashboardPanel | undefined;
    static readonly viewType = 'threatintelDashboard';

    private readonly panel: vscode.WebviewPanel;
    private readonly ctx: vscode.ExtensionContext;
    private subs: vscode.Disposable[] = [];

    // ── Factory ──────────────────────────────────────────────────────────

    public static createOrShow(ctx: vscode.ExtensionContext): void {
        const col = vscode.window.activeTextEditor?.viewColumn;

        if (DashboardPanel.currentPanel) {
            DashboardPanel.currentPanel.panel.reveal(col);
            DashboardPanel.currentPanel.loadData();
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            DashboardPanel.viewType,
            'ThreatIntel',
            col ?? vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(ctx.extensionUri, 'media')],
            }
        );

        DashboardPanel.currentPanel = new DashboardPanel(panel, ctx);
    }

    // ── Constructor ──────────────────────────────────────────────────────

    private constructor(panel: vscode.WebviewPanel, ctx: vscode.ExtensionContext) {
        this.panel = panel;
        this.ctx   = ctx;

        this.panel.webview.html = this.buildHtml();
        this.panel.onDidDispose(() => this.dispose(), null, this.subs);
        this.panel.onDidChangeViewState(
            () => { if (this.panel.visible) this.loadData(); },
            null, this.subs
        );
        this.panel.webview.onDidReceiveMessage(
            (msg) => this.handleMessage(msg),
            undefined, this.subs
        );
    }

    // ── Public ──────────────────────────────────────────────────────────

    public refresh(): void { this.loadData(); }

    public setLiveStatus(active: boolean, lastCheck?: string): void {
        this.post('liveStatus', { active, lastCheck: lastCheck ?? '' });
    }

    public pushNewEmail(email: any): void {
        this.post('newEmail', { email });
    }

    public dispose(): void {
        DashboardPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.subs.length) { this.subs.pop()?.dispose(); }
    }

    // ── Message handler ─────────────────────────────────────────────────

    private handleMessage(msg: any): void {
        switch (msg.type) {
            case 'ready':
            case 'refresh':
                this.loadData();
                break;
            case 'getBlacklist':
                this.sendBlacklist();
                break;
            case 'analyze':
                this.runAnalysis(msg.payload);
                break;
            case 'addBlacklist':
                this.addToBlacklist(msg.payload);
                break;
            case 'removeBlacklist':
                this.removeFromBlacklist(msg.payload.id);
                break;
            case 'launchAnalysis':
                this.runLaunchAnalysis();
                break;
        }
    }

    // ── Data loading ─────────────────────────────────────────────────────

    private async loadData(): Promise<void> {
        const res = await runScript('dashboard_data.py', [], undefined, this.ctx.extensionPath);
        if (res.success) {
            this.post('dashboardData', res.data);
        } else {
            this.post('dashboardData', {
                stats:  { total:0, danger:0, suspicious:0, safe:0, avg_score:0 },
                recent: [],
                error:  res.error,
            });
        }
    }

    // ── Blacklist ────────────────────────────────────────────────────────

    private sendBlacklist(): void {
        const bl = readBlacklist();
        this.post('blacklistData', { entries: bl.entries });
    }

    private addToBlacklist(p: { value: string; category: 'domain'|'ip'|'email'; reason: string }): void {
        try {
            addEntry(p.value, p.category, p.reason);
            this.post('blacklistUpdated', { entries: readBlacklist().entries });
        } catch (e: any) {
            this.post('error', { message: String(e.message) });
        }
    }

    private removeFromBlacklist(id: string): void {
        removeEntry(id);
        this.post('blacklistUpdated', { entries: readBlacklist().entries });
    }

    // ── Launch analysis (last 5 Gmail inbox emails) ──────────────────────────

    private async runLaunchAnalysis(): Promise<void> {
        this.post('launchProgress', { message: 'Fetching last 5 emails from Gmail inbox...' });
        const res = await runScript('launch_analysis.py', [], undefined, this.ctx.extensionPath);
        if (res.success && (res.data as any)?.results) {
            this.post('launchResult', { results: (res.data as any).results });
            setTimeout(() => this.loadData(), 1000);
        } else {
            this.post('launchResult', { error: (res.data as any)?.error ?? res.error ?? 'Analysis failed' });
        }
    }

    // ── Email analysis ───────────────────────────────────────────────────

    private async runAnalysis(p: { content: string; isPath: boolean }): Promise<void> {
        this.post('analysisStart', {});

        const res = p.isPath
            ? await runScript('analyze_email.py', ['--file', p.content], undefined, this.ctx.extensionPath)
            : await runScript('analyze_email.py', [], p.content, this.ctx.extensionPath);

        if (res.success) {
            this.post('analysisResult', this.normalizeResult(res.data));
        } else {
            this.post('analysisResult', { error: res.error || 'Analysis failed' });
        }
    }

    // ── Utilities ────────────────────────────────────────────────────────

    private normalizeResult(raw: any): any {
        const verdictMap: Record<string, string> = {
            QUARANTINE:'SUSPICIOUS', QUARANTAINE:'SUSPICIOUS',
            DELIVER:'SAFE', ALLOW:'SAFE', SAIN:'SAFE',
            DANGER:'DANGER', SUSPECT:'SUSPICIOUS', SUSPICIOUS:'SUSPICIOUS', SAFE:'SAFE',
        };
        const v = String(raw.verdict ?? '').toUpperCase();
        let verdict = 'SAFE';
        for (const [k, val] of Object.entries(verdictMap)) {
            if (v.includes(k)) { verdict = val; break; }
        }
        if (v.includes('DANGER')) verdict = 'DANGER';
        return {
            verdict,
            score:      raw.score ?? 0,
            confidence: raw.confidence ?? 0,
            action:     raw.action ?? '',
            hard_rule:  raw.hard_rule ?? '',
            agents:     raw.agents ?? [],
        };
    }

    private post(type: string, payload: any): void {
        this.panel.webview.postMessage({ type, payload });
    }

    // ── HTML builder ─────────────────────────────────────────────────────

    private buildHtml(): string {
        const wv        = this.panel.webview;
        const n         = nonce();
        const styleUri  = wv.asWebviewUri(vscode.Uri.joinPath(this.ctx.extensionUri, 'media', 'style.css'));
        const tmplPath  = path.join(this.ctx.extensionPath, 'media', 'dashboard.html');
        return fs.readFileSync(tmplPath, 'utf-8')
            .replace(/\{\{nonce\}\}/g,     n)
            .replace(/\{\{styleUri\}\}/g,  styleUri.toString())
            .replace(/\{\{cspSource\}\}/g, wv.cspSource);
    }
}
