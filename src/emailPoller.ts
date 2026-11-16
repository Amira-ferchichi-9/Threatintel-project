import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { DashboardPanel } from './dashboard';
import { runScript } from './pythonRunner';

interface PollState {
    historyId: string;
    lastCheck: string;
}

export class EmailPoller implements vscode.Disposable {
    private timer: NodeJS.Timeout | undefined;
    private busy  = false;
    private alive = false;

    constructor(
        private readonly ctx: vscode.ExtensionContext,
        private readonly intervalMs = 60_000,
    ) {}

    start(): void {
        if (this.alive) { return; }
        this.alive = true;
        this.tick();                                          // immediate first check
        this.timer = setInterval(() => this.tick(), this.intervalMs);
        DashboardPanel.currentPanel?.setLiveStatus(true);
    }

    stop(): void {
        this.alive = false;
        if (this.timer) { clearInterval(this.timer); this.timer = undefined; }
        DashboardPanel.currentPanel?.setLiveStatus(false);
    }

    dispose(): void { this.stop(); }

    // ── Core polling loop ────────────────────────────────────────────────────

    private async tick(): Promise<void> {
        if (this.busy || !this.alive) { return; }
        this.busy = true;
        try {
            const state = this.loadState();
            const args  = state.historyId ? ['--history-id', state.historyId] : [];
            const res   = await runScript('poll_gmail.py', args, undefined, this.ctx.extensionPath);

            if (!res.success) { return; }

            const data = res.data as any;

            // Persist updated historyId
            if (data.historyId) {
                this.saveState({ historyId: data.historyId, lastCheck: new Date().toISOString() });
            }

            // Notify dashboard the poller is alive
            DashboardPanel.currentPanel?.setLiveStatus(true, new Date().toLocaleTimeString());

            const newMessages: Array<{ id: string; folder: string } | string> = data.newMessages ?? [];
            for (const entry of newMessages) {
                const msgId  = typeof entry === 'string' ? entry : entry.id;
                const folder = typeof entry === 'string' ? 'INBOX' : (entry.folder ?? 'INBOX');
                await this.analyzeOne(msgId, folder);
            }
        } finally {
            this.busy = false;
        }
    }

    // ── Analyse a single new email ───────────────────────────────────────────

    private async analyzeOne(msgId: string, folder: string = 'INBOX'): Promise<void> {
        const res = await runScript(
            'analyze_by_id.py', ['--msg-id', msgId, '--folder', folder], undefined, this.ctx.extensionPath,
        );
        if (!res.success) { return; }

        const email = res.data as any;
        if (email.error) { return; }

        // Push to open dashboard
        DashboardPanel.currentPanel?.pushNewEmail(email);

        // VS Code notification for threats
        if (email.verdict === 'DANGER' || email.verdict === 'SUSPICIOUS') {
            const icon  = email.verdict === 'DANGER' ? '🚨' : '⚠️';
            const label = `${icon} ${email.verdict}: ${(email.subject ?? '').slice(0, 50)}`;
            const msg   = `${label}  —  from ${(email.from ?? '').slice(0, 40)}`;

            const choice = await vscode.window.showWarningMessage(msg, 'Open Dashboard');
            if (choice === 'Open Dashboard') {
                DashboardPanel.createOrShow(this.ctx);
            }
        }
    }

    // ── State persistence ────────────────────────────────────────────────────

    private statePath(): string {
        return path.join(this.ctx.extensionPath, 'poll_state.json');
    }

    private loadState(): PollState {
        try {
            return JSON.parse(fs.readFileSync(this.statePath(), 'utf-8')) as PollState;
        } catch {
            return { historyId: '', lastCheck: '' };
        }
    }

    private saveState(s: PollState): void {
        fs.writeFileSync(this.statePath(), JSON.stringify(s, null, 2), 'utf-8');
    }
}
