import * as vscode from 'vscode';
import { DashboardPanel } from './dashboard';
import { EmailPoller } from './emailPoller';
import { VerdictPanel } from './verdictPanel';

export function activate(context: vscode.ExtensionContext): void {
    const poller = new EmailPoller(context, 60_000);

    context.subscriptions.push(
        vscode.commands.registerCommand('threatintel.openDashboard', () => {
            DashboardPanel.createOrShow(context);
        }),
        vscode.commands.registerCommand('threatintel.refreshDashboard', () => {
            DashboardPanel.currentPanel?.refresh();
        }),
        vscode.commands.registerCommand('threatintel.openVerdicts', () => {
            VerdictPanel.createOrShow(context);
        }),
        poller,
    );

    poller.start();
}

export function deactivate(): void {}
