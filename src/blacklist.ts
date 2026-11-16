import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export interface BlacklistEntry {
    id: string;
    value: string;
    category: 'domain' | 'ip' | 'email';
    reason: string;
    addedAt: string;
}

interface BlacklistFile {
    entries: BlacklistEntry[];
    updatedAt: string;
}

function filePath(): string {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
    return path.join(root, 'blacklist.json');
}

export function readBlacklist(): BlacklistFile {
    try {
        const raw = fs.readFileSync(filePath(), 'utf-8');
        return JSON.parse(raw) as BlacklistFile;
    } catch {
        return { entries: [], updatedAt: new Date().toISOString() };
    }
}

function write(bl: BlacklistFile): void {
    bl.updatedAt = new Date().toISOString();
    fs.writeFileSync(filePath(), JSON.stringify(bl, null, 2), 'utf-8');
}

export function addEntry(
    value: string,
    category: 'domain' | 'ip' | 'email',
    reason: string
): BlacklistEntry {
    const bl = readBlacklist();
    const entry: BlacklistEntry = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
        value: value.trim().toLowerCase(),
        category,
        reason: reason.trim() || '—',
        addedAt: new Date().toISOString(),
    };
    bl.entries.unshift(entry);
    write(bl);
    return entry;
}

export function removeEntry(id: string): boolean {
    const bl = readBlacklist();
    const before = bl.entries.length;
    bl.entries = bl.entries.filter((e) => e.id !== id);
    if (bl.entries.length !== before) {
        write(bl);
        return true;
    }
    return false;
}
