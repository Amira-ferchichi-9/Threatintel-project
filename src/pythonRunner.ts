import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export interface RunResult {
    success: boolean;
    data?: any;
    error?: string;
}

function resolveRoot(rootOverride?: string): string {
    return rootOverride
        ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
        ?? process.cwd();
}

function resolvePython(root: string): string {
    // Prefer the project venv so all dependencies (cosmos, google-auth, etc.) are available
    const venvPy = process.platform === 'win32'
        ? path.join(root, 'venv', 'Scripts', 'python.exe')
        : path.join(root, 'venv', 'bin', 'python');
    if (fs.existsSync(venvPy)) { return venvPy; }
    return process.platform === 'win32' ? 'python' : 'python3';
}

export function runScript(
    scriptName: string,
    args: string[] = [],
    stdin?: string,
    rootOverride?: string
): Promise<RunResult> {
    return new Promise((resolve) => {
        const root       = resolveRoot(rootOverride);
        const python     = resolvePython(root);
        const scriptPath = path.join(root, 'scripts', scriptName);

        const child = cp.spawn(python, ['-X', 'utf8', scriptPath, ...args], {
            cwd: root,
            env: {
                ...process.env,
                PYTHONPATH:        root,
                PYTHONIOENCODING:  'utf-8',
                PYTHONUTF8:        '1',
            },
        });

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
        child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

        if (stdin !== undefined) {
            child.stdin.write(stdin, 'utf8');
            child.stdin.end();
        }

        child.on('close', (code) => {
            if (code !== 0) {
                resolve({ success: false, error: stderr.trim() || `Exit code ${code}` });
                return;
            }
            const raw = stdout.trim();
            if (!raw) {
                resolve({ success: false, error: stderr.trim() || 'Empty output from script' });
                return;
            }
            try {
                const data = JSON.parse(raw);
                if (data && typeof data.error === 'string') {
                    resolve({ success: false, error: data.error, data });
                } else {
                    resolve({ success: true, data });
                }
            } catch {
                resolve({ success: false, error: `Non-JSON output: ${raw.slice(0, 300)}` });
            }
        });

        child.on('error', (err) => resolve({ success: false, error: err.message }));
    });
}
