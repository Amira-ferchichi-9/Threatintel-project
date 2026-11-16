// types.ts — ThreatIntel TypeScript interfaces

export interface AgentScores {
    auth: number;
    url: number;
    nlp: number;
    sandbox: number;
}

/** Single verdict record as returned by /verdicts/latest or /analyze */
export interface VerdictItem {
    /** UUID from /analyze endpoint */
    email_id?: string;
    /** Cosmos DB document id field */
    id?: string;
    timestamp: string;
    subject: string;
    sender: string;
    verdict: string;
    action?: string;
    /** Score from /analyze response */
    score?: number;
    /** Score field name used by Cosmos DB get_recent_analyses() */
    final?: number;
    hard_rule?: string | null;
    report_url?: string;
    agents?: AgentScores;
}

export interface VerdictLatestResponse {
    verdicts: VerdictItem[];
    count: number;
}

export interface AnalyzeRequest {
    subject: string;
    sender: string;
    body: string;
    source_folder?: string;
    has_attachment?: boolean;
    /** Logic App callback URL for webhook notification */
    callback_url?: string;
    message_id?: string;
}

export interface AnalyzeResponse {
    email_id: string;
    timestamp: string;
    subject: string;
    sender: string;
    verdict: string;
    action: string;
    score: number;
    hard_rule?: string | null;
    report_url: string;
    agents: AgentScores;
}

export interface CacheStats {
    available: boolean;
    hits?: number;
    misses?: number;
    keys?: { email: number; url: number; nlp: number; auth: number };
    total_keys?: number;
    error?: string;
}

export interface HealthResponse {
    status: string;
    version: string;
}
