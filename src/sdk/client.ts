/**
 * MCP Security Gateway — TypeScript SDK
 * Typed client so developers don't hand-write JSON-RPC calls.
 *
 * Usage:
 *   import { McpGatewayClient } from '@mcp-security/sdk';
 *   const client = new McpGatewayClient({ gatewayUrl: 'https://your-gateway', token: 'bearer-token' });
 *   const result = await client.callTool('query_database', { query: 'SELECT ...' });
 */

export interface GatewayConfig {
  gatewayUrl: string;
  token: string;
  oidcProvider?: 'google' | 'azure' | 'okta';
  tenantId?: string;
  timeoutMs?: number;
  retries?: number;
}

export interface ToolCallResult<T = unknown> {
  content: T;
  isError: boolean;
  executionTimeMs?: number;
  requestId?: string;
}

export interface GatewayError {
  code: 'AUTH_FAILED' | 'POLICY_DENIED' | 'INSPECTION_BLOCKED' | 'RATE_LIMITED' | 'REPLAY_DETECTED' | 'UPSTREAM_ERROR';
  message: string;
  reason?: string;
  retryAfter?: number;
}

export class McpGatewayError extends Error {
  code: GatewayError['code'];
  reason?: string;
  retryAfter?: number;
  httpStatus: number;

  constructor(err: GatewayError, httpStatus: number) {
    super(err.message);
    this.name = 'McpGatewayError';
    this.code = err.code;
    this.reason = err.reason;
    this.retryAfter = err.retryAfter;
    this.httpStatus = httpStatus;
  }
}

// ── Main SDK client ────────────────────────────────────────────────────

export class McpGatewayClient {
  private config: Required<GatewayConfig>;
  private requestIdCounter = 1;

  constructor(config: GatewayConfig) {
    this.config = {
      oidcProvider: undefined as any,
      tenantId: undefined as any,
      timeoutMs: 30_000,
      retries: 2,
      ...config,
    };
  }

  // ── Core tool call ───────────────────────────────────────────────────

  async callTool<T = unknown>(toolName: string, args: Record<string, unknown>): Promise<ToolCallResult<T>> {
    const body = {
      jsonrpc: '2.0',
      id: this.requestIdCounter++,
      method: 'tools/call',
      params: { name: toolName, arguments: args },
    };

    const response = await this.post('/mcp', body);
    return {
      content: response.result?.content as T,
      isError: response.result?.isError ?? false,
      executionTimeMs: response._meta?.executionTimeMs,
      requestId: response._meta?.requestId,
    };
  }

  // ── Convenience methods for common MCP tools ─────────────────────────

  async queryDatabase(query: string, database?: string) {
    return this.callTool<{ rows: unknown[]; rowCount: number }>('query_database', { query, database });
  }

  async readFile(path: string) {
    return this.callTool<{ content: string; size: number }>('read_file', { path });
  }

  async writeFile(path: string, content: string) {
    return this.callTool<{ success: boolean }>('write_file', { path, content });
  }

  async httpRequest(url: string, method = 'GET', body?: unknown) {
    return this.callTool<{ status: number; body: unknown }>('http_request', { url, method, body });
  }

  // ── Policy management ─────────────────────────────────────────────────

  async getAgentPolicy(agentId: string) {
    return this.get(`/api/policies/${agentId}`);
  }

  async updateAgentPolicy(agentId: string, allowedTools: string[]) {
    return this.put(`/api/policies/${agentId}`, { allowedTools });
  }

  async getAuditLog(options?: { limit?: number; agentId?: string; decision?: 'ALLOW' | 'DENY' }) {
    const params = new URLSearchParams();
    if (options?.limit) params.set('limit', String(options.limit));
    if (options?.agentId) params.set('agentId', options.agentId);
    if (options?.decision) params.set('decision', options.decision);
    return this.get(`/api/dashboard/audit?${params}`);
  }

  async getMetrics() {
    return this.get('/api/dashboard/metrics');
  }

  async healthCheck() {
    return this.get('/health/ready');
  }

  // ── Alert rules ───────────────────────────────────────────────────────

  async createAlertRule(rule: {
    name: string;
    eventType: 'denial_rate_spike' | 'injection_detected' | 'agent_blocked' | 'auth_failure';
    threshold: number;
    windowSeconds: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    channels: Array<'slack' | 'pagerduty' | 'webhook'>;
  }) {
    return this.post('/api/alerts/rules', rule);
  }

  async listAlertRules() {
    return this.get('/api/alerts/rules');
  }

  // ── Tool registry ─────────────────────────────────────────────────────

  async lookupToolServer(serverName: string) {
    return this.get(`/api/registry/servers/${encodeURIComponent(serverName)}`);
  }

  async listTrustedServers() {
    return this.get('/api/registry/servers?trust=trusted');
  }

  // ── HTTP internals ────────────────────────────────────────────────────

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.config.token}`,
    };
    if (this.config.oidcProvider) headers['X-OIDC-Provider'] = this.config.oidcProvider;
    if (this.config.tenantId) headers['X-Tenant-ID'] = this.config.tenantId;
    return headers;
  }

  private async post(path: string, body: unknown): Promise<any> {
    return this.request('POST', path, body);
  }

  private async get(path: string): Promise<any> {
    return this.request('GET', path);
  }

  private async put(path: string, body: unknown): Promise<any> {
    return this.request('PUT', path, body);
  }

  private async request(method: string, path: string, body?: unknown, attempt = 0): Promise<any> {
    const url = `${this.config.gatewayUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const res = await fetch(url, {
        method,
        headers: this.buildHeaders(),
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const errorBody = await res.json().catch(() => ({}));
        const errCode = this.mapHttpToCode(res.status);

        if (res.status === 429 && attempt < this.config.retries) {
          const retryAfter = parseInt(res.headers.get('retry-after') || '5', 10) * 1000;
          await sleep(retryAfter);
          return this.request(method, path, body, attempt + 1);
        }

        throw new McpGatewayError({
          code: errCode,
          message: (errorBody as any).error || `Gateway returned ${res.status}`,
          reason: (errorBody as any).reason,
        }, res.status);
      }

      return res.json();
    } catch (err: any) {
      if (err.name === 'AbortError') throw new McpGatewayError({ code: 'UPSTREAM_ERROR', message: 'Request timed out' }, 408);
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  private mapHttpToCode(status: number): GatewayError['code'] {
    if (status === 401) return 'AUTH_FAILED';
    if (status === 403) return 'POLICY_DENIED';
    if (status === 409) return 'REPLAY_DETECTED';
    if (status === 429) return 'RATE_LIMITED';
    return 'UPSTREAM_ERROR';
  }
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// ── React hook (bonus) ────────────────────────────────────────────────

export function createGatewayClient(config: GatewayConfig) {
  return new McpGatewayClient(config);
}
