/**
 * LLM Policy Assistant â€” NEW Enterprise Feature
 *
 * Lets customers describe security policies in plain English and
 * auto-generates structured Postgres policy rows.
 *
 * Example:
 *   Input:  "Allow agent-123 to read files but not write or delete them,
 *            and let it query the database with SELECT only"
 *   Output: Policy rows inserted into the policies table, plus
 *           tool_arg_rules for SELECT-only enforcement
 *
 * Uses Anthropic Claude API via the proxy (no API key in this file â€”
 * set ANTHROPIC_API_KEY in .env).
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Anthropic from '@anthropic-ai/sdk';
import axios from 'axios';
import { decryptValue, encryptValue } from '../security/secrets';

interface GeneratedPolicy {
  agentId: string;
  allowedTools: string[];
  toolArgRules: Array<{
    toolName: string;
    argKey: string;
    allowedPattern?: string;
    maxLength?: number;
    description: string;
  }>;
  explanation: string;
  warnings: string[];
}

const POLICY_LLM_PROVIDERS = [
  'anthropic',
  'openai',
  'azure_openai',
  'gemini',
  'mistral',
  'groq',
  'openrouter',
  'cohere',
  'ollama',
  'custom_openai',
] as const;

type PolicyLLMProvider = typeof POLICY_LLM_PROVIDERS[number];

interface PolicyLLMConfig {
  provider: PolicyLLMProvider;
  apiKey: string;
  model: string;
  baseUrl?: string;
  source: 'tenant' | 'platform';
}

const DEFAULT_POLICY_MODELS: Record<PolicyLLMProvider, string> = {
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-4.1-mini',
  azure_openai: 'gpt-4.1-mini',
  gemini: 'gemini-1.5-flash',
  mistral: 'mistral-small-latest',
  groq: 'llama-3.1-8b-instant',
  openrouter: 'openai/gpt-4.1-mini',
  cohere: 'command-r',
  ollama: 'llama3.1',
  custom_openai: 'gpt-4.1-mini',
};

function isPolicyProvider(provider: string): provider is PolicyLLMProvider {
  return (POLICY_LLM_PROVIDERS as readonly string[]).includes(provider);
}

function defaultPolicyModel(provider: PolicyLLMProvider): string {
  return DEFAULT_POLICY_MODELS[provider] || DEFAULT_POLICY_MODELS.anthropic;
}

function providerRequiresApiKey(provider: PolicyLLMProvider): boolean {
  return !['ollama', 'custom_openai'].includes(provider);
}

function providerRequiresBaseUrl(provider: PolicyLLMProvider): boolean {
  return ['azure_openai', 'ollama', 'custom_openai'].includes(provider);
}

function platformPolicyRuntimeSource(): 'platform' | 'local' {
  return (process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY)
    ? 'platform'
    : 'local';
}

const ALLOWED_POLICY_TOOLS = new Set([
  'tools/list',
  'codex_status',
  'list_workspace',
  'read_workspace_file',
  'create_workspace_file',
  'delete_workspace_file',
  'read_file',
  'write_file',
  'list_directory',
  'query_database',
  'http_request',
  'send_message',
  'web_search',
  'run_command',
]);

const POLICY_SYSTEM_PROMPT = `You are a security policy generator for MCP Security Gateway.
Given a natural language description of what an AI agent should and should not be able to do,
generate a structured policy in JSON format.

Available tools in the system:
- read_file, write_file, list_directory (filesystem)
- query_database (databases â€” enforce SELECT-only via arg pattern)
- http_request (external APIs â€” enforce URL allowlists)
- send_message (messaging)
- web_search, run_command (dangerous â€” restrict carefully)

Respond ONLY with a valid JSON object matching this exact shape:
{
  "allowedTools": ["tool1", "tool2"],
  "toolArgRules": [
    {
      "toolName": "query_database",
      "argKey": "query",
      "allowedPattern": "^SELECT",
      "maxLength": 2048,
      "description": "SELECT-only queries"
    }
  ],
  "explanation": "Human-readable explanation of what was configured",
  "warnings": ["Any security concerns the user should know about"]
}

Be conservative â€” prefer explicit allowlists over wildcards.
If the request seems overly permissive or dangerous, include a warning.
Never allow ['*'] (wildcard) unless the user explicitly asks for it.`;

export async function policyAssistantPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;
  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  fastify.get('/api/policy-assistant/byok', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Policy Assistant BYOK requires Growth or Enterprise plan' });
    }
    const config = await readTenantByokConfig(db, tenant.id, false);
    const provider = isPolicyProvider(String(config?.provider || '')) ? config.provider as PolicyLLMProvider : 'anthropic';
    const tenantRuntime = config?.enabled !== false && config?.configured && (config?.apiKeyEnc || !providerRequiresApiKey(provider));
    return {
      configured: Boolean(config?.configured),
      enabled: config?.enabled !== false,
      provider,
      providers: POLICY_LLM_PROVIDERS,
      model: config?.model || defaultPolicyModel(provider),
      baseUrl: config?.baseUrl || '',
      hasApiKey: Boolean(config?.apiKeyEnc),
      updatedAt: config?.updatedAt || null,
      runtimeSource: tenantRuntime ? 'tenant' : platformPolicyRuntimeSource(),
    };
  });

  fastify.put('/api/policy-assistant/byok', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Policy Assistant BYOK requires Growth or Enterprise plan' });
    }
    const body = req.body || {};
    const provider = String(body.provider || 'anthropic').trim().toLowerCase();
    if (!isPolicyProvider(provider)) return reply.code(400).send({ error: `Provider must be one of: ${POLICY_LLM_PROVIDERS.join(', ')}` });
    const model = String(body.model || defaultPolicyModel(provider)).trim();
    const baseUrl = String(body.baseUrl || '').trim();
    const apiKey = String(body.apiKey || '').trim();
    const enabled = body.enabled !== false;
    const existing = await readTenantByokConfig(db, tenant.id, false);
    if (providerRequiresApiKey(provider) && !apiKey && !existing?.apiKeyEnc) {
      return reply.code(400).send({ error: 'API key required for this provider' });
    }
    if (providerRequiresBaseUrl(provider) && !baseUrl && !existing?.baseUrl) {
      return reply.code(400).send({ error: 'Base URL / endpoint required for this provider' });
    }
    const config = {
      provider,
      model,
      baseUrl: baseUrl || existing?.baseUrl || '',
      apiKeyEnc: apiKey ? encryptValue(apiKey) : existing?.apiKeyEnc || '',
      enabled,
      configured: true,
      updatedAt: new Date().toISOString(),
    };
    await db.query(
      `UPDATE tenants SET metadata = jsonb_set(COALESCE(metadata,'{}'), '{policyAssistantByok}', $1::jsonb) WHERE id=$2`,
      [JSON.stringify(config), tenant.id]
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'policy_assistant.byok.save','policy_assistant',$4,NOW())`,
      [
        tenant.id,
        String(req.headers['x-admin-email'] || 'local-admin'),
        String(req.headers['x-admin-role'] || 'local_admin'),
        JSON.stringify({ provider, model, baseUrl: config.baseUrl ? '[configured]' : '', enabled }),
      ]
    ).catch(() => {});
    return { saved: true, configured: true, provider, model, baseUrl: config.baseUrl, enabled, hasApiKey: Boolean(config.apiKeyEnc) };
  });

  fastify.post('/api/policy-assistant/byok/test', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Policy Assistant BYOK requires Growth or Enterprise plan' });
    }
    const llm = await resolvePolicyLLMConfig(db, tenant.id);
    if (!llm) return { ok: true, source: 'local', message: 'No LLM key configured. Local conservative policy generator is available.' };
    try {
      const text = await callPolicyTextLLM(llm, 'Reply with only the word ok.');
      return { ok: /ok/i.test(text), source: llm.source, provider: llm.provider, model: llm.model };
    } catch (err: any) {
      return reply.code(502).send({ ok: false, error: err?.message || 'LLM test failed' });
    }
  });

  // â”€â”€ Generate policy from plain English â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  fastify.post('/api/policy-assistant/generate', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'AI policy assistant requires Growth or Enterprise plan' });
    }
    const { agentId, description, dryRun = false } = req.body;

    if (!agentId || !description) {
      return reply.code(400).send({ error: 'agentId and description required' });
    }

    const agent = await findActiveAgent(db, tenant.id, agentId);
    if (!agent) return reply.code(404).send({ error: 'Agent not found for this tenant' });

    // Check feature flag
    const flag = await db.query(
      `SELECT enabled FROM tenant_feature_flags WHERE tenant_id=$1 AND flag_name='policy_assistant'`,
      [tenant.id]
    );
    if (flag.rows.length && !flag.rows[0]?.enabled) {
      return reply.code(403).send({ error: 'Policy assistant requires Growth or Enterprise plan' });
    }

    let generated: GeneratedPolicy;
    const llm = await resolvePolicyLLMConfig(db, tenant.id);
    if (llm) {
      try {
        generated = await callPolicyLLM(llm, agentId, description);
      } catch (err: any) {
        return reply.code(500).send({ error: `LLM error: ${err.message}` });
      }
    } else {
      generated = generateLocalPolicy(agentId, description);
    }
    generated = sanitizeGeneratedPolicy(agentId, generated);

    if (dryRun) {
      return { dryRun: true, policy: generated };
    }

    // Apply the generated policy
    await applyGeneratedPolicy(
      tenant.id,
      agentId,
      generated,
      db,
      description,
      req.user?.email || req.headers['x-admin-email'] || 'api'
    );

    // Log the action
    await db.query(
      `INSERT INTO admin_actions (action, target_id, reason, performed_by)
       VALUES ('policy_assistant_generated', $1, $2, $3)`,
      [agentId, description.slice(0, 200), req.user?.email || req.headers['x-admin-email'] || 'api']
    );

    return {
      applied: true,
      policy: generated,
      message: `Policy applied for agent ${agentId}. ${generated.allowedTools.length} tools allowed.`,
    };
  });

  fastify.post('/api/policy-assistant/apply', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'AI policy assistant requires Growth or Enterprise plan' });
    }

    const { agentId, description = 'Applied from policy assistant preview', policy } = req.body || {};
    if (!agentId || !policy) return reply.code(400).send({ error: 'agentId and policy required' });

    const agent = await findActiveAgent(db, tenant.id, agentId);
    if (!agent) return reply.code(404).send({ error: 'Agent not found for this tenant' });

    const generated = sanitizeGeneratedPolicy(agentId, {
      agentId,
      allowedTools: Array.isArray(policy.allowedTools) ? policy.allowedTools.map(String).slice(0, 100) : [],
      toolArgRules: Array.isArray(policy.toolArgRules) ? policy.toolArgRules.slice(0, 100) : [],
      explanation: String(policy.explanation || ''),
      warnings: Array.isArray(policy.warnings) ? policy.warnings.map(String).slice(0, 50) : [],
    });

    await applyGeneratedPolicy(
      tenant.id,
      agentId,
      generated,
      db,
      description,
      req.user?.email || req.headers['x-admin-email'] || 'api'
    );

    return {
      applied: true,
      policy: generated,
      message: `Policy applied for agent ${agentId}. ${generated.allowedTools.length} tools allowed.`,
    };
  });

  // â”€â”€ Explain existing policy in plain English â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  fastify.get('/api/policy-assistant/explain/:agentId', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'AI policy assistant requires Growth or Enterprise plan' });
    }
    const policyRows = await db.query(
      `SELECT tool_name, action, allowed_tools, active FROM policies WHERE agent_id=$1 AND tenant_id=$2 AND active=true`,
      [req.params.agentId, tenant.id]
    );
    if (!policyRows.rows.length) {
      return { explanation: 'No policy found for this agent. All tool calls will be denied.' };
    }

    const tools = policyRows.rows.flatMap((row: any) =>
      Array.isArray(row.allowed_tools) && row.allowed_tools.length ? row.allowed_tools : [row.tool_name]
    ).filter(Boolean);
    const argRules = await db.query(
      `SELECT DISTINCT ON (tool_name, arg_key)
              tool_name, arg_key, allowed_pattern, max_length, description
       FROM tool_arg_rules
       WHERE (tenant_id=$1 OR tenant_id IS NULL)
         AND tool_name = ANY($2::text[])
       ORDER BY tool_name, arg_key, CASE WHEN tenant_id=$1 THEN 0 ELSE 1 END`,
      [tenant.id, tools.length ? tools : ['__none__']]
    );

    const llm = await resolvePolicyLLMConfig(db, tenant.id);
    if (!llm) {
      return { explanation: `This agent can use ${tools.length ? tools.join(', ') : 'no tools'}. ${argRules.rows.length} argument rules are active for this tenant.` };
    }

    const text = await callPolicyTextLLM(
      llm,
      `Explain this MCP Security Gateway policy in plain English for a non-technical user:
          Allowed tools: ${JSON.stringify(policyRows.rows.flatMap((row: any) => Array.isArray(row.allowed_tools) && row.allowed_tools.length ? row.allowed_tools : [row.tool_name]))}
          Argument rules: ${JSON.stringify(argRules.rows)}
          Keep it to 2-3 sentences.`
    );

    return { explanation: text };
  });

  // â”€â”€ Suggest improvements to existing policy â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  fastify.post('/api/policy-assistant/suggest', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'AI policy assistant requires Growth or Enterprise plan' });
    }
    const { agentId } = req.body;

    // Fetch recent audit log for this agent
    const recentActivity = await db.query(
      `SELECT tool_name, decision, reason, COUNT(*) as cnt
       FROM audit_log WHERE agent_id=$1 AND tenant_id=$2 AND created_at > NOW()-INTERVAL '7d'
       GROUP BY tool_name, decision, reason ORDER BY cnt DESC LIMIT 20`,
      [agentId, tenant.id]
    );

    const llm = await resolvePolicyLLMConfig(db, tenant.id);
    if (!llm) {
      const denied = recentActivity.rows.filter((r: any) => r.decision === 'DENY');
      return {
        suggestions: recentActivity.rows.length ? ['Review the most frequent denied tools before adding access.', 'Prefer argument allowlists for database, file, and HTTP tools.'] : ['No recent activity found. Start with read-only access, then tighten from audit evidence.'],
        warnings: denied.length ? denied.slice(0, 3).map((r: any) => `${r.tool_name} was denied ${r.cnt} times: ${r.reason || 'no reason recorded'}`) : [],
        unusedTools: [],
      };
    }

    const text = await callPolicyTextLLM(
      llm,
      `Based on this agent's activity over the last 7 days, suggest policy improvements.
          Activity: ${JSON.stringify(recentActivity.rows)}
          Suggest: tools to add/remove, arg rules to tighten, security concerns.
          Format as JSON: { "suggestions": ["..."], "warnings": ["..."], "unusedTools": ["..."] }`
    );

    try {
      const suggestions = JSON.parse(text.replace(/```json\n?|```/g, '').trim());
      return suggestions;
    } catch {
      return { suggestions: [text] };
    }
  });
}

// â”€â”€ LLM call â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function callPolicyLLM(config: PolicyLLMConfig, agentId: string, description: string): Promise<GeneratedPolicy> {
  const rawText = await callPolicyTextLLM(config, `Agent ID: ${agentId}\n\nPolicy description: ${description}`, POLICY_SYSTEM_PROMPT, 1000);
  const parsed = JSON.parse(rawText.replace(/```json\n?|```/g, '').trim());

  return {
    agentId,
    allowedTools: parsed.allowedTools || [],
    toolArgRules: parsed.toolArgRules || [],
    explanation: parsed.explanation || '',
    warnings: parsed.warnings || [],
  };
}

async function callPolicyTextLLM(config: PolicyLLMConfig, prompt: string, system?: string, maxTokens = 800): Promise<string> {
  if (config.provider === 'anthropic') {
    const client = new Anthropic({ apiKey: config.apiKey });
    const msg = await client.messages.create({
      model: config.model,
      max_tokens: maxTokens,
      ...(system ? { system } : {}),
      messages: [{ role: 'user', content: prompt }],
    });
    return (msg.content[0] as any).text || '';
  }

  if (config.provider === 'gemini') {
    const base = (config.baseUrl || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');
    const response = await axios.post(`${base}/models/${encodeURIComponent(config.model)}:generateContent?key=${encodeURIComponent(config.apiKey)}`, {
      ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: maxTokens },
    }, { timeout: 20_000 });
    return (response.data?.candidates?.[0]?.content?.parts || []).map((part: any) => part.text || '').join('') || '';
  }

  if (config.provider === 'cohere') {
    const url = config.baseUrl || 'https://api.cohere.com/v2/chat';
    const response = await axios.post(url, {
      model: config.model,
      messages: [
        ...(system ? [{ role: 'system', content: system }] : []),
        { role: 'user', content: prompt },
      ],
      temperature: 0.1,
      max_tokens: maxTokens,
    }, {
      headers: { Authorization: `Bearer ${config.apiKey}`, 'Content-Type': 'application/json' },
      timeout: 20_000,
    });
    const content = response.data?.message?.content;
    if (Array.isArray(content)) return content.map((part: any) => part.text || '').join('');
    return response.data?.text || '';
  }

  if (config.provider === 'azure_openai') {
    const endpoint = String(config.baseUrl || '').replace(/\/$/, '');
    const baseUrl = endpoint.includes('/chat/completions')
      ? endpoint
      : `${endpoint}/openai/deployments/${encodeURIComponent(config.model)}/chat/completions`;
    const url = baseUrl.includes('api-version=') ? baseUrl : `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}api-version=2024-02-15-preview`;
    const response = await axios.post(url, {
      messages: [
        ...(system ? [{ role: 'system', content: system }] : []),
        { role: 'user', content: prompt },
      ],
      temperature: 0.1,
      max_tokens: maxTokens,
    }, {
      headers: { 'api-key': config.apiKey, 'Content-Type': 'application/json' },
      timeout: 20_000,
    });
    return response.data?.choices?.[0]?.message?.content || '';
  }

  const response = await axios.post(openAiCompatibleChatUrl(config), {
    model: config.model,
    messages: [
      ...(system ? [{ role: 'system', content: system }] : []),
      { role: 'user', content: prompt },
    ],
    temperature: 0.1,
    max_tokens: maxTokens,
  }, {
    headers: openAiCompatibleHeaders(config),
    timeout: 20_000,
  });
  return response.data?.choices?.[0]?.message?.content || '';
}

function openAiCompatibleChatUrl(config: PolicyLLMConfig): string {
  const defaults: Partial<Record<PolicyLLMProvider, string>> = {
    openai: 'https://api.openai.com/v1',
    mistral: 'https://api.mistral.ai/v1',
    groq: 'https://api.groq.com/openai/v1',
    openrouter: 'https://openrouter.ai/api/v1',
    ollama: 'http://127.0.0.1:11434',
  };
  const base = String(config.baseUrl || defaults[config.provider] || 'https://api.openai.com/v1').replace(/\/$/, '');
  if (base.endsWith('/chat/completions')) return base;
  if (base.endsWith('/v1')) return `${base}/chat/completions`;
  return `${base}/v1/chat/completions`;
}

function openAiCompatibleHeaders(config: PolicyLLMConfig): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;
  if (config.provider === 'openrouter') {
    headers['HTTP-Referer'] = process.env.PUBLIC_APP_URL || 'http://localhost:3000';
    headers['X-Title'] = 'MCP Security Gateway Policy Assistant';
  }
  return headers;
}

async function readTenantByokConfig(db: Pool, tenantId: string, decrypt = true): Promise<any | null> {
  const r = await db.query(`SELECT metadata->>'policyAssistantByok' AS config FROM tenants WHERE id=$1`, [tenantId]).catch(() => ({ rows: [] }));
  if (!r.rows[0]?.config) return null;
  const config = JSON.parse(r.rows[0].config);
  if (decrypt && config.apiKeyEnc) config.apiKey = decryptValue(config.apiKeyEnc);
  return config;
}

async function resolvePolicyLLMConfig(db: Pool, tenantId: string): Promise<PolicyLLMConfig | null> {
  const tenantConfig = await readTenantByokConfig(db, tenantId, true);
  const tenantProvider = String(tenantConfig?.provider || 'anthropic').toLowerCase();
  if (tenantConfig?.enabled !== false && isPolicyProvider(tenantProvider) && (tenantConfig?.apiKey || !providerRequiresApiKey(tenantProvider))) {
    return {
      provider: tenantProvider,
      apiKey: tenantConfig.apiKey || '',
      model: tenantConfig.model || defaultPolicyModel(tenantProvider),
      baseUrl: tenantConfig.baseUrl || '',
      source: 'tenant',
    };
  }
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      provider: 'anthropic',
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: defaultPolicyModel('anthropic'),
      source: 'platform',
    };
  }
  if (process.env.OPENAI_API_KEY) {
    return {
      provider: 'openai',
      apiKey: process.env.OPENAI_API_KEY,
      model: process.env.OPENAI_POLICY_MODEL || defaultPolicyModel('openai'),
      source: 'platform',
    };
  }
  if (process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY) {
    return {
      provider: 'gemini',
      apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '',
      model: process.env.GEMINI_POLICY_MODEL || defaultPolicyModel('gemini'),
      source: 'platform',
    };
  }
  return null;
}

// â”€â”€ Apply to DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function generateLocalPolicy(agentId: string, description: string): GeneratedPolicy {
  const d = description.toLowerCase();
  const allowedTools = new Set<string>();
  const toolArgRules: GeneratedPolicy['toolArgRules'] = [];
  const warnings: string[] = [];
  const deniesDatabase = /\b(no|not|deny|block|without|never)\b.{0,120}\b(database|sql|query|mutation|mutate)\b|\bdo\s+not\s+allow\b[^.]*\b(database|sql|query|mutation|mutate)\b|\b(database|sql|query|mutation|mutate)\b.{0,80}\b(no|not|deny|block|without|never)\b/.test(d);
  const deniesDangerous = /\b(no|not|deny|block|without|never)\b.{0,140}\b(write|create|update|edit|delete|remove|shell|command|execute|http|api|webhook|database|sql|query|mutation|mutate)\b|\bdo\s+not\s+allow\b[^.]*\b(write|create|update|edit|delete|remove|shell|command|execute|http|api|webhook|database|sql|query|mutation|mutate)\b/.test(d);

  if (/\btools?\s*\/?\s*list\b|\blist tools?\b|\bdiscover(y)?\b|\bmcp tools?\b/.test(d)) allowedTools.add('tools/list');
  if (/\bstatus|health|ping\b/.test(d)) allowedTools.add('codex_status');
  if (/\blist|directory|folder|workspace|file/.test(d)) allowedTools.add('list_workspace');
  if (/\bread|view|open|get|file|workspace/.test(d)) allowedTools.add('read_workspace_file');
  if (/\bcreate|write|update|edit|save\b/.test(d) && !deniesDangerous) {
    allowedTools.add('create_workspace_file');
    warnings.push('File write access should stay behind approval or strict path rules in production.');
  }
  if (/\bdelete|remove\b/.test(d) && !deniesDangerous) {
    allowedTools.add('delete_workspace_file');
    warnings.push('File deletion is destructive and should require human approval.');
  }
  if (/\bselect|query|database|sql/.test(d) && !deniesDatabase) {
    allowedTools.add('query_database');
    toolArgRules.push({
      toolName: 'query_database',
      argKey: 'query',
      allowedPattern: '^\\s*SELECT\\b',
      maxLength: 2048,
      description: 'SELECT-only database queries',
    });
  }
  if (/\bweb search|search web|web_search/.test(d)) allowedTools.add('web_search');
  if (/\bhttp|api|webhook/.test(d) && !deniesDangerous) {
    allowedTools.add('http_request');
    warnings.push('HTTP access should be restricted with domain allowlists before production use.');
  }
  if (deniesDangerous) {
    warnings.push('Dangerous access was explicitly denied and was not added to the generated allowlist.');
  } else if (/\bwrite|delete|remove|run command|shell|execute/.test(d)) {
    warnings.push('Destructive or command-execution access was requested. Keep it behind human approval and narrow argument rules.');
  }
  if (!allowedTools.size) {
    allowedTools.add('tools/list');
    warnings.push('No clear tool intent was detected, so only MCP discovery is allowed.');
  }

  return {
    agentId,
    allowedTools: Array.from(allowedTools),
    toolArgRules,
    explanation: 'Generated by the local enterprise policy assistant using conservative allowlist rules. Configure ANTHROPIC_API_KEY to use the LLM-backed generator.',
    warnings,
  };
}

async function findActiveAgent(db: Pool, tenantId: string, agentId: string) {
  const agent = await db.query(
    `SELECT agent_id FROM agent_tokens WHERE tenant_id=$1 AND agent_id=$2 AND active=true LIMIT 1`,
    [tenantId, agentId]
  );
  return agent.rows[0] || null;
}

function sanitizeGeneratedPolicy(agentId: string, policy: GeneratedPolicy): GeneratedPolicy {
  const warnings = new Set<string>((policy.warnings || []).map(String).filter(Boolean));
  const allowedTools = Array.from(new Set((policy.allowedTools || []).map(String)))
    .filter(tool => {
      const ok = ALLOWED_POLICY_TOOLS.has(tool);
      if (!ok) warnings.add(`Ignored unsupported tool "${tool}".`);
      return ok;
    })
    .filter(tool => {
      const ok = tool !== '*';
      if (!ok) warnings.add('Wildcard tool access is not allowed by the enterprise policy assistant.');
      return ok;
    })
    .slice(0, 50);

  const allowedToolSet = new Set(allowedTools);
  const toolArgRules = (policy.toolArgRules || []).flatMap((raw: any) => {
    const toolName = String(raw.toolName || '');
    const argKey = String(raw.argKey || '');
    const maxLength = Number(raw.maxLength || 4096);
    const allowedPattern = raw.allowedPattern ? String(raw.allowedPattern) : undefined;
    if (!allowedToolSet.has(toolName) || !argKey || !/^[a-zA-Z0-9_.-]{1,80}$/.test(argKey)) {
      warnings.add(`Ignored invalid argument rule for "${toolName || 'unknown'}".`);
      return [];
    }
    if (allowedPattern) {
      try { new RegExp(allowedPattern); }
      catch {
        warnings.add(`Ignored invalid regex for ${toolName}.${argKey}.`);
        return [];
      }
    }
    return [{
      toolName,
      argKey,
      allowedPattern,
      maxLength: Math.max(1, Math.min(Number.isFinite(maxLength) ? maxLength : 4096, 65536)),
      description: String(raw.description || 'Generated argument rule').slice(0, 500),
    }];
  }).slice(0, 100);

  return {
    agentId,
    allowedTools: allowedTools.length ? allowedTools : ['tools/list'],
    toolArgRules,
    explanation: String(policy.explanation || 'Generated policy').slice(0, 1000),
    warnings: Array.from(warnings).slice(0, 50),
  };
}

async function applyGeneratedPolicy(
  tenantId: string, agentId: string,
  generated: GeneratedPolicy, db: Pool,
  changeReason = 'Policy assistant generated policy',
  changedBy = 'api'
): Promise<void> {
  await db.query('BEGIN');
  let stage = 'begin';
  try {
    // Deactivate existing policies for this agent
    stage = 'deactivate_existing_policies';
    await db.query(
      `UPDATE policies SET active=false WHERE agent_id=$1 AND tenant_id=$2`,
      [agentId, tenantId]
    );

    // Insert one explicit allow row per tool. This keeps the policy readable in
    // older schemas that require tool_name, while the runtime also supports
    // newer allowed_tools rows.
    for (const tool of generated.allowedTools) {
      stage = `insert_policy:${tool}`;
      await db.query(
        `INSERT INTO policies (agent_id, tenant_id, tool_name, action, priority, active, description)
         VALUES ($1, $2, $3, 'allow', 100, true, 'Policy assistant generated allow rule')`,
        [agentId, tenantId, tool]
      );
    }

    stage = 'insert_policy_version';
    await db.query(
      `INSERT INTO policy_versions (tenant_id, agent_id, version, changed_by, change_reason, snapshot_json)
       VALUES ($1,$2,(SELECT COALESCE(MAX(version),0)+1 FROM policy_versions WHERE tenant_id=$1 AND agent_id=$2),$3,$4,$5)`,
      [
        tenantId,
        agentId,
        String(changedBy),
        String(changeReason).slice(0, 500),
        JSON.stringify({
          allowedTools: generated.allowedTools,
          toolArgRules: generated.toolArgRules,
          explanation: generated.explanation,
          warnings: generated.warnings,
        }),
      ]
    ).catch(() => {});

    // Insert argument rules
    for (const rule of generated.toolArgRules) {
      stage = `upsert_arg_rule:${rule.toolName}.${rule.argKey}`;
      const params = [
        rule.toolName,
        rule.argKey,
        rule.allowedPattern || null,
        rule.maxLength || 4096,
        rule.description,
        tenantId,
      ];
      const updated = await db.query(
        `UPDATE tool_arg_rules
         SET allowed_pattern=$3, max_length=$4, description=$5, active=true
         WHERE tool_name=$1 AND arg_key=$2 AND tenant_id=$6`,
        params
      );
      if (updated.rowCount === 0) {
        try {
          await db.query(
            `INSERT INTO tool_arg_rules
               (tool_name, arg_key, allowed_pattern, max_length, description, tenant_id, active)
             VALUES ($1,$2,$3,$4,$5,$6,true)`,
            params
          );
        } catch (e: any) {
          if (e?.code !== '23505') throw e;
          await db.query(
            `UPDATE tool_arg_rules
             SET allowed_pattern=$3, max_length=$4, description=$5, active=true
             WHERE tool_name=$1 AND arg_key=$2 AND tenant_id=$6`,
            params
          );
        }
      }
    }

    await db.query('COMMIT');
  } catch (e) {
    await db.query('ROLLBACK');
    if (e && typeof e === 'object') {
      (e as any).message = `Policy apply failed at ${stage}: ${(e as any).message}`;
    }
    throw e;
  }
}
