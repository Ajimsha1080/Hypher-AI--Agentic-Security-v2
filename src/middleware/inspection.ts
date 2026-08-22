import { Pool } from 'pg';

export interface InspectionResult {
  allowed: boolean;
  reason?: string;
  flagged?: string;
}

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(previous|all|above|prior)\s+instructions?/i,
  /disregard\s+(previous|all|above)\s+instructions?/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /forget\s+everything/i,
  /new\s+system\s+prompt/i,
  /override\s+(your\s+)?(previous\s+)?instructions?/i,
  /act\s+as\s+(a|an)\s+/i,
  /jailbreak/i,
  /DAN\s+mode/i,
];

const SHELL_METACHAR = /[;&|`$(){}[\]<>\\]/;
const MAX_DEFAULT_LENGTH = 4096;

export async function inspectToolCall(
  toolName: string,
  args: Record<string, unknown>,
  db: Pool
): Promise<InspectionResult> {

  // 1. Prompt injection scan
  for (const str of extractStrings(args)) {
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(str)) {
        return { allowed: false, reason: 'prompt_injection_detected', flagged: str.slice(0, 200) };
      }
    }
  }

  // 2. Load per-tool rules from DB
  const { rows: rules } = await db.query(
    `SELECT arg_key, allowed_pattern, max_length, required
     FROM tool_arg_rules WHERE tool_name=$1 AND active=true`,
    [toolName]
  );

  // 3. Required args
  for (const r of rules.filter((r: any) => r.required)) {
    if (!(r.arg_key in args)) {
      return { allowed: false, reason: `missing_required_arg:${r.arg_key}` };
    }
  }

  // 4. Validate each arg
  for (const rule of rules) {
    const val = args[rule.arg_key];
    if (val === undefined || val === null) continue;
    const str = String(val);
    const maxLen = rule.max_length ?? MAX_DEFAULT_LENGTH;
    if (str.length > maxLen) {
      return { allowed: false, reason: `arg_too_long:${rule.arg_key}(${str.length}>${maxLen})` };
    }
    if (rule.allowed_pattern) {
      if (!new RegExp(rule.allowed_pattern).test(str)) {
        return { allowed: false, reason: `arg_not_allowed:${rule.arg_key}="${str.slice(0,80)}"` };
      }
    }
  }

  // 5. Default shell metachar check for unregistered tools
  if (rules.length === 0) {
    for (const str of extractStrings(args)) {
      if (SHELL_METACHAR.test(str) && str.length > 3) {
        return { allowed: false, reason: 'shell_metachar_detected', flagged: str.slice(0, 200) };
      }
    }
  }

  return { allowed: true };
}

function extractStrings(obj: unknown, depth = 0): string[] {
  if (depth > 5) return [];
  if (typeof obj === 'string') return [obj];
  if (Array.isArray(obj)) return obj.flatMap(v => extractStrings(v, depth + 1));
  if (obj && typeof obj === 'object') return Object.values(obj).flatMap(v => extractStrings(v, depth + 1));
  return [];
}
