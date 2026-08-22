import crypto from 'crypto';

const ENCRYPTED_MARKER = '__mcpsg_encrypted_v1';
const SECRET_KEYS = new Set([
  'url',
  'webhookUrl',
  'integrationKey',
  'routingKey',
  'secret',
  'token',
  'botToken',
  'signingSecret',
  'apiKey',
  'password',
  'smtpPassword',
  'clientSecret',
  'privateKey',
]);

function encryptionKey(): Buffer {
  const source =
    process.env.SECRET_ENCRYPTION_KEY ||
    process.env.ADMIN_SESSION_SECRET ||
    process.env.ADMIN_SECRET ||
    'local-development-secret-encryption-key';
  return crypto.createHash('sha256').update(source).digest();
}

export function hasProductionSecretEncryption(): boolean {
  return Boolean(process.env.SECRET_ENCRYPTION_KEY && process.env.SECRET_ENCRYPTION_KEY.length >= 32);
}

export function encryptValue(value: string): string {
  if (!value || value.startsWith(`${ENCRYPTED_MARKER}:`)) return value;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_MARKER}:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

export function decryptValue(value: string): string {
  if (!value || !value.startsWith(`${ENCRYPTED_MARKER}:`)) return value;
  const [, ivB64, tagB64, dataB64] = value.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function encryptSecretConfig<T>(config: T): T {
  return transformConfig(config, (key, value) => (
    SECRET_KEYS.has(key) && typeof value === 'string' ? encryptValue(value) : value
  ));
}

export function decryptSecretConfig<T>(config: T): T {
  return transformConfig(config, (_key, value) => (
    typeof value === 'string' && value.startsWith(`${ENCRYPTED_MARKER}:`) ? decryptValue(value) : value
  ));
}

export function redactSecretConfig<T>(config: T): T {
  return transformConfig(config, (key, value) => {
    if (!SECRET_KEYS.has(key) || typeof value !== 'string' || !value) return value;
    const plain = decryptValue(value);
    if (plain.includes('@') && !plain.startsWith('http')) {
      const [name, domain] = plain.split('@');
      return `${name.slice(0, 2)}***@${domain}`;
    }
    if (plain.startsWith('http')) {
      try {
        const url = new URL(plain);
        return `${url.origin}${url.pathname.split('/').slice(0, 3).join('/')}/...`;
      } catch {
        return '[redacted-url]';
      }
    }
    return plain.length > 8 ? `${plain.slice(0, 4)}...${plain.slice(-4)}` : '[redacted]';
  });
}

function transformConfig<T>(value: T, visitor: (key: string, value: unknown) => unknown, key = ''): T {
  if (Array.isArray(value)) return value.map(v => transformConfig(v, visitor, key)) as T;
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, transformConfig(v, visitor, k)])
    ) as T;
  }
  return visitor(key, value) as T;
}
