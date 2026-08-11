import { GroundworkError } from './errors.js';
import { GroundworkClient } from './client.js';

/**
 * Mint a demo/console user assertion (HS256 JWT) signed with the runtime's
 * GROUNDWORK_JWT_HS_SECRET. Only for local development and first-party
 * console flows — production integrations receive end-user assertions from
 * the enterprise OIDC provider instead.
 *
 * Uses Web Crypto (Node >= 20, browsers); falls back to node:crypto on
 * Node 18.
 */
export async function mintUserAssertion(options: {
  hsSecret: string;
  subject: string;
  tenantId: string;
  roles?: string[];
  ttlSeconds?: number;
}): Promise<string> {
  const { hsSecret, subject, tenantId, roles = ['console-admin'], ttlSeconds = 300 } = options;
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: subject,
    iss: 'groundwork-console',
    aud: 'groundwork-query-runtime',
    tenant_id: tenantId,
    roles,
    iat: now,
    exp: now + ttlSeconds,
  };
  const b64url = (input: string | Uint8Array): string => {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    let bin = '';
    for (const byte of bytes) {
      bin += String.fromCharCode(byte);
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;

  if (globalThis.crypto?.subtle) {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(hsSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
    return `${signingInput}.${b64url(new Uint8Array(signature))}`;
  }

  const { createHmac } = await import('node:crypto');
  const signature = createHmac('sha256', hsSecret).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

export { GroundworkClient, GroundworkError };
export * from './types.js';
