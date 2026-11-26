/* Cifrado en reposo (AES-256-GCM) y sesiones firmadas (HMAC-SHA256) */

import crypto from 'node:crypto';

function keyFrom(appSecret) {
  return crypto.createHash('sha256').update(String(appSecret)).digest();
}

export function encSecret(appSecret, plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keyFrom(appSecret), iv);
  const data = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return {
    iv: iv.toString('base64'),
    d: data.toString('base64'),
    t: c.getAuthTag().toString('base64')
  };
}

export function decSecret(appSecret, obj) {
  const d = crypto.createDecipheriv('aes-256-gcm', keyFrom(appSecret), Buffer.from(obj.iv, 'base64'));
  d.setAuthTag(Buffer.from(obj.t, 'base64'));
  return Buffer.concat([d.update(Buffer.from(obj.d, 'base64')), d.final()]).toString('utf8');
}

function sign(appSecret, payload) {
  return crypto.createHmac('sha256', String(appSecret)).update(payload).digest('base64url');
}

export function makeSessionToken(appSecret, ttlMs) {
  const payload = Buffer.from(
    JSON.stringify({ exp: Date.now() + ttlMs, jti: crypto.randomUUID() })
  ).toString('base64url');
  return `${payload}.${sign(appSecret, payload)}`;
}

/** Devuelve { exp, jti } si la firma y la vigencia son válidas; si no, null. */
export function parseSessionToken(appSecret, token) {
  if (!token || typeof token !== 'string') return null;
  const i = token.indexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expected = sign(appSecret, payload);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof data.exp !== 'number' || data.exp <= Date.now() || !data.jti) return null;
    return data;
  } catch {
    return null;
  }
}
