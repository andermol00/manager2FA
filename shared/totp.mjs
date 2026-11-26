/* Base32 (RFC 4648) y TOTP (RFC 6238) — sin dependencias */

import crypto from 'node:crypto';

export const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(str) {
  const s = String(str).replace(/[\s-]/g, '').replace(/=+$/g, '').toUpperCase();
  if (s.length < 16) throw new Error('La clave secreta es demasiado corta.');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error('Clave secreta inválida (usa A-Z y 2-7).');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length < 10) throw new Error('La clave secreta es demasiado corta.');
  return Buffer.from(out);
}

export function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function totp(keyBuf, seconds) {
  const counter = Math.floor(seconds / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', keyBuf).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin =
    ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

export function verifyCode(secretStr, code) {
  const key = base32Decode(secretStr);
  const now = Math.floor(Date.now() / 1000);
  const c = String(code || '').replace(/\D/g, '');
  if (c.length !== 6) return false;
  for (let w = -1; w <= 1; w++) {
    if (totp(key, now + w * 30) === c) return true;
  }
  return false;
}

export function otpauthUrl(secret, issuer = 'Authenticator 2FA', label = 'Acceso') {
  const full = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${full}?secret=${secret}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=SHA1&digits=6&period=30`;
}

export function parseOtpauth(input) {
  const s = String(input || '').trim();
  if (!/^otpauth:\/\//i.test(s)) return null;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error('Enlace otpauth inválido.');
  }
  const params = u.searchParams;
  const pathLabel = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const colon = pathLabel.indexOf(':');
  return {
    secret: (params.get('secret') || '').trim(),
    issuer: (params.get('issuer') || (colon > 0 ? pathLabel.slice(0, colon) : '')).trim(),
    name: (colon > 0 ? pathLabel.slice(colon + 1) : pathLabel).trim() || 'Cuenta'
  };
}
