/* Base32 (RFC 4648) y TOTP (RFC 6238) — sin dependencias */

import crypto from 'node:crypto';

export const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Quita basura típica de copiar-pegar: invisibles, comillas y etiquetas. */
export function sanitizeSecret(input) {
  let s = String(input ?? '');
  // zero-width, soft hyphen, BOM y espacios no separables
  s = s.replace(/[\u200B-\u200D\u2060\uFEFF\u00AD\u00A0]/g, '');
  // comillas y espacios en los extremos
  s = s.replace(/^[`'"\s]+|[`'"\s]+$/g, '');
  // prefijos tipo "Secret:", "Clave:", "Base32:"
  const m = s.match(/^(?:secret|clave|c[oó]digo|key|base32|token)\s*[:=-]\s*(.+)$/is);
  if (m) s = m[1].trim();
  return s.trim();
}

/**
 * Normaliza lo que el usuario pega a base32 estándar:
 *  - "Emisor: CLAVE"  → CLAVE
 *  - secreto en hex    → base32
 *  - secreto en base64 → base32
 */
export function normalizeSecretInput(input) {
  let s = sanitizeSecret(input);

  // Etiqueta con dos puntos delante de la clave
  const ci = s.lastIndexOf(':');
  if (ci > -1) {
    const tail = s.slice(ci + 1).trim();
    const cleaned = tail.replace(/[\s-]/g, '');
    if (cleaned.length >= 16 && /^[A-Za-z0-9+/=]+$/.test(cleaned)) s = tail;
  }

  // Hex (32/40/64 chars = 16/20/32 bytes). Solo si trae 0/1/8/9:
  // esos caracteres no existen en base32 válido, así no hay ambigüedad.
  const compact = s.replace(/\s+/g, '');
  if (
    /^[0-9a-fA-F]+$/.test(compact) &&
    (compact.length === 32 || compact.length === 40 || compact.length === 64) &&
    /[0189]/.test(compact)
  ) {
    return base32Encode(Buffer.from(compact, 'hex'));
  }

  // Base64 (contiene + o /, algo que el base32 nunca tiene)
  if (/^[A-Za-z0-9+/=\s]+$/.test(s) && /[+/]/.test(s)) {
    try {
      const buf = Buffer.from(s.replace(/\s+/g, ''), 'base64');
      if (buf.length >= 10) return base32Encode(buf);
    } catch { /* se queda como estaba */ }
  }

  return s;
}

/**
 * Extrae la clave de textos "sucios": un enlace otpauth:// en cualquier parte,
 * o una URL que lleve la clave dentro (parámetro secret, chl de un QR, etc.).
 * Devuelve { secret, issuer, name } o null si no hay nada que extraer.
 */
export function extractFromPastedText(input) {
  const s = String(input ?? '').replace(/&amp;/gi, '&');

  // 1) enlace otpauth:// aparezca donde aparezca (etiquetas, saltos de línea…)
  const m = s.match(/otpauth:\/\/[^\s"'<>]+/i);
  if (m) {
    try {
      const p = parseOtpauth(m[0].replace(/[).,;]+$/, ''));
      if (p && p.secret) return p;
    } catch { /* continúa */ }
  }

  // 2) ¿es una URL http(s) con la clave dentro?
  const trimmed = s.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const u = new URL(trimmed);
      const direct = u.searchParams.get('secret');
      if (direct && direct.trim()) {
        return {
          secret: direct.trim(),
          issuer: u.searchParams.get('issuer') || '',
          name: ''
        };
      }
      const chl = u.searchParams.get('chl'); // URLs tipo Google Charts que generan el QR
      if (chl) {
        let inner = chl;
        try {
          inner = decodeURIComponent(chl);
        } catch { /* ya decodificada */ }
        const im = inner.match(/otpauth:\/\/[^\s"'<>]+/i);
        if (im) {
          try {
            const p = parseOtpauth(im[0].replace(/[).,;]+$/, ''));
            if (p && p.secret) return p;
          } catch { /* continúa */ }
        }
        if (looksLikeBase32(inner)) return { secret: inner.trim(), issuer: '', name: '' };
      }
      for (const k of ['key', 'token', 'otp', 'totp']) {
        const v = u.searchParams.get(k);
        if (v && looksLikeBase32(v)) return { secret: v.trim(), issuer: '', name: '' };
      }
    } catch { /* no era una URL parseable */ }
  }
  return null;
}

function looksLikeBase32(v) {
  const cleaned = String(v).trim().replace(/[\s-]/g, '').replace(/=+$/g, '');
  return cleaned.length >= 16 && /^[A-Za-z2-7]+$/.test(cleaned);
}

export function base32Decode(input) {
  const s = sanitizeSecret(input).replace(/[\s-]/g, '').replace(/=+$/g, '').toUpperCase();
  const bad = [...new Set([...s].filter((ch) => !B32.includes(ch)))];
  if (bad.length) {
    const show = bad
      .map((c) => (/[\x20-\x7E]/.test(c) ? `"${c}"` : `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`))
      .join(', ');
    let msg = `Clave secreta inválida: caracteres no permitidos ${show}. Usa solo A-Z y 2-7.`;
    if (/https?:\/\/|www\.|otpauth:/i.test(String(input ?? ''))) {
      msg =
        'Eso parece una URL, no una clave. Copia la clave secreta (base32) o el enlace completo que empieza con "otpauth://". ' +
        msg;
    } else if (/[0189]/.test(s)) {
      msg += ' Si tu servicio muestra 0/1/8/9, prueba sustituirlos por O/I/B/G.';
    }
    throw new Error(msg);
  }
  if (s.length < 16) throw new Error('La clave secreta es demasiado corta (mínimo 16 caracteres).');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length < 10) throw new Error('La clave secreta es demasiado corta (mínimo 16 caracteres).');
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
  const s = String(input || '').trim().replace(/&amp;/gi, '&');
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
