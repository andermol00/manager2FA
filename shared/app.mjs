/*
 * Router de la API — compartido entre:
 *   • Netlify Function  (netlify/functions/api.mjs, contexto real → Blobs)
 *   • Servidor local    (dev-server.mjs, context.dev = true → archivo)
 */

import crypto from 'node:crypto';
import QRCode from 'qrcode';
import {
  base32Decode,
  base32Encode,
  totp,
  verifyCode,
  otpauthUrl,
  parseOtpauth,
  sanitizeSecret,
  normalizeSecretInput,
  extractFromPastedText
} from './totp.mjs';
import { isMigrationText, parseMigrationAccounts } from './migration.mjs';
import { encSecret, decSecret, makeSessionToken, parseSessionToken } from './security.mjs';
import { loadState, saveState } from './store.mjs';

const COOKIE = 'auth2fa_session';
const TTL_MS = 7 * 24 * 3600 * 1000;
const ISSUER = 'Authenticator 2FA';
const LABEL = 'Acceso';

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extra }
  });
}

/** Acepta tanto /api/login como /.netlify/functions/api/login (según el rewrite). */
function apiSubpath(pathname) {
  const marker = '/.netlify/functions/api';
  let p = pathname;
  const i = p.indexOf(marker);
  if (i >= 0) p = '/api' + p.slice(i + marker.length);
  if (!p.startsWith('/api')) return null;
  p = p.slice(4);
  if (p.startsWith('/')) p = p.slice(1);
  if (p.endsWith('/')) p = p.slice(0, -1);
  return p;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function tokenFrom(request) {
  const a = request.headers.get('authorization') || '';
  if (a.startsWith('Bearer ')) return a.slice(7).trim();
  return parseCookies(request.headers.get('cookie'))[COOKIE] || null;
}

function clientIp(request) {
  const nf = request.headers.get('x-nf-client-ip');
  if (nf) return nf.trim();
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

function sessionCookie(token, request) {
  const proto =
    request.headers.get('x-forwarded-proto') ||
    new URL(request.url).protocol.replace(':', '');
  const secure = proto === 'https' ? '; Secure' : '';
  return `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(
    TTL_MS / 1000
  )}${secure}`;
}

const clearCookie = `${COOKIE}=; HttpOnly; Path=/; Max-Age=0`;

export async function handleApi(request, context = {}) {
  try {
    const url = new URL(request.url);
    const sub = apiSubpath(url.pathname);
    if (sub === null) return json({ error: 'No encontrado.' }, 404);

    const method = (request.method || 'GET').toUpperCase();
    const seg = sub ? sub.split('/') : [];
    const route = seg.join('/');

    let body = {};
    if (method === 'POST') {
      try {
        body = await request.json();
      } catch {
        body = {};
      }
    }

    /* ---------- estado ---------- */
    let state = await loadState(context);
    if (!state || typeof state !== 'object' || !state.appSecret) {
      state = state && typeof state === 'object' ? state : {};
      state.appSecret = state.appSecret || crypto.randomBytes(32).toString('hex');
      if (!state.primary) state.primary = null;
      if (!Array.isArray(state.accounts)) state.accounts = [];
      if (!Array.isArray(state.revoked)) state.revoked = [];
      if (!state.attempts || typeof state.attempts !== 'object') state.attempts = {};
      await saveState(context, state);
    }
    const commit = () => saveState(context, state);

    const session = () => {
      const t = tokenFrom(request);
      const data = t ? parseSessionToken(state.appSecret, t) : null;
      if (!data) return null;
      if (state.revoked.some((r) => r.jti === data.jti)) return null;
      return data;
    };
    const requireAuth = () => (session() ? true : json({ error: 'Sesión no válida. Ingresa de nuevo.' }, 401));

    /* ---------- rutas públicas ---------- */

    if (method === 'GET' && route === 'state') {
      return json({
        setupDone: !!(state.primary && state.primary.confirmed),
        authed: !!session()
      });
    }

    if (method === 'POST' && route === 'setup') {
      if (state.primary && state.primary.confirmed) {
        return json({ error: 'Ya está configurado.' }, 400);
      }
      if (!state.primary) {
        state.primary = {
          secretEnc: encSecret(state.appSecret, base32Encode(crypto.randomBytes(20))),
          confirmed: false,
          createdAt: Date.now()
        };
        await commit();
      }
      const secret = decSecret(state.appSecret, state.primary.secretEnc);
      const otpauth = otpauthUrl(secret, ISSUER, LABEL);
      const qr = await QRCode.toDataURL(otpauth, { margin: 1, width: 320 });
      return json({ secret, otpauth, qr });
    }

    if (method === 'POST' && route === 'confirm-setup') {
      if (!state.primary) return json({ error: 'Primero genera el código principal.' }, 400);
      if (state.primary.confirmed) return json({ error: 'Ya está configurado.' }, 400);
      let ok = false;
      try {
        ok = verifyCode(decSecret(state.appSecret, state.primary.secretEnc), body.code);
      } catch {
        ok = false;
      }
      if (!ok) {
        return json({ error: 'Código incorrecto. Verifica tu Google Authenticator.' }, 400);
      }
      state.primary.confirmed = true;
      state.primary.confirmedAt = Date.now();
      await commit();
      return json({ ok: true });
    }

    if (method === 'POST' && route === 'login') {
      const ip = clientIp(request);
      for (const [k, v] of Object.entries(state.attempts)) {
        if (v && v.until && v.until < Date.now()) delete state.attempts[k];
      }
      const at = state.attempts[ip];
      if (at && at.until > Date.now()) {
        return json({ error: 'Demasiados intentos. Espera 5 minutos.' }, 429);
      }
      if (!state.primary || !state.primary.confirmed) {
        return json({ error: 'La app aún no está configurada.' }, 400);
      }
      let ok = false;
      try {
        ok = verifyCode(decSecret(state.appSecret, state.primary.secretEnc), body.code);
      } catch {
        ok = false;
      }
      if (!ok) {
        const a = state.attempts[ip] || { count: 0, until: 0 };
        a.count += 1;
        if (a.count >= 5) {
          a.count = 0;
          a.until = Date.now() + 5 * 60 * 1000;
        }
        state.attempts[ip] = a;
        await commit();
        return json({ error: 'Código incorrecto.' }, 401);
      }
      delete state.attempts[ip];
      await commit();
      const token = makeSessionToken(state.appSecret, TTL_MS);
      return json({ ok: true, token }, 200, { 'Set-Cookie': sessionCookie(token, request) });
    }

    if (method === 'POST' && route === 'logout') {
      const data = session();
      if (data) {
        state.revoked = state.revoked.filter((r) => r.exp > Date.now());
        state.revoked.push({ jti: data.jti, exp: data.exp });
        await commit();
      }
      return json({ ok: true }, 200, { 'Set-Cookie': clearCookie });
    }

    /* ---------- rutas autenticadas ---------- */

    if (route === 'primary' && method === 'GET') {
      const denied = requireAuth();
      if (denied !== true) return denied;
      const secret = decSecret(state.appSecret, state.primary.secretEnc);
      const otpauth = otpauthUrl(secret, ISSUER, LABEL);
      const qr = await QRCode.toDataURL(otpauth, { margin: 1, width: 320 });
      return json({ secret, otpauth, qr });
    }

    if (seg[0] === 'accounts') {
      if (method === 'GET' && seg.length === 1) {
        const denied = requireAuth();
        if (denied !== true) return denied;
        return json({
          accounts: state.accounts.map(({ id, name, issuer, createdAt }) => ({
            id,
            name,
            issuer,
            createdAt
          }))
        });
      }

      if (method === 'POST' && seg.length === 1) {
        const denied = requireAuth();
        if (denied !== true) return denied;
        try {
          let { name, issuer, secret } = body || {};
          const cleaned = sanitizeSecret(secret);

          // Exportación de Google Authenticator → importa todas las cuentas
          if (isMigrationText(cleaned)) {
            const list = parseMigrationAccounts(cleaned);
            let imported = 0;
            let skipped = 0;
            for (const a of list) {
              // Nuestro motor es TOTP/SHA1/6 dígitos; se omiten HOTP y variantes
              if (a.type === 1 || a.algorithm === 2 || a.algorithm === 3 || a.digits === 2) {
                skipped++;
                continue;
              }
              state.accounts.push({
                id: crypto.randomUUID(),
                name: String(a.name || 'Cuenta').trim().slice(0, 60) || 'Cuenta',
                issuer: String(a.issuer || '').trim().slice(0, 60),
                secretEnc: encSecret(state.appSecret, a.secretB32),
                createdAt: Date.now()
              });
              imported++;
            }
            if (imported === 0) {
              throw new Error(
                'El enlace no contiene cuentas TOTP compatibles (se omiten HOTP, SHA256/512 y 8 dígitos).'
              );
            }
            await commit();
            return json(
              {
                imported,
                skipped,
                accounts: state.accounts.map(({ id, name, issuer, createdAt }) => ({
                  id,
                  name,
                  issuer,
                  createdAt
                }))
              },
              201
            );
          }

          const parsed = extractFromPastedText(cleaned) || parseOtpauth(cleaned);
          if (parsed) {
            secret = parsed.secret;
            name = name || parsed.name;
            issuer = issuer || parsed.issuer;
          } else {
            secret = normalizeSecretInput(cleaned);
          }
          const keyBuf = base32Decode(secret); // valida
          secret = base32Encode(keyBuf); // normaliza
          name = String(name || '').trim().slice(0, 60) || 'Cuenta';
          issuer = String(issuer || '').trim().slice(0, 60);
          const acc = {
            id: crypto.randomUUID(),
            name,
            issuer,
            secretEnc: encSecret(state.appSecret, secret),
            createdAt: Date.now()
          };
          state.accounts.push(acc);
          await commit();
          return json(
            { id: acc.id, name: acc.name, issuer: acc.issuer, createdAt: acc.createdAt },
            201
          );
        } catch (e) {
          return json({ error: e.message }, 400);
        }
      }

      if (method === 'DELETE' && seg.length === 2 && seg[1]) {
        const denied = requireAuth();
        if (denied !== true) return denied;
        const before = state.accounts.length;
        state.accounts = state.accounts.filter((a) => a.id !== seg[1]);
        if (state.accounts.length === before) {
          return json({ error: 'Cuenta no encontrada.' }, 404);
        }
        await commit();
        return json({ ok: true });
      }
    }

    if (method === 'GET' && route === 'codes') {
      const denied = requireAuth();
      if (denied !== true) return denied;
      const now = Math.floor(Date.now() / 1000);
      const left = 30 - (now % 30);
      const codes = [];
      for (const a of state.accounts) {
        try {
          codes.push({ id: a.id, code: totp(base32Decode(decSecret(state.appSecret, a.secretEnc)), now) });
        } catch {
          /* cuenta corrupta: se omite */
        }
      }
      return json({ serverTime: Date.now(), left, period: 30, codes });
    }

    return json({ error: 'No encontrado.' }, 404);
  } catch (e) {
    console.error('Error en la API:', e);
    return json({ error: 'Error interno del servidor.' }, 500);
  }
}
