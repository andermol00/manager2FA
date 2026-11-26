'use strict';
// Prueba end-to-end del flujo completo del Authenticator
const BASE = 'http://127.0.0.1:3000';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(str) {
  const s = String(str).replace(/[\s-]/g, '').replace(/=+$/g, '').toUpperCase();
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('bad b32: ' + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secret) {
  const key = b32decode(secret);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = require('crypto').createHmac('sha1', key).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

async function main() {
  const log = (step, ok, extra = '') =>
    console.log(`${ok ? '✅' : '❌'} ${step}${extra ? ' — ' + extra : ''}`);

  // 1. Estado inicial
  let r = await fetch(BASE + '/api/state');
  let st = await r.json();
  log('GET /api/state (setupDone=false)', r.ok && st.setupDone === false, JSON.stringify(st));

  // 2. Setup: genera secreto principal + QR
  r = await fetch(BASE + '/api/setup', { method: 'POST' });
  const setup = await r.json();
  log('POST /api/setup genera secreto+QR',
    r.ok && /^[A-Z2-7]{32}$/.test(setup.secret) && setup.qr.startsWith('data:image/png'),
    `secret=${setup.secret.slice(0, 8)}… qr=${setup.qr.slice(0, 30)}…`);
  if (!setup.secret) return process.exit(1);

  // 3. Código incorrecto rechazado
  r = await fetch(BASE + '/api/confirm-setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: '000000' })
  });
  const bad = await r.json();
  const codeReal = totp(setup.secret);
  log('confirm-setup rechaza código incorrecto', r.status === 400, bad.error || '');

  // 4. Código correcto confirma
  r = await fetch(BASE + '/api/confirm-setup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: codeReal })
  });
  log('confirm-setup acepta código TOTP real', r.ok, JSON.stringify(await r.json()));

  // 5. Login
  r = await fetch(BASE + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: totp(setup.secret) })
  });
  const login = await r.json();
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  log('POST /api/login con Google Authenticator', r.ok && !!login.token, `token=${String(login.token).slice(0, 20)}… cookie=${cookie.slice(0, 30)}…`);
  if (!login.token) return process.exit(1);
  const auth = { Authorization: 'Bearer ' + login.token, 'Content-Type': 'application/json' };

  // 6. Sin auth → 401
  r = await fetch(BASE + '/api/accounts');
  log('GET /api/accounts sin sesión → 401', r.status === 401);

  // 7. Agregar cuenta con clave secreta manual
  const testSecret = 'JBSWY3DPEHPK3PXP'; // base32 de "Hello!\xde\xad\xbe\xef"
  r = await fetch(BASE + '/api/accounts', {
    method: 'POST', headers: auth,
    body: JSON.stringify({ name: 'GitHub personal', issuer: 'GitHub', secret: testSecret })
  });
  const acc = await r.json();
  log('POST /api/accounts (clave manual)', r.status === 201, JSON.stringify(acc));

  // 8. Agregar cuenta pegando enlace otpauth://
  r = await fetch(BASE + '/api/accounts', {
    method: 'POST', headers: auth,
    body: JSON.stringify({ secret: `otpauth://totp/Netflix:cuenta?secret=${testSecret}&issuer=Netflix` })
  });
  const acc2 = await r.json();
  log('POST /api/accounts (enlace otpauth://)', r.status === 201 && acc2.issuer === 'Netflix', JSON.stringify(acc2));

  // 9. Clave inválida rechazada
  r = await fetch(BASE + '/api/accounts', {
    method: 'POST', headers: auth,
    body: JSON.stringify({ name: 'malo', secret: '¡esto no es base32!' })
  });
  log('POST /api/accounts rechaza clave inválida', r.status === 400, (await r.json()).error || '');

  // 10. Lista de cuentas (sin exponer secretos)
  r = await fetch(BASE + '/api/accounts', { headers: auth });
  const list = await r.json();
  const expone = JSON.stringify(list).includes(testSecret);
  log('GET /api/accounts lista 2 cuentas sin secretos', r.ok && list.accounts.length === 2 && !expone,
    JSON.stringify(list.accounts.map(a => `${a.issuer||''}/${a.name}`)));

  // 11. Códigos TOTP en vivo
  r = await fetch(BASE + '/api/codes', { headers: auth });
  const codes = await r.json();
  const esperado = totp(testSecret);
  const okCodes = r.ok && codes.codes.length === 2 &&
    codes.codes.every(c => /^\d{6}$/.test(c.code)) &&
    codes.codes[0].code === esperado && codes.left >= 1 && codes.left <= 30;
  log('GET /api/codes genera TOTP válidos', okCodes,
    `codes=${codes.codes.map(c => c.code).join(',')} esperado=${esperado} left=${codes.left}`);

  // 12. QR principal (re-escaneo)
  r = await fetch(BASE + '/api/primary', { headers: auth });
  const prim = await r.json();
  log('GET /api/primary re-muestra QR', r.ok && prim.secret === setup.secret && prim.qr.startsWith('data:image/png'));

  // 13. Cookie también autentica (producción)
  r = await fetch(BASE + '/api/accounts', { headers: { Cookie: cookie } });
  log('GET /api/accounts vía cookie (producción)', r.ok);

  // 14. Token inválido rechazado
  r = await fetch(BASE + '/api/accounts', { headers: { Authorization: 'Bearer ' + login.token + 'x' } });
  log('Token manipulado → 401', r.status === 401);

  // 15. Eliminar cuenta (antes del logout)
  r = await fetch(BASE + '/api/accounts/' + acc.id, { method: 'DELETE', headers: auth });
  const del = await r.json();
  log('DELETE /api/accounts/:id', r.ok && del.ok, JSON.stringify(del));

  // 16. Logout revoca la sesión
  r = await fetch(BASE + '/api/logout', { method: 'POST', headers: { Cookie: cookie } });
  const cleared = (r.headers.get('set-cookie') || '').includes('Max-Age=0');
  r = await fetch(BASE + '/api/accounts', { headers: { Cookie: cookie } });
  log('Logout revoca la sesión (cookie inválida)', r.status === 401 && cleared);
  r = await fetch(BASE + '/api/accounts', { headers: auth });
  log('Token revocado por logout → 401', r.status === 401);
}

main().catch((e) => { console.error('❌ ERROR:', e); process.exit(1); });
