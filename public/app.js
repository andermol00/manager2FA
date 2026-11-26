'use strict';

const $ = (id) => document.getElementById(id);

let token = null; // token de sesión en memoria (el sandbox no permite storage)
let accounts = [];
let codeState = { serverTime: 0, clientAt: 0, codes: [] };
let tickTimer = null;
let lastLeft = 30;
let scanStream = null;
let scanRaf = null;

/* ---------------- utilidades ---------------- */

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  let data = {};
  try { data = await res.json(); } catch { /* vacío */ }
  if (!res.ok) {
    const err = new Error(data.error || 'Error de conexión');
    err.status = res.status;
    throw err;
  }
  return data;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

let toastTimer = null;
function toast(msg, kind = 'ok') {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2600);
}

function show(screenId) {
  for (const id of ['screen-setup', 'screen-login', 'screen-app']) {
    $(id).classList.toggle('hidden', id !== screenId);
  }
}

function onlyDigits(v) {
  return String(v || '').replace(/\D/g, '').slice(0, 6);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copiado al portapapeles');
    return;
  } catch { /* fallback */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast('Copiado al portapapeles');
  } catch {
    toast('No se pudo copiar: selecciona y copia manualmente', 'err');
  }
}

function saveToken(t) {
  token = t;
  try { localStorage.setItem('auth2fa_token', t); } catch { /* sandbox */ }
}

function clearToken() {
  token = null;
  try { localStorage.removeItem('auth2fa_token'); } catch { /* sandbox */ }
}

function loadToken() {
  try { return localStorage.getItem('auth2fa_token'); } catch { return null; }
}

/* ---------------- SETUP ---------------- */

async function showSetup() {
  show('screen-setup');
  try {
    const d = await api('/api/setup', { method: 'POST' });
    $('setup-qr').src = d.qr;
    $('setup-secret').textContent = d.secret;
  } catch (e) {
    $('setup-error').textContent = e.message;
    $('setup-error').classList.remove('hidden');
  }
}

async function confirmSetup() {
  const code = onlyDigits($('setup-code').value);
  const errEl = $('setup-error');
  errEl.classList.add('hidden');
  if (code.length !== 6) {
    errEl.textContent = 'Ingresa los 6 dígitos.';
    errEl.classList.remove('hidden');
    return;
  }
  try {
    await api('/api/confirm-setup', { method: 'POST', body: { code } });
    toast('¡Acceso activado! Ya puedes entrar.');
    $('setup-code').value = '';
    showLogin();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
    $('setup-code').value = '';
    $('setup-code').focus();
  }
}

/* ---------------- LOGIN ---------------- */

function showLogin() {
  stopTicker();
  show('screen-login');
  $('login-code').value = '';
  setTimeout(() => $('login-code').focus(), 50);
}

async function doLogin() {
  const code = onlyDigits($('login-code').value);
  const errEl = $('login-error');
  errEl.classList.add('hidden');
  if (code.length !== 6) {
    errEl.textContent = 'Ingresa los 6 dígitos.';
    errEl.classList.remove('hidden');
    return;
  }
  try {
    const d = await api('/api/login', { method: 'POST', body: { code } });
    saveToken(d.token);
    $('login-code').value = '';
    toast('¡Bienvenido!');
    enterApp();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
    $('login-code').value = '';
    $('login-code').focus();
  }
}

/* ---------------- APP ---------------- */

async function enterApp() {
  show('screen-app');
  await refreshAccounts();
  await fetchCodes();
  startTicker();
}

async function refreshAccounts() {
  try {
    const d = await api('/api/accounts');
    accounts = d.accounts || [];
    renderAccounts();
  } catch (e) {
    if (e.status === 401) sessionExpired();
    else toast(e.message, 'err');
  }
}

function sessionExpired() {
  stopTicker();
  clearToken();
  showLogin();
  $('login-error').textContent = 'Tu sesión expiró. Ingresa de nuevo.';
  $('login-error').classList.remove('hidden');
}

function renderAccounts() {
  const wrap = $('accounts');
  wrap.innerHTML = '';
  $('empty').classList.toggle('hidden', accounts.length > 0);

  for (const a of accounts) {
    const card = document.createElement('div');
    card.className = 'acc-card';
    card.dataset.id = a.id;
    const title = a.issuer || a.name;
    const sub = a.issuer && a.issuer !== a.name ? a.name : '';
    card.innerHTML = `
      <div class="acc-info">
        <div class="acc-name">${esc(title)}</div>
        <div class="acc-sub">${esc(sub)}</div>
      </div>
      <button class="acc-code" type="button" title="Toca para copiar">••• •••</button>
      <button class="acc-del" type="button" title="Eliminar">🗑</button>
      <div class="acc-bar"><i style="width:100%"></i></div>`;

    card.querySelector('.acc-code').addEventListener('click', (ev) => {
      const code = ev.currentTarget.dataset.code;
      if (code) copyText(code.replace(/\s/g, ''));
    });
    card.querySelector('.acc-del').addEventListener('click', async () => {
      if (!confirm(`¿Eliminar "${title}" de tus códigos secundarios?`)) return;
      try {
        await api('/api/accounts/' + a.id, { method: 'DELETE' });
        toast('Cuenta eliminada');
        await refreshAccounts();
        await fetchCodes();
      } catch (e) {
        toast(e.message, 'err');
      }
    });
    wrap.appendChild(card);
  }
}

/* ---------------- códigos en vivo (poco consumo de API) ----------------
   El servidor calcula los TOTP; el cliente solo los pide al cambiar de
   periodo (cada 30 s) y pinta la cuenta regresiva con el reloj del
   servidor, minimizando peticiones (créditos de Netlify).            */

function serverNowMs() {
  if (!codeState.serverTime) return Date.now();
  return codeState.serverTime + (Date.now() - codeState.clientAt);
}

function leftNow() {
  return 30 - ((serverNowMs() / 1000) % 30);
}

async function fetchCodes() {
  try {
    const d = await api('/api/codes');
    codeState = {
      serverTime: d.serverTime || Date.now(),
      clientAt: Date.now(),
      codes: d.codes || []
    };
    lastLeft = leftNow();
    paintCodes();
  } catch (e) {
    if (e.status === 401) sessionExpired();
  }
}

function paintCodes() {
  const map = new Map(codeState.codes.map((c) => [c.id, c.code]));
  document.querySelectorAll('.acc-card').forEach((card) => {
    const code = map.get(card.dataset.id);
    const btn = card.querySelector('.acc-code');
    if (code) {
      const pretty = code.slice(0, 3) + ' ' + code.slice(3);
      btn.textContent = pretty;
      btn.dataset.code = pretty;
    }
  });
  paintTick();
}

function paintTick() {
  const left = leftNow();
  document.querySelectorAll('.acc-card').forEach((card) => {
    card.querySelector('.acc-bar i').style.width = ((left / 30) * 100).toFixed(1) + '%';
    card.classList.toggle('urgent', left <= 5);
  });
}

function startTicker() {
  stopTicker();
  tickTimer = setInterval(() => {
    const left = leftNow();
    if (left > lastLeft + 10) {
      fetchCodes(); // giró el periodo de 30 s → pedir códigos nuevos
    } else {
      paintTick();
    }
    lastLeft = left;
  }, 250);
}

function stopTicker() {
  clearInterval(tickTimer);
  tickTimer = null;
}

/* ---------------- agregar / eliminar ---------------- */

function openAdd() {
  $('panel-add').classList.remove('hidden');
  $('panel-primary').classList.add('hidden');
  $('add-error').classList.add('hidden');
  $('acc-name').focus();
}

function closeAdd() {
  $('panel-add').classList.add('hidden');
  $('acc-name').value = '';
  $('acc-issuer').value = '';
  $('acc-secret').value = '';
  $('add-error').classList.add('hidden');
}

async function saveAccount() {
  const errEl = $('add-error');
  errEl.classList.add('hidden');
  const body = {
    name: $('acc-name').value.trim(),
    issuer: $('acc-issuer').value.trim(),
    secret: $('acc-secret').value.trim()
  };
  if (!body.secret) {
    errEl.textContent = 'Pega la clave secreta o escanea el QR.';
    errEl.classList.remove('hidden');
    return;
  }
  try {
    const d = await api('/api/accounts', { method: 'POST', body });
    if (d && d.imported > 1) {
      toast(`${d.imported} cuentas importadas${d.skipped ? ` · ${d.skipped} omitidas` : ''}`);
    } else {
      toast('Cuenta agregada');
    }
    closeAdd();
    await refreshAccounts();
    await fetchCodes();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.remove('hidden');
  }
}

/* ---------------- QR principal ---------------- */

async function showPrimary() {
  const panel = $('panel-primary');
  const isOpen = !panel.classList.contains('hidden');
  if (isOpen) {
    panel.classList.add('hidden');
    return;
  }
  closeAdd();
  try {
    const d = await api('/api/primary');
    $('primary-qr').src = d.qr;
    $('primary-secret').textContent = d.secret;
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (e) {
    toast(e.message, 'err');
  }
}

/* ---------------- escáner de QR con cámara ---------------- */

function openScan() {
  const modal = $('modal-scan');
  const status = $('scan-status');
  modal.classList.remove('hidden');
  status.textContent = 'Apunta al código QR…';

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    status.textContent = 'Cámara no disponible aquí. Pega la clave manualmente.';
    return;
  }

  navigator.mediaDevices
    .getUserMedia({ video: { facingMode: 'environment' } })
    .then((stream) => {
      scanStream = stream;
      const video = $('scan-video');
      video.srcObject = stream;
      video.play().catch(() => {});
      tickScan();
    })
    .catch(() => {
      status.textContent = 'No se pudo abrir la cámara. Pega la clave manualmente.';
    });
}

function tickScan() {
  const video = $('scan-video');
  const status = $('scan-status');
  if (!scanStream) return;

  if (video.readyState === video.HAVE_ENOUGH_DATA && typeof jsQR !== 'undefined') {
    const canvas = document.createElement('canvas');
    const w = video.videoWidth;
    const h = video.videoHeight;
    if (w && h) {
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(video, 0, 0, w, h);
      const img = ctx.getImageData(0, 0, w, h);
      const found = jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
      if (found && found.data) {
        status.textContent = '¡QR detectado!';
        applyScan(found.data);
        return;
      }
    }
  }
  scanRaf = requestAnimationFrame(tickScan);
}

function applyScan(data) {
  const raw = String(data).trim();
  let secret = raw;
  let name = '';
  let issuer = '';

  if (/^otpauth:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      secret = u.searchParams.get('secret') || '';
      issuer = u.searchParams.get('issuer') || '';
      const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
      const i = label.indexOf(':');
      name = i > 0 ? label.slice(i + 1) : label;
      if (!issuer && i > 0) issuer = label.slice(0, i);
    } catch {
      /* se queda con el texto crudo */
    }
  }

  if (!secret) {
    toast('QR sin clave secreta', 'err');
    return;
  }

  $('acc-secret').value = secret;
  if (name && !$('acc-name').value) $('acc-name').value = name;
  if (issuer && !$('acc-issuer').value) $('acc-issuer').value = issuer;
  closeScan();
  toast('QR escaneado. Revisa y guarda.');
}

function closeScan() {
  if (scanRaf) cancelAnimationFrame(scanRaf);
  scanRaf = null;
  if (scanStream) {
    scanStream.getTracks().forEach((t) => t.stop());
    scanStream = null;
  }
  $('scan-video').srcObject = null;
  $('modal-scan').classList.add('hidden');
}

/* ---------------- arranque ---------------- */

function bindEvents() {
  $('btn-copy-secret').addEventListener('click', () => copyText($('setup-secret').textContent));
  $('btn-copy-primary').addEventListener('click', () => copyText($('primary-secret').textContent));
  $('btn-confirm-setup').addEventListener('click', confirmSetup);
  $('btn-login').addEventListener('click', doLogin);

  for (const id of ['setup-code', 'login-code']) {
    $(id).addEventListener('input', (e) => {
      e.target.value = onlyDigits(e.target.value);
      if (e.target.value.length === 6) {
        if (id === 'setup-code') confirmSetup();
        else doLogin();
      }
    });
    $(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        if (id === 'setup-code') confirmSetup();
        else doLogin();
      }
    });
  }

  $('btn-show-add').addEventListener('click', openAdd);
  $('btn-empty-add').addEventListener('click', openAdd);
  $('btn-cancel-add').addEventListener('click', closeAdd);
  $('btn-save-acc').addEventListener('click', saveAccount);
  $('btn-scan').addEventListener('click', openScan);
  $('btn-cancel-scan').addEventListener('click', closeScan);

  $('btn-show-primary').addEventListener('click', showPrimary);
  $('btn-close-primary').addEventListener('click', () => $('panel-primary').classList.add('hidden'));

  $('btn-logout').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch { /* ok */ }
    clearToken();
    toast('Sesión cerrada');
    showLogin();
  });

  $('modal-scan').addEventListener('click', (e) => {
    if (e.target === $('modal-scan')) closeScan();
  });

  // Al volver a la pestaña: refresca códigos por si cambió el periodo
  document.addEventListener('visibilitychange', () => {
    if (
      document.visibilityState === 'visible' &&
      !$('screen-app').classList.contains('hidden')
    ) {
      fetchCodes();
    }
  });
}

async function init() {
  bindEvents();
  token = loadToken();
  try {
    const st = await api('/api/state');
    if (!st.setupDone) {
      showSetup();
    } else if (st.authed || token) {
      enterApp();
    } else {
      showLogin();
    }
  } catch {
    showLogin();
    $('login-error').textContent = 'No se pudo conectar con el servidor.';
    $('login-error').classList.remove('hidden');
  }
}

init();
