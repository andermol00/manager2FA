/*
 * Servidor local de desarrollo (sin necesidad de Netlify CLI).
 * Sirve public/ y enruta /api/* por el mismo router que usa Netlify.
 *
 *   npm start   →  http://localhost:3000
 */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleApi } from './shared/app.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT) || 3000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json'
};

const HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'host']);

function buildHeaders(req) {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP.has(key) || v == null) continue;
    if (Array.isArray(v)) for (const x of v) headers.append(key, x);
    else headers.set(key, v);
  }
  return headers;
}

createServer(async (req, res) => {
  try {
    const u = new URL(req.url || '/', `http://localhost:${PORT}`);

    /* ---------- API (igual que en Netlify: /api/* o /.netlify/functions/api/*) ---------- */
    if (
      u.pathname === '/api' ||
      u.pathname.startsWith('/api/') ||
      u.pathname.startsWith('/.netlify/functions/api')
    ) {
      const headers = buildHeaders(req);
      let body;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        body = Buffer.concat(chunks);
      }
      const request = new Request(u.toString(), {
        method: req.method,
        headers,
        body,
        redirect: 'manual'
      });
      const resp = await handleApi(request, { dev: true });
      const out = Object.fromEntries(resp.headers);
      const setCookies =
        typeof resp.headers.getSetCookie === 'function'
          ? resp.headers.getSetCookie()
          : resp.headers.get('set-cookie')
            ? [resp.headers.get('set-cookie')]
            : [];
      delete out['set-cookie'];
      res.writeHead(resp.status, setCookies.length ? { ...out, 'set-cookie': setCookies } : out);
      res.end(Buffer.from(await resp.arrayBuffer()));
      return;
    }

    /* ---------- estáticos ---------- */
    let p = decodeURIComponent(u.pathname);
    if (p === '/') p = '/index.html';
    const file = path.normalize(path.join(PUB, p));
    if (!file.startsWith(PUB + path.sep) && file !== PUB) {
      res.writeHead(403);
      res.end('403');
      return;
    }
    try {
      const data = await readFile(file);
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
      res.end(data);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404');
    }
  } catch (e) {
    console.error(e);
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('500');
  }
}).listen(PORT, '0.0.0.0', () => {
  console.log(`Authenticator 2FA → http://0.0.0.0:${PORT}`);
  console.log('Almacenamiento local: data/store.json (en Netlify usa Blobs)');
});
