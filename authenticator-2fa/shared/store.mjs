/*
 * Almacenamiento del estado.
 * - En Netlify (producción): Netlify Blobs, consistencia fuerte, cero configuración.
 * - En local (npm start / pruebas): archivo data/store.json.
 */

import { getStore } from '@netlify/blobs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const KEY = 'state';
const STORE_NAME = 'authenticator-2fa';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILE = process.env.DATA_PATH || path.join(HERE, '..', 'data', 'store.json');

let kvPromise = null;

function fileKV() {
  return {
    async get() {
      try {
        return await readFile(FILE, 'utf8');
      } catch {
        return null;
      }
    },
    async set(_key, value) {
      await mkdir(path.dirname(FILE), { recursive: true });
      const tmp = FILE + '.tmp';
      await writeFile(tmp, value);
      await rename(tmp, FILE);
    }
  };
}

async function openKV(context) {
  // El servidor local de desarrollo (dev-server.mjs) marca context.dev = true
  if (context && context.dev) return fileKV();

  try {
    const store = getStore({ name: STORE_NAME, consistency: 'strong' });
    await store.get('__probe__'); // valida que las credenciales de Blobs existan
    return {
      get: (k) => store.get(k),
      set: (k, v) => store.set(k, v)
    };
  } catch (e) {
    // En Netlify real: falla ruidosamente (nunca datos efímeros en disco).
    if (process.env.NETLIFY === 'true' || process.env.NETLIFY_SITE_ID) throw e;
    console.warn('⚠️  Netlify Blobs no disponible, usando archivo local:', e.message);
    return fileKV();
  }
}

function kv(context) {
  if (!kvPromise) kvPromise = openKV(context);
  return kvPromise;
}

export async function loadState(context) {
  const k = await kv(context);
  const raw = await k.get(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function saveState(context, state) {
  const k = await kv(context);
  await k.set(KEY, JSON.stringify(state));
}
