/*
 * Exportación/migración de Google Authenticator:
 *   otpauth-migration://offline?data=<base64 protobuf>
 *
 * Formato (reverse-engineered, ampliamente documentado):
 *   MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
 *   OtpParameters {
 *     bytes secret = 1;  string name = 2;  string issuer = 3;
 *     Algorithm algorithm = 4;  DigitCount digits = 5;  OtpType type = 6;
 *   }
 *   Algorithm: 1=SHA1, 2=SHA256, 3=SHA512
 *   DigitCount: 1=6, 2=8
 *   OtpType: 1=HOTP, 2=TOTP
 */

import { base32Encode } from './totp.mjs';

export function isMigrationText(text) {
  return /otpauth-migration:\/\//i.test(String(text ?? ''));
}

/** Devuelve [{ secretB32, name, issuer, algorithm, digits, type }, ...] */
export function parseMigrationAccounts(input) {
  // Los enlaces suelen pegarse partidos por saltos de línea o espacios
  const flat = String(input ?? '').replace(/&amp;/gi, '&').replace(/\s+/g, '');
  const m = flat.match(/otpauth-migration:\/\/[^\s"'<>]+/i);
  if (!m) throw new Error('No se encontró el enlace otpauth-migration://.');
  const link = m[0].replace(/[).,;]+$/, '');

  let u;
  try {
    u = new URL(link);
  } catch {
    throw new Error('Enlace de migración inválido.');
  }
  let data = u.searchParams.get('data');
  if (!data) throw new Error('El enlace de migración no contiene el parámetro "data".');

  // base64 estándar o base64url; "+" en query llega convertido en espacio
  data = data.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  while (data.length % 4 !== 0) data += '=';

  const buf = Buffer.from(data, 'base64');
  if (buf.length < 2) throw new Error('No se pudo decodificar la data de migración.');
  return decodePayload(buf);
}

/* ---------------- protobuf mínimo (suficiente para este formato) ---------------- */

function* protoFields(buf) {
  let i = 0;
  const readVarint = () => {
    let v = 0n;
    let shift = 0n;
    while (true) {
      if (i >= buf.length) throw new Error('Protobuf corrupto.');
      const b = buf[i++];
      v |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return v;
      shift += 7n;
      if (shift > 70n) throw new Error('Protobuf corrupto.');
    }
  };

  while (i < buf.length) {
    const key = readVarint();
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (wire === 0) {
      yield { field, wire, varint: readVarint() };
    } else if (wire === 2) {
      const len = Number(readVarint());
      if (i + len > buf.length) throw new Error('Protobuf corrupto.');
      yield { field, wire, bytes: buf.subarray(i, i + len) };
      i += len;
    } else if (wire === 5) {
      i += 4;
      yield { field, wire };
    } else if (wire === 1) {
      i += 8;
      yield { field, wire };
    } else {
      throw new Error('Protobuf corrupto (wire type ' + wire + ').');
    }
  }
}

function parseOtpParameters(buf) {
  let secret = null;
  let name = '';
  let issuer = '';
  let algorithm = 0;
  let digits = 0;
  let type = 0;
  for (const f of protoFields(buf)) {
    if (f.field === 1 && f.wire === 2) secret = f.bytes;
    else if (f.field === 2 && f.wire === 2) name = f.bytes.toString('utf8');
    else if (f.field === 3 && f.wire === 2) issuer = f.bytes.toString('utf8');
    else if (f.field === 4 && f.wire === 0) algorithm = Number(f.varint);
    else if (f.field === 5 && f.wire === 0) digits = Number(f.varint);
    else if (f.field === 6 && f.wire === 0) type = Number(f.varint);
  }
  if (!secret || secret.length < 10) return null;
  return {
    secretB32: base32Encode(secret),
    name: name || issuer || 'Cuenta',
    issuer,
    algorithm,
    digits,
    type
  };
}

function decodePayload(buf) {
  const accounts = [];
  for (const f of protoFields(buf)) {
    if (f.field === 1 && f.wire === 2) {
      const acc = parseOtpParameters(f.bytes);
      if (acc) accounts.push(acc);
    }
  }
  if (!accounts.length) throw new Error('No se encontraron cuentas en el enlace de migración.');
  return accounts;
}
