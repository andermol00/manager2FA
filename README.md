# 🔐 Authenticator 2FA — Netlify

Sistema **Authenticator 2FA** para guardar tus **códigos secundarios**, con acceso
protegido mediante un **código principal** que vives en **Google Authenticator**.

```
Google Authenticator (código principal · cuenta "Acceso")
        │
        ▼  ingresas el código de 6 dígitos
┌──────────────────────────────────────────┐
│  Authenticator 2FA                       │
│  ├── GitHub      → 483 920              │
│  ├── Netflix     → 105 774              │
│  └── …tus códigos secundarios           │
└──────────────────────────────────────────┘
```

## Cómo funciona

1. **Primera vez**: la app genera un QR principal (etiqueta `Authenticator 2FA · Acceso`)
   que escaneas con Google Authenticator y confirmas con su código.
2. **Entrar**: cada visita pide el código de 6 dígitos de esa cuenta principal.
3. **Códigos secundarios**: TOTP estándar (RFC 6238, 6 dígitos, 30 s) con barra de
   tiempo; se calculan **en el servidor** y solo se piden al cambiar de periodo
   (minimiza peticiones y el consumo de créditos de Netlify).

## Arquitectura en Netlify

| Pieza | Dónde | Rol |
|---|---|---|
| `public/` | CDN (estático) | Interfaz: setup · login · app · escáner QR |
| `netlify/functions/api.mjs` | Function v2 | Toda la API `/api/*` |
| `shared/` | empaquetado por esbuild | TOTP, cifrado, sesiones, router |
| **Netlify Blobs** | almacenamiento | Estado cifrado (cero configuración, consistencia fuerte) |
| `netlify.toml` | config | `publish: public` + rewrite `/api/* → función` |

- Sin variables de entorno requeridas: Blobs se auto-provisiona en tu sitio.
- Los secretos se guardan cifrados (AES-256-GCM) y **nunca** viajan al navegador
  solo para mostrar códigos.
- Sesiones firmadas (HMAC) de **30 días** con revocación real al cerrar sesión,
  cookie `HttpOnly` + token Bearer (así no te vuelve a pedir el código al
  recargar), y rate-limit de login (5 fallos → 5 min).

## 🚀 Despliegue en Netlify

### Opción A — desde GitHub (recomendada)

1. Sube esta carpeta a un repositorio de GitHub.
2. En [app.netlify.com](https://app.netlify.com): **Add new site → Import an existing project**.
3. Selecciona el repositorio. Netlify detecta `netlify.toml` solo
   (publica `public/` y empaqueta la función con esbuild).
4. **Deploy**. Abre la URL → escanea el QR principal → entra.

### Opción B — arrastrar y soltar

1. **Add new site → Deploy manually**.
2. Arrastra la carpeta del proyecto (con `netlify.toml` y `package.json`).

> Después del primer deploy, visita la URL: verás la pantalla de configuración
> del QR principal. Los datos quedan guardados en **Netlify Blobs** y sobreviven
> a futuros deploys.

## Uso local (sin Netlify)

```bash
npm install
npm start        # http://localhost:3000  (datos en data/store.json)
npm test         # 17 pruebas end-to-end (con el servidor corriendo)
```

> `npx netlify dev` también funciona (simula el entorno real de Netlify y sus
> Blobs); si no tienes sesión de Netlify CLI, usa `npm start`.

## API

| Método | Ruta                    | Auth | Descripción                           |
|--------|-------------------------|------|---------------------------------------|
| GET    | `/api/state`            | –    | ¿configurado? ¿sesión válida?        |
| POST   | `/api/setup`            | –    | Genera/obtiene el QR principal        |
| POST   | `/api/confirm-setup`    | –    | Confirma el escaneo con un código     |
| POST   | `/api/login`            | –    | Entrada con código principal          |
| POST   | `/api/logout`           | –    | Revoca la sesión                      |
| GET    | `/api/primary`          | ✓    | QR + secreto principal (re-escaneo)   |
| GET    | `/api/accounts`         | ✓    | Lista de cuentas (sin secretos)       |
| POST   | `/api/accounts`         | ✓    | Agrega cuenta (clave, `otpauth://` o exportación `otpauth-migration://` de Google Authenticator) |
| DELETE | `/api/accounts/:id`     | ✓    | Elimina cuenta                        |
| GET    | `/api/codes`            | ✓    | Códigos TOTP + `serverTime` en vivo   |

## Créditos de Netlify

El plan Free incluye **300 créditos/mes**. Esta app está optimizada para gastar
poco: los códigos se solicitan ~1 vez por periodo de 30 s (no cada segundo) y la
interfaz pinta la cuenta regresiva con el reloj del servidor. Un uso personal
diario queda muy por debajo del límite.

## Estructura

```
authenticator-2fa/
├── netlify.toml               # publish + rewrite de la API
├── netlify/functions/api.mjs  # Function v2 (entrada única de la API)
├── shared/
│   ├── app.mjs                # router + sesiones + rate-limit
│   ├── totp.mjs               # Base32 + TOTP (RFC 6238)
│   ├── security.mjs           # AES-256-GCM + firmas HMAC
│   └── store.mjs              # Netlify Blobs (prod) / archivo (local)
├── public/                    # interfaz (HTML/CSS/JS + jsQR vendorizado)
├── dev-server.mjs             # servidor local de desarrollo
├── test-e2e.js                # 17 pruebas del flujo completo
└── README.md
```
