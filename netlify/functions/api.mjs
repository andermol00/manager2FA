/* Netlify Function v2 — enruta todas las rutas /api/* */

import { handleApi } from '../../shared/app.mjs';

export default async (req, context) => handleApi(req, context || {});
