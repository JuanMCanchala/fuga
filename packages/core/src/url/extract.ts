/**
 * Extracción de configuración y secretos desde el bundle de una app desplegada.
 *
 * El "escaneo por URL" es la vía de baja fricción: un vibe coder no siempre sabe
 * dónde están sus reglas, pero SÍ tiene una URL. Igual que un atacante, bajamos
 * el HTML + los bundles de JavaScript y sacamos de ahí la config de Firebase o
 * Supabase (que viaja en el frontend, en claro) para luego probar el backend en
 * vivo. Este módulo es PURO: sólo trabaja sobre strings, sin red, para poder
 * testearlo de forma determinista.
 *
 * OJO: el escaneo por URL es best-effort (depende de qué exponga el bundle).
 * El análisis COMPLETO —incluida la fuga entre usuarios— se hace pegando las
 * reglas de Firestore / Realtime Database / Supabase.
 */

import { Severity } from '../scan/types';

export interface FirebaseConfig {
  apiKey?: string;
  authDomain?: string;
  projectId?: string;
  databaseURL?: string;
  storageBucket?: string;
  appId?: string;
}

export interface SupabaseConfig {
  url: string; // https://<ref>.supabase.co
  ref: string;
  anonKey?: string; // JWT anon o clave publishable (sb_publishable_...)
}

export interface ExtractedConfigs {
  firebase?: FirebaseConfig;
  supabase?: SupabaseConfig;
  /** Nombres de colecciones/tablas inferidos del código cliente del bundle. */
  collections: string[];
}

export interface DetectedSecret {
  kind: string;
  label: string;
  severity: Severity;
  /** Muestra enmascarada — nunca devolvemos el secreto completo. */
  sample: string;
  why: string;
}

/** Enmascara un secreto: primeros 6 + últimos 4, el resto oculto. */
export function mask(secret: string): string {
  if (!secret) return '';
  if (secret.length <= 12) return secret.slice(0, 3) + '…' + secret.slice(-2);
  return secret.slice(0, 6) + '…' + secret.slice(-4);
}

/** Decodifica el payload de un JWT sin verificar la firma. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? b64 + '='.repeat(4 - (b64.length % 4)) : b64;
    const json =
      typeof Buffer !== 'undefined'
        ? Buffer.from(pad, 'base64').toString('utf8')
        : atob(pad);
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? obj : null;
  } catch {
    return null;
  }
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

function firstField(text: string, key: string): string | undefined {
  const re = new RegExp('["\'`]?' + key + '["\'`]?\\s*[:=]\\s*["\'`]([^"\'`]+)["\'`]');
  const m = re.exec(text);
  return m ? m[1] : undefined;
}

function deriveProjectId(cfg: FirebaseConfig): string | undefined {
  if (cfg.projectId) return cfg.projectId;
  if (cfg.authDomain) {
    const m = /^([a-z0-9-]+)\.firebaseapp\.com$/i.exec(cfg.authDomain);
    if (m) return m[1];
  }
  if (cfg.storageBucket) {
    const m = /^([a-z0-9-]+)\.(appspot\.com|firebasestorage\.app)$/i.exec(cfg.storageBucket);
    if (m) return m[1];
  }
  if (cfg.databaseURL) {
    const m = /^https?:\/\/([a-z0-9-]+?)(-default-rtdb)?\./i.exec(cfg.databaseURL);
    if (m) return m[1];
  }
  return undefined;
}

export function extractFirebaseConfig(text: string): FirebaseConfig | undefined {
  const apiKey = firstField(text, 'apiKey');
  const authDomain = firstField(text, 'authDomain');
  const projectId = firstField(text, 'projectId');
  const databaseURL = firstField(text, 'databaseURL');
  const storageBucket = firstField(text, 'storageBucket');
  const appId = firstField(text, 'appId');

  const looksFirebase =
    (apiKey && /^AIza[0-9A-Za-z_-]{10,}$/.test(apiKey)) ||
    !!authDomain ||
    !!databaseURL ||
    (!!storageBucket && /(appspot\.com|firebasestorage\.app)/.test(storageBucket)) ||
    !!projectId;
  if (!looksFirebase) return undefined;

  const cfg: FirebaseConfig = { apiKey, authDomain, projectId, databaseURL, storageBucket, appId };
  cfg.projectId = deriveProjectId(cfg);
  (Object.keys(cfg) as (keyof FirebaseConfig)[]).forEach((k) => cfg[k] === undefined && delete cfg[k]);
  return Object.keys(cfg).length ? cfg : undefined;
}

export function extractSupabaseConfig(text: string): SupabaseConfig | undefined {
  const urlM = /https?:\/\/([a-z0-9]{20})\.supabase\.co/i.exec(text);
  if (!urlM) return undefined;
  const ref = urlM[1].toLowerCase();
  const url = `https://${ref}.supabase.co`;

  let anonKey: string | undefined;
  const jwts = text.match(JWT_RE) || [];
  for (const jwt of jwts) {
    const payload = decodeJwtPayload(jwt);
    if (payload && payload.role === 'anon') {
      anonKey = jwt;
      break;
    }
  }
  if (!anonKey) {
    const pub = /sb_publishable_[A-Za-z0-9_-]{10,}/.exec(text);
    if (pub) anonKey = pub[0];
  }
  return { url, ref, anonKey };
}

const COLLECTION_RES: RegExp[] = [
  /\bcollection\s*\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?["'`]([A-Za-z0-9_-]{2,})["'`]/g,
  /\bcollectionGroup\s*\(\s*["'`]([A-Za-z0-9_-]{2,})["'`]/g,
  /\bdoc\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*["'`]([A-Za-z0-9_-]{2,})\//g,
  /\.from\s*\(\s*["'`]([A-Za-z0-9_-]{2,})["'`]/g,
  /\bref\s*\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?["'`]\/?([A-Za-z0-9_-]{2,})/g,
  /\bchild\s*\(\s*["'`]([A-Za-z0-9_-]{2,})/g,
];

const CODE_NOISE = new Set([
  'default', 'databases', 'documents', 'v1', 'rest', 'auth', 'storage', 'functions',
  'public', 'https', 'http', 'com', 'www', 'app', 'index', 'main', 'node_modules',
]);

export function extractCollections(text: string): string[] {
  const set = new Set<string>();
  for (const re of COLLECTION_RES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && set.size < 60) {
      const name = m[1];
      if (name && !CODE_NOISE.has(name.toLowerCase())) set.add(name);
    }
  }
  return [...set];
}

export function extractConfigs(text: string): ExtractedConfigs {
  return {
    firebase: extractFirebaseConfig(text),
    supabase: extractSupabaseConfig(text),
    collections: extractCollections(text),
  };
}

// ---------------------------------------------------------------------------
// Secretos filtrados. La apiKey de Firebase y la anon key de Supabase son
// PÚBLICAS por diseño (van en el frontend): NO son secretos, no las reportamos.
// El peligro son las claves que nunca deberían salir del servidor.
// ---------------------------------------------------------------------------

export function detectSecrets(text: string): DetectedSecret[] {
  const found: DetectedSecret[] = [];
  const seen = new Set<string>();
  const add = (s: DetectedSecret) => {
    if (seen.has(s.kind)) return;
    seen.add(s.kind);
    found.push(s);
  };

  for (const jwt of text.match(JWT_RE) || []) {
    const payload = decodeJwtPayload(jwt);
    if (payload && payload.role === 'service_role') {
      add({
        kind: 'supabase_service_role',
        label: 'Clave service_role de Supabase',
        severity: 'critical',
        sample: mask(jwt),
        why: 'Ignora por completo el Row Level Security: quien la tenga lee y escribe TODA tu base de datos. Nunca debe salir del servidor.',
      });
    }
  }
  const sbSecret = /sb_secret_[A-Za-z0-9_-]{10,}/.exec(text);
  if (sbSecret) add({ kind: 'supabase_secret_key', label: 'Clave secreta de Supabase (sb_secret_)', severity: 'critical', sample: mask(sbSecret[0]), why: 'Clave de servicio de Supabase con acceso total. No debe estar en el frontend.' });

  const stripeLive = /\b(sk|rk)_live_[0-9A-Za-z]{16,}/.exec(text);
  if (stripeLive) add({ kind: 'stripe_secret_live', label: 'Clave secreta de Stripe (LIVE)', severity: 'critical', sample: mask(stripeLive[0]), why: 'Permite mover dinero real en tu cuenta de Stripe. Debe vivir sólo en el servidor.' });
  const stripeTest = /\b(sk|rk)_test_[0-9A-Za-z]{16,}/.exec(text);
  if (stripeTest) add({ kind: 'stripe_secret_test', label: 'Clave secreta de Stripe (test)', severity: 'high', sample: mask(stripeTest[0]), why: 'Es de pruebas, pero no debería estar en el cliente.' });

  const openai = /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/.exec(text);
  if (openai && !/sk-ant-/.test(openai[0])) add({ kind: 'openai_api_key', label: 'API key de OpenAI', severity: 'critical', sample: mask(openai[0]), why: 'Cualquiera puede gastar tu saldo de OpenAI. Muévela a una variable de entorno del servidor.' });
  const anthropic = /\bsk-ant-[A-Za-z0-9_-]{20,}/.exec(text);
  if (anthropic) add({ kind: 'anthropic_api_key', label: 'API key de Anthropic', severity: 'critical', sample: mask(anthropic[0]), why: 'Expone tu cuenta de Anthropic; cualquiera puede gastar tu saldo.' });

  const aws = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/.exec(text);
  if (aws) add({ kind: 'aws_access_key', label: 'Access key de AWS', severity: 'critical', sample: mask(aws[0]), why: 'Credenciales de AWS. Con el secreto asociado, dan acceso a tu infraestructura.' });

  if (/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(text)) {
    add({ kind: 'private_key', label: 'Bloque de clave privada', severity: 'critical', sample: '-----BEGIN PRIVATE KEY----- …', why: 'Una clave privada en el frontend permite suplantar a tu servidor o servicio.' });
  }
  const gsecret = /\bGOCSPX-[A-Za-z0-9_-]{20,}/.exec(text);
  if (gsecret) add({ kind: 'google_oauth_secret', label: 'Client secret de Google OAuth', severity: 'high', sample: mask(gsecret[0]), why: 'El secreto de tu cliente OAuth no debe exponerse.' });

  return found;
}
