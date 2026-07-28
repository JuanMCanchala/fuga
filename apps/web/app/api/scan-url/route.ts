import { NextRequest, NextResponse } from 'next/server';
import { promises as dns } from 'node:dns';
import {
  extractConfigs,
  detectSecrets,
  buildUrlReport,
  type UrlProbeResult,
  type UrlProbeLeak,
} from '@fuga/core';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 30;

const FETCH_TIMEOUT = 6000;
const MAX_HTML = 1_500_000;
const MAX_JS = 2_500_000;
const MAX_SCRIPTS = 6;
const MAX_TABLES = 12;
const SAMPLE_ROWS = 2;

// ---------------------------------------------------------------------------
// SSRF: solo permitimos URLs públicas. Bloqueamos loopback, rangos privados,
// link-local y metadata de la nube.
// ---------------------------------------------------------------------------

function isPrivateIp(ip: string): boolean {
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l === '::';
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

async function assertPublicHost(hostname: string): Promise<void> {
  const bad = /^(localhost|.*\.local|.*\.internal|metadata\.google\.internal)$/i;
  if (bad.test(hostname)) throw new Error('host no permitido');
  // Si es un literal IP, valídalo directo.
  if (/^[\d.]+$/.test(hostname) || hostname.includes(':')) {
    if (isPrivateIp(hostname)) throw new Error('IP privada no permitida');
    return;
  }
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length) throw new Error('host sin resolución');
  for (const a of addrs) if (isPrivateIp(a.address)) throw new Error('el host resuelve a una IP privada');
}

async function safeFetch(url: string, maxBytes: number, headers?: Record<string, string>): Promise<string> {
  const u = new URL(url);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('protocolo no permitido');
  await assertPublicHost(u.hostname);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers, redirect: 'follow' });
    const reader = res.body?.getReader();
    if (!reader) return '';
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        size += value.length;
        if (size > maxBytes) {
          try { await reader.cancel(); } catch { /* noop */ }
          break;
        }
        chunks.push(value);
      }
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    clearTimeout(t);
  }
}

/** Baja el HTML + los scripts del mismo origen y concatena el texto. */
async function fetchBundle(url: string): Promise<string> {
  const html = await safeFetch(url, MAX_HTML);
  const base = new URL(url);
  const srcs: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null && srcs.length < MAX_SCRIPTS) {
    try {
      const abs = new URL(m[1], base);
      if (abs.host === base.host && /\.js(\?|$)/.test(abs.pathname)) srcs.push(abs.toString());
    } catch { /* ignora src inválido */ }
  }
  let text = html;
  const scripts = await Promise.allSettled(srcs.map((s) => safeFetch(s, MAX_JS)));
  for (const r of scripts) if (r.status === 'fulfilled') text += '\n' + r.value;
  return text;
}

// ---------------------------------------------------------------------------
// Sondas (solo lectura, acotadas). La clave pública va en el frontend; si el
// backend responde datos sin autenticación, la fuga es real.
// ---------------------------------------------------------------------------

async function probeSupabase(refUrl: string, anonKey: string): Promise<UrlProbeResult> {
  const result: UrlProbeResult = { backend: 'supabase', reachable: false, leaks: [], protectedTargets: [], enumerated: [] };
  const headers = { apikey: anonKey, authorization: `Bearer ${anonKey}` };
  // PostgREST expone el esquema en la raíz: enumera tablas.
  try {
    const rootTxt = await safeFetch(`${refUrl}/rest/v1/`, 400_000, headers);
    result.reachable = true;
    try {
      const spec = JSON.parse(rootTxt);
      const defs = spec.definitions || (spec.components && spec.components.schemas) || {};
      result.enumerated = Object.keys(defs).slice(0, MAX_TABLES);
    } catch { /* sin OpenAPI legible */ }
  } catch { return result; }

  for (const table of result.enumerated) {
    try {
      const txt = await safeFetch(`${refUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=${SAMPLE_ROWS}`, 200_000, headers);
      let rows: unknown;
      try { rows = JSON.parse(txt); } catch { rows = null; }
      if (Array.isArray(rows) && rows.length > 0) {
        result.leaks.push({ backend: 'supabase', target: table, method: 'read', rows: rows.slice(0, SAMPLE_ROWS) as Record<string, unknown>[] });
      } else {
        result.protectedTargets.push(table); // RLS bloqueó o tabla vacía
      }
    } catch { result.protectedTargets.push(table); }
  }
  return result;
}

const FIRESTORE_WORDLIST = ['users', 'usuarios', 'profiles', 'perfiles', 'pagos', 'payments', 'orders', 'pedidos', 'messages', 'mensajes', 'pacientes', 'clientes', 'customers', 'posts', 'productos', 'invoices'];

function decodeFirestoreDoc(doc: any): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const fields = doc?.fields || {};
  for (const [k, v] of Object.entries<any>(fields)) {
    out[k] =
      v.stringValue ?? v.integerValue ?? v.doubleValue ?? v.booleanValue ??
      (v.timestampValue ?? (v.nullValue !== undefined ? null : v.mapValue ? '[objeto]' : v.arrayValue ? '[lista]' : '[valor]'));
  }
  return out;
}

async function probeFirestore(projectId: string, apiKey: string, candidates: string[]): Promise<UrlProbeResult> {
  const result: UrlProbeResult = { backend: 'firestore', reachable: false, leaks: [], protectedTargets: [], enumerated: [] };
  const targets = [...new Set([...candidates, ...FIRESTORE_WORDLIST])].slice(0, MAX_TABLES);
  for (const coll of targets) {
    const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${encodeURIComponent(coll)}?key=${encodeURIComponent(apiKey)}&pageSize=${SAMPLE_ROWS}`;
    try {
      const txt = await safeFetch(url, 200_000);
      result.reachable = true;
      let data: any;
      try { data = JSON.parse(txt); } catch { data = null; }
      if (data && Array.isArray(data.documents) && data.documents.length > 0) {
        result.enumerated.push(coll);
        result.leaks.push({ backend: 'firestore', target: coll, method: 'read', rows: data.documents.slice(0, SAMPLE_ROWS).map(decodeFirestoreDoc) });
      } else if (data && !data.error) {
        result.enumerated.push(coll); // existe/legible pero sin docs
      } else if (data && data.error && (data.error.status === 'PERMISSION_DENIED' || data.error.code === 403)) {
        result.protectedTargets.push(coll);
      }
    } catch { /* red/timeout: sigue */ }
  }
  return result;
}

// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as { url?: string };
    let raw = (body?.url ?? '').trim();
    if (!raw) return NextResponse.json({ error: 'Falta el campo "url".' }, { status: 400 });
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

    let target: URL;
    try { target = new URL(raw); } catch { return NextResponse.json({ error: 'URL inválida.' }, { status: 400 }); }
    try { await assertPublicHost(target.hostname); } catch (e) {
      return NextResponse.json({ error: 'Esa URL no se puede escanear (host interno/privado no permitido).' }, { status: 400 });
    }

    const bundle = await fetchBundle(target.toString());
    const configs = extractConfigs(bundle);
    const secrets = detectSecrets(bundle);

    if (!configs.firebase && !configs.supabase) {
      return NextResponse.json({
        error: 'no-backend',
        message:
          'No encontramos config de Firebase ni Supabase en el bundle de esa URL. Puede ser que uses otro backend, o que la config no viaje en el frontend. Para el análisis completo, pega tus reglas de Firestore, Realtime Database o Supabase.',
        secrets,
      }, { status: 200 });
    }

    const probes: UrlProbeResult[] = [];
    if (configs.supabase?.anonKey) {
      probes.push(await probeSupabase(configs.supabase.url, configs.supabase.anonKey));
    }
    if (configs.firebase?.projectId && configs.firebase.apiKey) {
      probes.push(await probeFirestore(configs.firebase.projectId, configs.firebase.apiKey, configs.collections));
    }

    const report = buildUrlReport({ url: target.toString(), configs, secrets, probes });
    return NextResponse.json(report);
  } catch (err) {
    console.error('[fuga/api/scan-url]', err);
    const out: { error: string; detail?: string } = { error: 'No se pudo escanear la URL.' };
    if (process.env.NODE_ENV !== 'production') out.detail = String(err);
    return NextResponse.json(out, { status: 500 });
  }
}
