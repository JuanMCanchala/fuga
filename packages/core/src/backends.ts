/**
 * Dispatcher multi-backend de FUGA. Detecta si el texto son reglas de Firestore,
 * de Realtime Database (JSON) o políticas RLS de Supabase (SQL), y ejecuta el
 * pipeline scan -> prove -> fix -> verify con el motor correspondiente,
 * devolviendo siempre la MISMA forma de salida para que la UI sea uniforme.
 */

import { parseRules } from './rules/parser';
import { analyze } from './scan/analyzer';
import { prove } from './prove/attacker';
import { harden } from './fix/harden';
import { indexClientCode } from './rag/indexer';
import { selectProvider } from './llm/provider';
import { synthSeed, synthSeedFor } from './prove/seed';
import type { SeededDb } from './prove/attacker';
import type { ScanReport } from './scan/types';
import type { ExploitReport } from './prove/attacker';

import { parseRtdbRules, analyzeRtdb, proveRtdb, hardenRtdb, rtdbCollections } from './rtdb/engine';
import { parseSupabase, analyzeSupabase, proveSupabase, hardenSupabase } from './supabase/engine';
import {
  proveCrossTenantFirestore,
  proveCrossTenantSupabase,
  crossTenantFindings,
  type TenantLeak,
  type TenantReport,
} from './prove/multitenant';
import { SEVERITY_ORDER } from './scan/types';
import type { ExploitAttempt } from './prove/attacker';

export type Backend = 'firestore' | 'rtdb' | 'supabase';

/** Detecta el backend a partir del contenido de las reglas. */
export function detectBackend(text: string): Backend {
  const t = text.trim();
  const lower = t.toLowerCase();
  // SQL de Supabase.
  if (/create\s+policy|row\s+level\s+security|create\s+table|alter\s+table/.test(lower)) {
    return 'supabase';
  }
  // Firestore (CEL con match/allow).
  if (/rules_version|service\s+cloud\.firestore|service\s+firebase\.storage|allow\s+(read|write|get|list|create|update|delete)/.test(lower)) {
    return 'firestore';
  }
  // RTDB: JSON con ".read"/".write" o clave "rules".
  if ((t.startsWith('{') && (/"\.(read|write|validate)"/.test(t) || /"rules"\s*:/.test(t)))) {
    return 'rtdb';
  }
  // Por defecto, intenta firestore.
  return 'firestore';
}

export interface RunResult {
  backend: Backend;
  llm: string;
  targets: string[];
  scan: ScanReport;
  exploit: ExploitReport;
  fix: { rules: string; source: string; validated: boolean };
  verify: { clean: boolean; remaining: number };
  /** Fugas ENTRE USUARIOS probadas (IDOR / cross-tenant). El diferenciador. */
  crossTenant: TenantLeak[];
}

/**
 * Funde las fugas entre usuarios en los reportes de scan y exploit: los
 * hallazgos IDOR van primero (son el titular), la evidencia de Alice se suma a
 * lo exfiltrado, y el riesgo sube a crítico si hay PII de por medio.
 */
function mergeCrossTenant(scan: ScanReport, exploit: ExploitReport, tenant: TenantReport): void {
  if (!tenant.leaks.length) return;
  const findings = crossTenantFindings(tenant);
  scan.findings = [...findings, ...scan.findings];
  scan.findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of scan.findings) summary[f.severity]++;
  scan.summary = summary;

  const hasCrit = findings.some((f) => f.severity === 'critical');
  scan.riskScore = Math.min(100, Math.max(scan.riskScore, hasCrit ? 100 : 80));

  for (const l of tenant.leaks) {
    const attempt: ExploitAttempt = {
      collection: l.collection,
      path: l.collection,
      method: l.method,
      verdict: 'ALLOW',
      proven: true,
      exfiltrated: l.method === 'read' && l.victimData ? [l.victimData] : undefined,
      piiFields: l.piiFields,
    };
    exploit.attempts.push(attempt);
    exploit.leaks.push(attempt);
  }
  exploit.totalDocsExposed += tenant.leaks.filter((l) => l.method === 'read').length;
  exploit.clean = exploit.leaks.length === 0;
}

export interface RunOptions {
  rules: string;
  code?: string;
  seed?: SeededDb;
  backend?: Backend;
}

/** Ejecuta el pipeline completo de FUGA para cualquier backend. */
export async function runFuga(opts: RunOptions): Promise<RunResult> {
  const backend = opts.backend ?? detectBackend(opts.rules);
  const schema = indexClientCode(opts.code ? [{ file: 'cliente', content: opts.code }] : []);

  if (backend === 'rtdb') {
    const ast = parseRtdbRules(opts.rules);
    const targets = rtdbCollections(ast);
    const scan = analyzeRtdb(ast, schema);
    const db = opts.seed ?? synthSeedFor(targets, schema);
    const exploit = proveRtdb(ast, db);
    const fix = hardenRtdb(targets);
    const verify = proveRtdb(parseRtdbRules(fix.rules), db);
    // El motor cross-tenant de RTDB llega en la próxima iteración.
    return { backend, llm: 'none', targets, scan, exploit, fix, verify: { clean: verify.clean, remaining: verify.leaks.length }, crossTenant: [] };
  }

  if (backend === 'supabase') {
    const sb = parseSupabase(opts.rules);
    const targets = [...sb.tables.keys()];
    const scan = analyzeSupabase(sb, schema);
    const db = opts.seed ?? synthSeedFor(targets, schema);
    const exploit = proveSupabase(sb, db);
    const tenant = proveCrossTenantSupabase(sb, schema);
    mergeCrossTenant(scan, exploit, tenant);
    const fix = hardenSupabase(sb);
    const hardenedSb = parseSupabase(fix.rules);
    const verifyAnon = proveSupabase(hardenedSb, db);
    const verifyTenant = proveCrossTenantSupabase(hardenedSb, schema);
    const remaining = verifyAnon.leaks.length + verifyTenant.leaks.length;
    return { backend, llm: 'none', targets, scan, exploit, fix, verify: { clean: remaining === 0, remaining }, crossTenant: tenant.leaks };
  }

  // Firestore (con LLM opcional para el fix).
  const ast = parseRules(opts.rules);
  const codeCollections = Object.keys(schema.collections);
  const scan = analyze(ast, { schema });
  const db = opts.seed ?? (codeCollections.length ? synthSeed(schema) : synthSeedFor(collectionsFromFirestore(opts.rules), schema));
  const exploit = prove(ast, { db, schema });
  const tenant = proveCrossTenantFirestore(ast, schema);
  mergeCrossTenant(scan, exploit, tenant);
  const provider = await selectProvider();
  const collections = codeCollections.length ? codeCollections : collectionsFromFirestore(opts.rules);
  const fix = await harden({ originalRules: opts.rules, collections, schema, provider });
  const hardenedAst = parseRules(fix.rules);
  const verifyAnon = prove(hardenedAst, { db, schema });
  const verifyTenant = proveCrossTenantFirestore(hardenedAst, schema);
  const remaining = verifyAnon.leaks.length + verifyTenant.leaks.length;
  return {
    backend,
    llm: provider.name,
    targets: collections,
    scan,
    exploit,
    fix: { rules: fix.rules, source: fix.source, validated: fix.validated },
    verify: { clean: remaining === 0, remaining },
    crossTenant: tenant.leaks,
  };
}

/** Colecciones de nivel superior a partir de los match de Firestore. */
function collectionsFromFirestore(rulesText: string): string[] {
  const set = new Set<string>();
  const re = /match\s+\/([A-Za-z0-9_-]+)\//g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rulesText)) !== null) {
    if (m[1] !== 'databases') set.add(m[1]);
  }
  return [...set];
}
