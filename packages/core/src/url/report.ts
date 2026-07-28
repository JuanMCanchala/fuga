/**
 * Construye el reporte uniforme del ESCANEO POR URL a partir de la config y los
 * secretos extraídos del bundle + los resultados de sondear el backend en vivo.
 * Devuelve la MISMA forma que runFuga para que la consola lo renderice igual,
 * más `secrets` y `source: 'url'`.
 *
 * PURO (sin red): la parte de red vive en la API route con guardas anti-SSRF.
 */

import { Finding, ScanReport, Severity, SEVERITY_ORDER } from '../scan/types';
import { ExploitReport, ExploitAttempt } from '../prove/attacker';
import { classifyFieldByLexicon } from '../rag/schema';
import { hardenSupabase, type SupabaseSchema, type TableModel } from '../supabase/engine';
import { templateRules } from '../fix/harden';
import type { ExtractedConfigs, DetectedSecret } from './extract';

export interface UrlProbeLeak {
  backend: 'firestore' | 'rtdb' | 'supabase';
  target: string;
  method: 'read' | 'write';
  /** Filas/documentos de muestra que el backend devolvió sin autenticación. */
  rows: Record<string, unknown>[];
}

export interface UrlProbeResult {
  backend: 'firestore' | 'rtdb' | 'supabase';
  reachable: boolean;
  leaks: UrlProbeLeak[];
  /** Targets que respondieron 401/403 (bien: protegidos). */
  protectedTargets: string[];
  /** Todos los targets que llegamos a enumerar. */
  enumerated: string[];
  note?: string;
}

export interface UrlScanInput {
  url: string;
  configs: ExtractedConfigs;
  secrets: DetectedSecret[];
  probes: UrlProbeResult[];
}

export interface UrlReport {
  source: 'url';
  target: string;
  backend: string;
  llm: 'none';
  schema: { collections: string[] };
  scan: ScanReport;
  exploit: ExploitReport;
  fix: { rules: string; source: string; validated: boolean };
  verify: { clean: boolean; remaining: number };
  crossTenant: [];
  secrets: DetectedSecret[];
  configs: { firebase?: { projectId?: string }; supabase?: { ref: string } };
  /** Aviso: el escaneo por URL es best-effort. */
  advisory: string;
}

function piiOf(row: Record<string, unknown>): string[] {
  return Object.keys(row).filter((k) => classifyFieldByLexicon(k) !== 'ninguno');
}

export function buildUrlReport(input: UrlScanInput): UrlReport {
  const { url, configs, secrets, probes } = input;
  const findings: Finding[] = [];
  const attempts: ExploitAttempt[] = [];

  // --- Secretos filtrados en el bundle ---
  for (const s of secrets) {
    findings.push({
      code: 'FUGA-URL-SECRET',
      title: `Secreto expuesto en el frontend: ${s.label}`,
      severity: s.severity,
      matchPath: 'bundle JS',
      line: 0,
      methods: ['read'],
      condition: s.sample,
      rationale: `${s.why} Se encontró en el código que se descarga al navegador (${s.sample}).`,
      recommendation: 'Muévela a una variable de entorno del servidor y rótala: ya está comprometida.',
      proven: true,
      collection: 'bundle',
      piiFields: [],
    });
  }

  // --- Fugas probadas contra el backend en vivo ---
  const leakTargets = new Set<string>();
  let totalDocsExposed = 0;
  for (const probe of probes) {
    for (const leak of probe.leaks) {
      leakTargets.add(leak.target);
      const sample = leak.rows[0] ?? {};
      const pii = piiOf(sample);
      const isRead = leak.method === 'read';
      findings.push({
        code: isRead ? 'FUGA-URL-READ' : 'FUGA-URL-WRITE',
        title: isRead
          ? `Lectura pública probada en "${leak.target}"`
          : `Escritura pública probada en "${leak.target}"`,
        severity: pii.length ? 'critical' : isRead ? 'high' : 'critical',
        matchPath: `${leak.backend} · ${leak.target}`,
        line: 0,
        methods: isRead ? ['read'] : ['write'],
        condition: 'acceso sin autenticación',
        rationale:
          `Cualquiera en internet puede ${isRead ? 'leer' : 'escribir'} "${leak.target}" en tu ${leak.backend}. ` +
          `Lo probamos desde afuera con la clave pública que va en tu app.` +
          (pii.length ? ` Se exponen datos personales: ${pii.join(', ')}.` : ''),
        recommendation:
          leak.backend === 'supabase'
            ? 'Activa Row Level Security y crea policies por dueño: `USING (auth.uid() = user_id)`.'
            : 'Restringe la regla al dueño autenticado en vez de acceso público.',
        proven: true,
        collection: leak.target,
        piiFields: pii,
      });
      if (isRead) {
        totalDocsExposed += leak.rows.length;
        attempts.push({
          collection: leak.target,
          path: leak.target,
          method: 'read',
          verdict: 'ALLOW',
          proven: true,
          exfiltrated: leak.rows,
          piiFields: pii,
        });
      } else {
        attempts.push({ collection: leak.target, path: leak.target, method: 'write', verdict: 'ALLOW', proven: true, piiFields: pii });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  const riskScore = Math.min(100, findings.reduce((s, f) => s + SEVERITY_ORDER[f.severity] * 20, 0));

  const scan: ScanReport = { service: 'url-scan', version: null, findings, summary, riskScore };
  const exploit: ExploitReport = {
    attempts,
    leaks: attempts.filter((a) => a.proven),
    totalDocsExposed,
    clean: attempts.length === 0,
  };

  // --- Fix a partir de lo que descubrimos ---
  const supabaseLeaks = probes.find((p) => p.backend === 'supabase');
  const firestoreLeaks = probes.find((p) => p.backend === 'firestore');
  let fix = { rules: '', source: 'plantilla', validated: false };
  let backend = 'unknown';

  if (supabaseLeaks && (supabaseLeaks.leaks.length || supabaseLeaks.enumerated.length)) {
    backend = 'supabase';
    const names = supabaseLeaks.enumerated.length ? supabaseLeaks.enumerated : supabaseLeaks.leaks.map((l) => l.target);
    const tables = new Map<string, TableModel>(names.map((n) => [n, { name: n, rlsEnabled: false, policies: [] }]));
    const schema: SupabaseSchema = { tables };
    fix = hardenSupabase(schema);
  } else if (firestoreLeaks && (firestoreLeaks.leaks.length || firestoreLeaks.enumerated.length)) {
    backend = 'firestore';
    const names = firestoreLeaks.enumerated.length ? firestoreLeaks.enumerated : firestoreLeaks.leaks.map((l) => l.target);
    fix = { rules: templateRules(names, 'ownerId'), source: 'plantilla', validated: true };
  } else if (configs.supabase) {
    backend = 'supabase';
  } else if (configs.firebase) {
    backend = 'firestore';
  }

  const collections = [...new Set(probes.flatMap((p) => p.enumerated))];

  return {
    source: 'url',
    target: url,
    backend,
    llm: 'none',
    schema: { collections },
    scan,
    exploit,
    fix,
    verify: { clean: fix.validated, remaining: fix.validated ? 0 : leakTargets.size },
    crossTenant: [],
    secrets,
    configs: {
      firebase: configs.firebase ? { projectId: configs.firebase.projectId } : undefined,
      supabase: configs.supabase ? { ref: configs.supabase.ref } : undefined,
    },
    advisory:
      'El escaneo por URL es best-effort: solo ve lo que expone tu bundle y lo que responde tu backend sin autenticación. ' +
      'Para el análisis completo —incluida la fuga entre usuarios— pega tus reglas de Firestore, Realtime Database o Supabase.',
  };
}
