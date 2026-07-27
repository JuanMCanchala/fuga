/**
 * Motor de FUGA para Supabase (Postgres Row Level Security).
 *
 * Supabase expone TODAS las tablas del esquema `public` por PostgREST usando la
 * clave `anon`. Si una tabla NO tiene RLS habilitado, cualquiera con la anon key
 * (que es pública, va en el frontend) puede leer y escribir TODO. Ese es el
 * antipatrón #1 de los vibe coders: crean tablas y olvidan `ENABLE ROW LEVEL
 * SECURITY`. El segundo: una policy `USING (true)`.
 *
 * Reutiliza los tipos de reporte para que la UI sea uniforme con Firestore/RTDB.
 */

import { Finding, ScanReport, Severity, SEVERITY_ORDER } from '../scan/types';
import { ExploitAttempt, ExploitReport, SeededDb } from '../prove/attacker';
import { classifyFieldByLexicon, sensitivityOf } from '../rag/schema';
import type { SchemaModel } from '../rag/schema';

export type Verdict = 'ALLOW' | 'DENY' | 'INDETERMINATE';

export interface Policy {
  name: string;
  command: 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
  roles: string[]; // vacío => public (todos, incluido anon)
  using?: string;
  check?: string;
}

export interface TableModel {
  name: string;
  rlsEnabled: boolean;
  policies: Policy[];
}

export interface SupabaseSchema {
  tables: Map<string, TableModel>;
}

// ---------------------------------------------------------------------------
// Parseo SQL
// ---------------------------------------------------------------------------

function splitStatements(sql: string): string[] {
  const stmts: string[] = [];
  let cur = '';
  let depth = 0;
  let q: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (q) {
      cur += c;
      if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      cur += c;
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i++;
      continue;
    }
    if (c === '(') depth++;
    if (c === ')') depth--;
    if (c === ';' && depth === 0) {
      if (cur.trim()) stmts.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) stmts.push(cur.trim());
  return stmts;
}

function bareName(raw: string): string {
  return raw.replace(/["'`]/g, '').replace(/^\w+\./, ''); // quita esquema public.
}

/** Extrae el contenido de los paréntesis que siguen a `keyword` en la sentencia. */
function extractParens(stmt: string, keyword: RegExp): string | undefined {
  const m = keyword.exec(stmt);
  if (!m) return undefined;
  let i = m.index + m[0].length;
  while (i < stmt.length && stmt[i] !== '(') i++;
  if (stmt[i] !== '(') return undefined;
  let depth = 0;
  let out = '';
  for (; i < stmt.length; i++) {
    const c = stmt[i];
    if (c === '(') {
      depth++;
      if (depth === 1) continue;
    }
    if (c === ')') {
      depth--;
      if (depth === 0) break;
    }
    out += c;
  }
  return out.trim();
}

export function parseSupabase(sql: string): SupabaseSchema {
  const tables = new Map<string, TableModel>();
  const ensure = (name: string): TableModel => {
    const n = bareName(name);
    if (!tables.has(n)) tables.set(n, { name: n, rlsEnabled: false, policies: [] });
    return tables.get(n)!;
  };

  for (const stmt of splitStatements(sql)) {
    const s = stmt.replace(/\s+/g, ' ').trim();
    const lower = s.toLowerCase();

    // CREATE TABLE
    let m = /create\s+table\s+(?:if\s+not\s+exists\s+)?([^\s(]+)/i.exec(s);
    if (m) {
      ensure(m[1]);
      continue;
    }

    // ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY
    m = /alter\s+table\s+([^\s]+)\s+(enable|disable)\s+row\s+level\s+security/i.exec(s);
    if (m) {
      ensure(m[1]).rlsEnabled = m[2].toLowerCase() === 'enable';
      continue;
    }

    // CREATE POLICY name ON table [AS ...] [FOR cmd] [TO roles] [USING (..)] [WITH CHECK (..)]
    m = /create\s+policy\s+("[^"]+"|'[^']+'|[^\s]+)\s+on\s+([^\s]+)/i.exec(s);
    if (m) {
      const t = ensure(m[2]);
      const cmdM = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(lower);
      const toM = /\bto\s+([a-z_,\s]+?)(?:\s+using|\s+with\s+check|$)/i.exec(lower);
      const roles = toM
        ? toM[1].split(',').map((r) => r.trim()).filter((r) => r && r !== 'using' && r !== 'with')
        : [];
      const using = extractParens(s, /\busing\b/i);
      const check = extractParens(s, /\bwith\s+check\b/i);
      t.policies.push({
        name: bareName(m[1]),
        command: (cmdM ? cmdM[1].toUpperCase() : 'ALL') as Policy['command'],
        roles,
        using,
        check,
      });
      continue;
    }
  }

  return { tables };
}

// ---------------------------------------------------------------------------
// Evaluación para el atacante anónimo (rol `anon`, auth.uid() null)
// ---------------------------------------------------------------------------

function evalPolicyExpr(expr: string | undefined): Verdict {
  if (expr === undefined) return 'INDETERMINATE';
  const e = expr.trim().toLowerCase();
  if (e === 'true') return 'ALLOW';
  if (e === 'false') return 'DENY';
  // Cualquier referencia a la identidad requiere autenticación => el anónimo NO pasa.
  if (/auth\.(uid|jwt|role)\s*\(\)|authenticated|current_user|current_setting|user_id|owner|created_by/.test(e)) {
    return 'DENY';
  }
  return 'INDETERMINATE';
}

function appliesToAnon(p: Policy): boolean {
  // Sin TO => public (incluye anon). Con TO, aplica si incluye anon o public.
  if (p.roles.length === 0) return true;
  return p.roles.some((r) => r === 'anon' || r === 'public');
}

const READ_CMDS = new Set(['ALL', 'SELECT']);
const WRITE_CMDS = new Set(['ALL', 'INSERT', 'UPDATE', 'DELETE']);

export function evaluateSupabase(table: TableModel, kind: 'read' | 'write'): Verdict {
  // Sin RLS: PostgREST expone la tabla al rol anon por completo.
  if (!table.rlsEnabled) return 'ALLOW';

  const relevant = table.policies.filter(
    (p) => appliesToAnon(p) && (kind === 'read' ? READ_CMDS.has(p.command) : WRITE_CMDS.has(p.command)),
  );
  if (relevant.length === 0) return 'DENY'; // RLS on y sin policy que aplique => denegado
  let indet = false;
  for (const p of relevant) {
    const expr = kind === 'read' ? p.using : p.check ?? p.using;
    const v = evalPolicyExpr(expr);
    if (v === 'ALLOW') return 'ALLOW';
    if (v === 'INDETERMINATE') indet = true;
  }
  return indet ? 'INDETERMINATE' : 'DENY';
}

// ---------------------------------------------------------------------------
// Análisis (scan)
// ---------------------------------------------------------------------------

export function analyzeSupabase(schema: SupabaseSchema, dataSchema?: SchemaModel): ScanReport {
  const findings: Finding[] = [];

  for (const table of schema.tables.values()) {
    const sensitive = sensitivityOf(table.name, dataSchema);
    const piiFields = sensitive.piiFields;

    if (!table.rlsEnabled) {
      findings.push({
        code: 'FUGA-SB-RLS-OFF',
        title: sensitive.sensitive
          ? `RLS deshabilitado en tabla sensible "${table.name}"`
          : `Row Level Security deshabilitado en "${table.name}"`,
        severity: 'critical',
        matchPath: table.name,
        line: 0,
        methods: ['read', 'write'],
        condition: 'RLS disabled',
        rationale:
          `La tabla "${table.name}" no tiene Row Level Security. Supabase la expone por PostgREST, ` +
          `así que cualquiera con la clave anon (pública, va en el frontend) puede leer y escribir TODAS sus filas.`,
        recommendation: `\`ALTER TABLE ${table.name} ENABLE ROW LEVEL SECURITY;\` y crear policies por dueño.`,
        proven: true,
        collection: table.name,
        piiFields,
      });
      continue;
    }

    // RLS on: buscar policies públicas.
    for (const p of table.policies) {
      if (!appliesToAnon(p)) continue;
      const usingV = evalPolicyExpr(p.using);
      if (usingV === 'ALLOW') {
        const isRead = READ_CMDS.has(p.command);
        findings.push({
          code: 'FUGA-SB-POLICY-TRUE',
          title: `Policy pública (${p.command}) en "${table.name}"`,
          severity: isRead && piiFields.length ? 'critical' : 'high',
          matchPath: `${table.name} · ${p.name}`,
          line: 0,
          methods: isRead ? ['read'] : ['write'],
          condition: `USING (${p.using})`,
          rationale:
            `La policy "${p.name}" concede ${p.command} a cualquiera (rol anon/public) con USING (${p.using}). ` +
            `Equivale a exponer la tabla.`,
          recommendation: 'Reemplazar por `USING (auth.uid() = user_id)` o restringir el rol.',
          proven: true,
          collection: table.name,
          piiFields,
        });
      }
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  const riskScore = Math.min(100, findings.reduce((s, f) => s + SEVERITY_ORDER[f.severity] * 18, 0));

  return { service: 'supabase.postgres', version: null, findings, summary, riskScore };
}

// ---------------------------------------------------------------------------
// Atacante (prove)
// ---------------------------------------------------------------------------

export function proveSupabase(schema: SupabaseSchema, db: SeededDb): ExploitReport {
  const attempts: ExploitAttempt[] = [];
  const grouped = new Map<string, Record<string, unknown>[]>();
  for (const [path, doc] of Object.entries(db)) {
    const table = path.replace(/^\//, '').split('/')[0] ?? '';
    if (!grouped.has(table)) grouped.set(table, []);
    grouped.get(table)!.push(doc);
  }

  for (const [tableName, docs] of grouped) {
    const table = schema.tables.get(tableName) ?? { name: tableName, rlsEnabled: false, policies: [] };
    const docPii = Object.keys(docs[0]).filter((k) => classifyFieldByLexicon(k) !== 'ninguno');

    const readV = evaluateSupabase(table, 'read');
    const readProven = readV === 'ALLOW';
    attempts.push({
      collection: tableName,
      path: tableName,
      method: 'read',
      verdict: readV,
      proven: readProven,
      exfiltrated: readProven ? docs : undefined,
      piiFields: docPii,
    });

    const writeV = evaluateSupabase(table, 'write');
    attempts.push({
      collection: tableName,
      path: tableName,
      method: 'write',
      verdict: writeV,
      proven: writeV === 'ALLOW',
      piiFields: docPii,
    });
  }

  const leaks = attempts.filter((a) => a.proven);
  const totalDocsExposed = leaks
    .filter((a) => a.method === 'read')
    .reduce((s, a) => s + (a.exfiltrated?.length ?? 0), 0);
  return { attempts, leaks, totalDocsExposed, clean: leaks.length === 0 };
}

// ---------------------------------------------------------------------------
// Fix
// ---------------------------------------------------------------------------

export function hardenSupabase(schema: SupabaseSchema): { rules: string; source: string; validated: boolean } {
  const tables = [...schema.tables.values()];
  const targets = tables.length ? tables : [{ name: 'tabla', rlsEnabled: false, policies: [] as Policy[] }];
  const blocks: string[] = [];

  for (const t of targets) {
    const owner = /^(users|usuarios|profiles|perfiles)$/i.test(t.name) ? 'id' : 'user_id';
    blocks.push(
      [
        `-- ${t.name}`,
        `ALTER TABLE ${t.name} ENABLE ROW LEVEL SECURITY;`,
        `CREATE POLICY "${t.name}_select_own" ON ${t.name}`,
        `  FOR SELECT TO authenticated USING (auth.uid() = ${owner});`,
        `CREATE POLICY "${t.name}_modify_own" ON ${t.name}`,
        `  FOR ALL TO authenticated USING (auth.uid() = ${owner}) WITH CHECK (auth.uid() = ${owner});`,
      ].join('\n'),
    );
  }

  const rules =
    '-- Reglas endurecidas por FUGA: RLS habilitado + acceso por dueño autenticado.\n\n' + blocks.join('\n\n') + '\n';

  // Validación: re-parsear y comprobar que el anónimo queda denegado.
  const hardened = parseSupabase(rules);
  let clean = true;
  for (const t of hardened.tables.values()) {
    if (evaluateSupabase(t, 'read') === 'ALLOW' || evaluateSupabase(t, 'write') === 'ALLOW') clean = false;
  }
  return { rules, source: 'plantilla', validated: clean };
}
