/**
 * Fuga ENTRE USUARIOS (escalada horizontal / IDOR / cross-tenant).
 *
 * Éste es el diferenciador de FUGA. Todos los escáneres del mercado detectan lo
 * obvio: "la regla es pública" o "el RLS está apagado". El bug DIFÍCIL —el que
 * expuso apps de Supabase en masa (CVE-2025-48757) y que ningún linter ve— es
 * otro: la regla SÍ exige estar autenticado, pero no comprueba que seas el
 * DUEÑO del dato. Resultado: cualquier usuario con cuenta puede leer o editar
 * los registros de los demás.
 *
 * Un atacante anónimo obtiene DENY, así que el análisis clásico dice "seguro".
 * Aquí NO atacamos como anónimos: atacamos como un segundo usuario legítimo
 * ("Mallory") contra los datos de otro ("Alice"). Si Mallory llega al registro
 * de Alice y el anónimo no, la regla está autenticada pero no acotada al dueño:
 * fuga entre usuarios, PROBADA.
 */

import { RulesFile } from '../rules/ast';
import { PathSegment } from '../rules/ast';
import { evaluate, Verdict } from '../rules/evaluator';
import { Finding, Severity } from '../scan/types';
import { classifyFieldByLexicon } from '../rag/schema';
import type { SchemaModel } from '../rag/schema';
import { synthSeedFor } from './seed';
import { listRules } from '../rules/evaluator';
import type { SupabaseSchema, Policy } from '../supabase/engine';
import { evaluateSupabase } from '../supabase/engine';

/** Identidades ficticias del ataque entre inquilinos. */
export const VICTIM_UID = 'alice_perez_uid';
export const ATTACKER_UID = 'mallory_uid';

/** Campos que marcan la propiedad de un registro. */
const OWNER_FIELDS = ['ownerId', 'owner_id', 'userId', 'user_id', 'uid', 'owner', 'authorId', 'author_id', 'createdBy', 'created_by', 'user'];

export interface TenantLeak {
  backend: 'firestore' | 'rtdb' | 'supabase';
  collection: string;
  method: 'read' | 'write';
  /** Los datos de la víctima que el atacante (otra cuenta) logró alcanzar. */
  victimData?: Record<string, unknown>;
  piiFields: string[];
  /** La condición/policy que lo permitió. */
  rule: string;
}

export interface TenantReport {
  leaks: TenantLeak[];
  clean: boolean;
}

// ---------------------------------------------------------------------------
// Utilidades comunes
// ---------------------------------------------------------------------------

/** Campos PII del doc de la víctima (sin los marcadores de propiedad). */
function piiOf(doc: Record<string, unknown>): string[] {
  return Object.keys(doc).filter((k) => !OWNER_FIELDS.includes(k) && classifyFieldByLexicon(k) !== 'ninguno');
}

/** Documento-víctima: datos verosímiles + marcadores de propiedad = Alice. */
function victimDoc(collection: string, schema?: SchemaModel): Record<string, unknown> {
  const seed = synthSeedFor([collection], schema);
  const base = (Object.values(seed)[0] as Record<string, unknown>) ?? {};
  const doc: Record<string, unknown> = { ...base };
  // Reescribe cualquier marcador de propiedad presente como Alice…
  for (const f of OWNER_FIELDS) if (f in doc) doc[f] = VICTIM_UID;
  // …y garantiza los tres más comunes para que las reglas por-dueño resuelvan.
  doc.ownerId = VICTIM_UID;
  doc.userId = VICTIM_UID;
  doc.uid = VICTIM_UID;
  return doc;
}

// ---------------------------------------------------------------------------
// Firestore
// ---------------------------------------------------------------------------

function topCollection(matchPath: string): string | undefined {
  const parts = matchPath.replace(/^\//, '').split('/').filter(Boolean);
  return parts.find((p) => !p.startsWith('{'));
}

/** Path de la víctima: literales tal cual, la última variable = uid de Alice. */
function victimPath(segs: PathSegment[]): string {
  let lastVarIdx = -1;
  segs.forEach((s, i) => {
    if (!s.literal && !s.recursive) lastVarIdx = i;
  });
  const parts = segs.map((s, i) => {
    if (s.literal) return s.raw;
    if (s.recursive) return VICTIM_UID;
    return i === lastVarIdx ? VICTIM_UID : 'x';
  });
  return '/' + parts.join('/');
}

const READ_MS = ['read', 'get', 'list'];
const WRITE_MS = ['write', 'create', 'update', 'delete'];

export function proveCrossTenantFirestore(rules: RulesFile, schema?: SchemaModel): TenantReport {
  const flat = listRules(rules, 'firestore');
  const leaks: TenantLeak[] = [];
  const seen = new Set<string>();

  for (const fr of flat) {
    const collection = topCollection(fr.pathSource) ?? 'datos';
    const path = victimPath(fr.segments);
    const doc = victimDoc(collection, schema);
    const db = { [path]: doc };
    const methods = fr.allow.methods as string[];
    const cond = fr.allow.conditionSource;

    const test = (method: 'get' | 'update', uid: string | null): Verdict =>
      evaluate(
        rules,
        {
          path,
          method,
          auth: uid ? { uid } : null,
          resource: doc,
          data: method === 'update' ? { ...doc, _tampered: true } : undefined,
          db,
        },
        'firestore',
      ).verdict;

    // Lectura: ¿un usuario cualquiera lee el registro de Alice?
    if (methods.some((m) => READ_MS.includes(m))) {
      const key = `${collection}:read`;
      if (!seen.has(key)) {
        const anon = test('get', null);
        const outsider = test('get', ATTACKER_UID);
        if (outsider === 'ALLOW' && anon !== 'ALLOW') {
          seen.add(key);
          leaks.push({ backend: 'firestore', collection, method: 'read', victimData: doc, piiFields: piiOf(doc), rule: cond });
        }
      }
    }

    // Escritura: ¿un usuario cualquiera edita el registro de Alice?
    if (methods.some((m) => WRITE_MS.includes(m))) {
      const key = `${collection}:write`;
      if (!seen.has(key)) {
        const anon = test('update', null);
        const outsider = test('update', ATTACKER_UID);
        if (outsider === 'ALLOW' && anon !== 'ALLOW') {
          seen.add(key);
          leaks.push({ backend: 'firestore', collection, method: 'write', victimData: doc, piiFields: piiOf(doc), rule: cond });
        }
      }
    }
  }

  return { leaks, clean: leaks.length === 0 };
}

// ---------------------------------------------------------------------------
// Supabase (Postgres RLS)
// ---------------------------------------------------------------------------

function appliesToAuthenticated(p: Policy): boolean {
  // Sin TO => public (incluye authenticated). Con TO, si menciona authenticated/public.
  if (p.roles.length === 0) return true;
  return p.roles.some((r) => r === 'authenticated' || r === 'public');
}

/** ¿La expresión ata la fila al que llama (dueño), o sólo exige estar logueado? */
function isOwnershipScoped(expr: string | undefined): boolean {
  if (!expr) return false;
  const e = expr.toLowerCase();
  // auth.uid() comparado con una columna, o claim del jwt comparado con una columna.
  if (/auth\.uid\(\)\s*(=|<@|@>|\bin\b|&&)/.test(e) || /(=|<@|@>|\bin\b|&&)\s*auth\.uid\(\)/.test(e)) return true;
  if (/auth\.jwt\(\)/.test(e) && /(=|->>|\bin\b)/.test(e)) return true;
  return false;
}

/** ¿Sólo comprueba "está autenticado" sin acotar al dueño? */
function isPresenceOnly(expr: string | undefined): boolean {
  if (expr === undefined) return false;
  const e = expr.trim().toLowerCase();
  if (e === 'true') return true;
  if (/auth\.role\(\)\s*=\s*'authenticated'/.test(e)) return true;
  if (/\bauthenticated\b/.test(e)) return true;
  if (/auth\.(uid|jwt|role)\(\)\s+is\s+not\s+null/.test(e)) return true;
  if (/auth\.uid\(\)\s*<>\s*null/.test(e) || /auth\.uid\(\)\s*!=\s*null/.test(e)) return true;
  return false;
}

const READ_CMDS = new Set(['ALL', 'SELECT']);
const WRITE_CMDS = new Set(['ALL', 'INSERT', 'UPDATE', 'DELETE']);

export function proveCrossTenantSupabase(schema: SupabaseSchema, dataSchema?: SchemaModel): TenantReport {
  const leaks: TenantLeak[] = [];

  for (const table of schema.tables.values()) {
    if (!table.rlsEnabled) continue; // sin RLS ya es fuga pública (otro hallazgo)
    const doc = victimDoc(table.name, dataSchema);

    for (const kind of ['read', 'write'] as const) {
      // Si el anónimo YA puede, es fuga pública, no entre-usuarios.
      if (evaluateSupabase(table, kind) === 'ALLOW') continue;

      const cmds = kind === 'read' ? READ_CMDS : WRITE_CMDS;
      const vulnerable = table.policies.find((p) => {
        if (!appliesToAuthenticated(p) || !cmds.has(p.command)) return false;
        const expr = kind === 'read' ? p.using : p.check ?? p.using;
        return isPresenceOnly(expr) && !isOwnershipScoped(expr);
      });

      if (vulnerable) {
        const expr = kind === 'read' ? vulnerable.using : vulnerable.check ?? vulnerable.using;
        leaks.push({
          backend: 'supabase',
          collection: table.name,
          method: kind,
          victimData: doc,
          piiFields: piiOf(doc),
          rule: `${vulnerable.name}: USING (${expr ?? '—'})`,
        });
      }
    }
  }

  return { leaks, clean: leaks.length === 0 };
}

// ---------------------------------------------------------------------------
// Hallazgos a partir de las fugas entre usuarios
// ---------------------------------------------------------------------------

export function crossTenantFindings(report: TenantReport): Finding[] {
  return report.leaks.map((l) => {
    const isRead = l.method === 'read';
    const severity: Severity = l.piiFields.length ? 'critical' : isRead ? 'high' : 'critical';
    const verbo = isRead ? 'leer' : 'modificar';
    const fix =
      l.backend === 'supabase'
        ? 'Cambia la policy a `USING (auth.uid() = user_id)` para que cada quien vea solo lo suyo.'
        : 'Ata el acceso al dueño: `allow ' +
          (isRead ? 'read' : 'write') +
          ': if request.auth.uid == resource.data.ownerId;` (o `== userId` si el id del documento es el uid del usuario).';
    return {
      code: isRead ? 'FUGA-IDOR-READ' : 'FUGA-IDOR-WRITE',
      title: isRead
        ? 'Fuga entre usuarios: cualquiera lee los datos de otro'
        : 'Fuga entre usuarios: cualquiera modifica los datos de otro',
      severity,
      matchPath: l.collection,
      line: 0,
      methods: (isRead ? ['get'] : ['update']) as Finding['methods'],
      condition: l.rule,
      rationale:
        `La regla de "${l.collection}" exige estar autenticado, pero no comprueba que seas el DUEÑO del registro. ` +
        `Cualquier usuario con una cuenta —sin ser admin— puede ${verbo} los datos de los demás. ` +
        `Lo probamos: la cuenta "Mallory" ${isRead ? 'leyó' : 'modificó'} el registro de otra usuaria ("Alice") ` +
        `sin ser su dueña.` +
        (l.piiFields.length ? ` Quedan expuestos datos personales: ${l.piiFields.join(', ')}.` : ''),
      recommendation: fix,
      proven: true,
      collection: l.collection,
      piiFields: l.piiFields,
    };
  });
}
