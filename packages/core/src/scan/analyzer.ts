/**
 * Análisis estático de reglas. Toma el AST + (opcional) un mapa de esquema/PII
 * inferido por el RAG y produce hallazgos con severidad. La explotabilidad se
 * *confirma* con el evaluador: cada hallazgo "público" se sondea con un atacante
 * anónimo, de modo que `proven: true` significa que la fuga es demostrable, no
 * una heurística.
 */

import { Expr, Method } from '../rules/ast';
import { RulesFile } from '../rules/ast';
import { FlatAllow, listRules, probeAllow, samplePath } from '../rules/evaluator';
import { SchemaModel, sensitivityOf } from '../rag/schema';
import { Finding, ScanReport, Severity, SEVERITY_ORDER } from './types';

const READ_METHODS: Method[] = ['read', 'get', 'list'];
const WRITE_METHODS: Method[] = ['write', 'create', 'update', 'delete'];

function hasRead(methods: Method[]): boolean {
  return methods.some((m) => READ_METHODS.includes(m));
}
function hasWrite(methods: Method[]): boolean {
  return methods.some((m) => WRITE_METHODS.includes(m));
}

/** ¿La condición referencia request.auth en algún punto? (heurística). */
function referencesAuth(expr: Expr): boolean {
  switch (expr.type) {
    case 'member':
      if (expr.property === 'auth' && expr.object.type === 'ident' && expr.object.name === 'request') {
        return true;
      }
      return referencesAuth(expr.object);
    case 'index':
      return referencesAuth(expr.object) || referencesAuth(expr.index);
    case 'call':
      return referencesAuth(expr.callee) || expr.args.some(referencesAuth);
    case 'unary':
      return referencesAuth(expr.operand);
    case 'binary':
      return referencesAuth(expr.left) || referencesAuth(expr.right);
    case 'list':
      return expr.elements.some(referencesAuth);
    case 'path':
      // get(/databases/.../$(request.auth.uid)/...) referencia auth de forma
      // indirecta; el path es un string opaco, así que lo inspeccionamos.
      return expr.source.includes('request.auth');
    default:
      return false;
  }
}

/** Nombre de colección de nivel superior a partir del path del match. */
function topCollection(matchPath: string): string | undefined {
  const parts = matchPath.replace(/^\//, '').split('/').filter(Boolean);
  const first = parts.find((p) => !p.startsWith('{'));
  return first;
}

interface AnalyzeOptions {
  schema?: SchemaModel;
}

function escalateForPii(base: Severity, piiFields: string[] | undefined): Severity {
  if (piiFields && piiFields.length > 0) return 'critical';
  return base;
}

function findingsForRule(fr: FlatAllow, opts: AnalyzeOptions): Finding[] {
  const out: Finding[] = [];
  const { allow, pathSource } = fr;
  const methods = allow.methods;
  const collection = topCollection(pathSource);
  const sensitive = collection ? sensitivityOf(collection, opts.schema) : undefined;
  const piiFields = sensitive?.piiFields;

  // Sonda de atacante anónimo sobre un path de ejemplo del patrón.
  const readVerdict = hasRead(methods)
    ? probeAllow(fr, { path: samplePath(fr.segments), method: 'get', auth: null })
    : 'DENY';
  const writeVerdict = hasWrite(methods)
    ? probeAllow(fr, { path: samplePath(fr.segments), method: 'create', auth: null, data: {} })
    : 'DENY';

  const recursiveWildcard = fr.segments.some((s) => s.recursive);
  const noAuthCheck = !referencesAuth(allow.condition);

  // FUGA002: escritura pública probada.
  if (writeVerdict === 'ALLOW') {
    out.push({
      code: 'FUGA002',
      title: 'Escritura pública sin restricciones',
      severity: 'critical',
      matchPath: pathSource,
      line: allow.position.line,
      methods,
      condition: allow.conditionSource,
      rationale:
        'Cualquier persona en Internet puede crear, modificar o borrar documentos ' +
        (recursiveWildcard ? 'en toda la base de datos' : `en "${collection ?? pathSource}"`) +
        ' sin autenticarse. Permite sabotaje, inyección de datos y borrado masivo.',
      recommendation:
        'Exigir autenticación y propiedad: `allow write: if request.auth != null && request.auth.uid == resource.data.ownerId;`',
      proven: true,
      collection,
      piiFields,
    });
  }

  // FUGA003: lectura pública probada.
  if (readVerdict === 'ALLOW') {
    out.push({
      code: 'FUGA003',
      title: piiFields?.length ? 'Fuga de datos personales (lectura pública)' : 'Lectura pública sin restricciones',
      severity: escalateForPii('high', piiFields),
      matchPath: pathSource,
      line: allow.position.line,
      methods,
      condition: allow.conditionSource,
      rationale:
        (recursiveWildcard ? 'Toda la base de datos es legible' : `La colección "${collection ?? pathSource}" es legible`) +
        ' por cualquier persona sin autenticarse.' +
        (piiFields?.length
          ? ` Se exponen campos sensibles: ${piiFields.join(', ')}. Esto es una fuga de datos personales notificable.`
          : ''),
      recommendation:
        'Restringir la lectura al dueño o a roles autorizados: `allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;`',
      proven: true,
      collection,
      piiFields,
    });
  }

  // FUGA004: comodín recursivo amplio con acceso concedido a anónimos.
  if (recursiveWildcard && (readVerdict === 'ALLOW' || writeVerdict === 'ALLOW')) {
    out.push({
      code: 'FUGA004',
      title: 'Comodín recursivo con acceso global',
      severity: 'critical',
      matchPath: pathSource,
      line: allow.position.line,
      methods,
      condition: allow.conditionSource,
      rationale:
        'El patrón `{document=**}` aplica esta regla a TODA la base de datos, incluidas colecciones ' +
        'futuras que aún no existen. Una sola regla permisiva aquí anula cualquier regla específica más segura.',
      recommendation:
        'Nunca usar `allow` amplio sobre `{document=**}`. Declarar reglas por colección con el mínimo privilegio.',
      proven: true,
      collection,
      piiFields,
    });
  }

  // FUGA005: falta verificación de auth en escritura (aunque no sea "if true").
  if (hasWrite(methods) && noAuthCheck && writeVerdict !== 'ALLOW' && allow.conditionSource !== 'false') {
    out.push({
      code: 'FUGA005',
      title: 'Escritura sin verificación de autenticación',
      severity: 'medium',
      matchPath: pathSource,
      line: allow.position.line,
      methods,
      condition: allow.conditionSource,
      rationale:
        'La condición de escritura no referencia `request.auth`. Aunque no sea trivialmente pública, ' +
        'depender solo de datos del documento para autorizar escrituras suele ser explotable.',
      recommendation: 'Añadir `request.auth != null &&` y validar propiedad del recurso.',
      proven: false,
      collection,
      piiFields,
    });
  }

  return out;
}

export function analyze(rules: RulesFile, opts: AnalyzeOptions = {}): ScanReport {
  const service = rules.services[0]?.name ?? 'desconocido';
  const isStorage = service.includes('storage');
  const flat = listRules(rules, isStorage ? 'storage' : 'firestore');

  const findings: Finding[] = [];
  for (const fr of flat) {
    findings.push(...findingsForRule(fr, opts));
  }

  // Orden: severidad desc, luego probados primero.
  findings.sort((a, b) => {
    const s = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (s !== 0) return s;
    return Number(b.proven) - Number(a.proven);
  });

  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  const riskScore = computeRisk(findings);

  return { service, version: rules.version, findings, summary, riskScore };
}

function computeRisk(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) {
    const base = SEVERITY_ORDER[f.severity] * 15; // critical=60
    score += f.proven ? base : base * 0.4;
  }
  return Math.min(100, Math.round(score));
}
