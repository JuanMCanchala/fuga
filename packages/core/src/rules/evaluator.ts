/**
 * Evaluador portátil de reglas Firestore (sin Java, sin emulador).
 *
 * Dada una petición de acceso concreta (path, método, estado de auth, datos),
 * decide si las reglas la CONCEDEN, la DENIEGAN, o si es INDETERMINADA (la
 * condición usa construcciones que no podemos resolver sin backend). Esto es
 * lo que permite *probar* una fuga: si un atacante no autenticado obtiene
 * ALLOW definitivo sobre una colección con PII, la fuga es real, no una
 * sospecha. Y tras el fix, el mismo atacante debe obtener DENY.
 *
 * No pretende replicar CEL al 100%. Es un oráculo conservador: ante lo que no
 * puede resolver devuelve UNKNOWN y nunca afirma un ALLOW que no pueda derivar.
 */

import {
  AllowRule,
  Expr,
  FunctionDef,
  MatchNode,
  Method,
  PathSegment,
  RulesFile,
  ServiceNode,
} from './ast';

export interface AuthState {
  uid: string;
  token?: Record<string, unknown>;
}

export interface AccessRequest {
  /** Path relativo a documents, ej "/pagos/abc" o "pagos/abc". */
  path: string;
  method: Method;
  /** null => petición NO autenticada (el atacante). */
  auth: AuthState | null;
  /** resource.data: documento existente (para read/update/delete). */
  resource?: Record<string, unknown>;
  /** request.resource.data: datos entrantes (para create/update). */
  data?: Record<string, unknown>;
  /** Almacén de documentos sembrado, para resolver get()/exists(). */
  db?: Record<string, Record<string, unknown>>;
}

export type Verdict = 'ALLOW' | 'DENY' | 'INDETERMINATE';

export interface RuleMatch {
  rule: AllowRule;
  matchPath: string;
  bindings: Record<string, string>;
  result: boolean | typeof UNKNOWN;
}

export interface Decision {
  verdict: Verdict;
  /** Reglas cuyo path casó con la petición y cómo evaluó cada condición. */
  matched: RuleMatch[];
  /** Regla concreta que concedió el acceso (si verdict === ALLOW). */
  grantedBy?: RuleMatch;
}

export const UNKNOWN = Symbol('UNKNOWN');
type Value = unknown | typeof UNKNOWN;

// ---------------------------------------------------------------------------
// Aplanado del árbol de match a reglas con path absoluto (relativo a documents)
// ---------------------------------------------------------------------------

interface FlatRule {
  segments: PathSegment[];
  pathSource: string;
  allow: AllowRule;
  functions: FunctionDef[];
}

const DOCS_PREFIX = ['databases', 'documents'];

function isDocumentsWrapper(segs: PathSegment[]): boolean {
  // /databases/{database}/documents  => literal "databases", captura, literal "documents"
  return (
    segs.length === 3 &&
    segs[0].literal &&
    segs[0].raw === DOCS_PREFIX[0] &&
    !segs[1].literal &&
    segs[2].literal &&
    segs[2].raw === DOCS_PREFIX[1]
  );
}

function flatten(node: MatchNode, prefix: PathSegment[], fns: FunctionDef[], out: FlatRule[]): void {
  const here = [...prefix, ...node.path];
  const scopedFns = [...fns, ...node.functions];
  for (const allow of node.allows) {
    out.push({
      segments: here,
      pathSource: '/' + here.map((s) => s.raw).join('/'),
      allow,
      functions: scopedFns,
    });
  }
  for (const child of node.children) {
    flatten(child, here, scopedFns, out);
  }
}

function collectRules(rules: RulesFile, service?: string): FlatRule[] {
  const out: FlatRule[] = [];
  const services = service
    ? rules.services.filter((s) => s.name.includes(service))
    : rules.services;
  for (const svc of services) {
    if (!svc.match) continue;
    collectFromService(svc, out);
  }
  return out;
}

function collectFromService(svc: ServiceNode, out: FlatRule[]): void {
  const root = svc.match!;
  // Si el match raíz es el envoltorio /databases/{db}/documents, arrancamos
  // el path relativo desde sus hijos para poder casar paths "documents-relative".
  if (isDocumentsWrapper(root.path)) {
    for (const allow of root.allows) {
      out.push({ segments: [], pathSource: '/', allow, functions: [...svc.functions, ...root.functions] });
    }
    for (const child of root.children) {
      flatten(child, [], [...svc.functions, ...root.functions], out);
    }
  } else {
    flatten(root, [], svc.functions, out);
  }
}

// ---------------------------------------------------------------------------
// Matching de path con captura de variables y comodín recursivo {x=**}
// ---------------------------------------------------------------------------

function splitPath(path: string): string[] {
  return path.replace(/^\//, '').replace(/\/$/, '').split('/').filter(Boolean);
}

function matchSegments(
  pat: PathSegment[],
  path: string[],
  bindings: Record<string, string>,
): Record<string, string> | null {
  if (pat.length === 0) {
    return path.length === 0 ? bindings : null;
  }
  const [seg, ...restPat] = pat;

  if (seg.recursive) {
    // Comodín recursivo: consume 0..N segmentos. Probamos de mayor a menor.
    for (let k = path.length; k >= 0; k--) {
      const consumed = path.slice(0, k).join('/');
      const next = matchSegments(restPat, path.slice(k), {
        ...bindings,
        ...(seg.variable ? { [seg.variable]: consumed } : {}),
      });
      if (next) return next;
    }
    return null;
  }

  if (path.length === 0) return null;

  if (seg.literal) {
    if (seg.raw !== path[0]) return null;
    return matchSegments(restPat, path.slice(1), bindings);
  }

  // Captura de un solo segmento.
  return matchSegments(restPat, path.slice(1), {
    ...bindings,
    ...(seg.variable ? { [seg.variable]: path[0] } : {}),
  });
}

function methodMatches(ruleMethods: Method[], req: Method): boolean {
  if (ruleMethods.includes(req)) return true;
  const isReadOp = req === 'get' || req === 'list' || req === 'read';
  const isWriteOp = req === 'create' || req === 'update' || req === 'delete' || req === 'write';
  if (isReadOp && ruleMethods.includes('read')) return true;
  if (isWriteOp && ruleMethods.includes('write')) return true;
  if (req === 'read' && ruleMethods.some((m) => m === 'get' || m === 'list')) return true;
  if (req === 'write' && ruleMethods.some((m) => m === 'create' || m === 'update' || m === 'delete')) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Evaluación de expresiones
// ---------------------------------------------------------------------------

interface EvalContext {
  req: AccessRequest;
  bindings: Record<string, string>;
  functions: Map<string, FunctionDef>;
  /** Variables locales (parámetros de función). */
  locals: Record<string, Value>;
}

function isUnknown(v: Value): v is typeof UNKNOWN {
  return v === UNKNOWN;
}

function buildRoot(ctx: EvalContext): Record<string, Value> {
  const { req } = ctx;
  const auth = req.auth
    ? { uid: req.auth.uid, token: req.auth.token ?? {} }
    : null;
  return {
    request: {
      auth,
      method: req.method,
      resource: { data: req.data ?? {} },
      time: Date.parse('2026-01-01T00:00:00Z'),
      path: req.path,
    },
    resource: {
      data: req.resource ?? (req.method === 'create' ? {} : UNKNOWN),
      id: splitPath(req.path).slice(-1)[0] ?? '',
    },
  };
}

function evalExpr(expr: Expr, ctx: EvalContext, root: Record<string, Value>): Value {
  switch (expr.type) {
    case 'bool':
      return expr.value;
    case 'number':
      return expr.value;
    case 'string':
      return expr.value;
    case 'null':
      return null;
    case 'list':
      return expr.elements.map((e) => evalExpr(e, ctx, root));
    case 'ident':
      return evalIdent(expr.name, ctx, root);
    case 'member':
      return evalMember(expr.object, expr.property, ctx, root);
    case 'index': {
      const obj = evalExpr(expr.object, ctx, root);
      const idx = evalExpr(expr.index, ctx, root);
      if (isUnknown(obj) || isUnknown(idx)) return UNKNOWN;
      if (obj && typeof obj === 'object') return (obj as Record<string, unknown>)[String(idx)] ?? UNKNOWN;
      return UNKNOWN;
    }
    case 'unary':
      return evalUnary(expr.op, evalExpr(expr.operand, ctx, root));
    case 'binary':
      return evalBinary(expr, ctx, root);
    case 'call':
      return evalCall(expr, ctx, root);
    case 'path':
      return { __path: expr.source };
    case 'raw':
      return UNKNOWN;
    default:
      return UNKNOWN;
  }
}

function evalIdent(name: string, ctx: EvalContext, root: Record<string, Value>): Value {
  if (name in ctx.locals) return ctx.locals[name];
  if (name in root) return root[name];
  if (name in ctx.bindings) return ctx.bindings[name];
  return UNKNOWN;
}

function evalMember(objExpr: Expr, prop: string, ctx: EvalContext, root: Record<string, Value>): Value {
  const obj = evalExpr(objExpr, ctx, root);
  if (isUnknown(obj)) return UNKNOWN;
  if (obj === null) return UNKNOWN;
  if (typeof obj === 'object') {
    const rec = obj as Record<string, unknown>;
    if (prop in rec) return rec[prop] as Value;
    return UNKNOWN;
  }
  return UNKNOWN;
}

function evalUnary(op: '!' | '-', v: Value): Value {
  if (isUnknown(v)) return UNKNOWN;
  if (op === '!') return typeof v === 'boolean' ? !v : UNKNOWN;
  return typeof v === 'number' ? -v : UNKNOWN;
}

function evalBinary(expr: { op: string; left: Expr; right: Expr }, ctx: EvalContext, root: Record<string, Value>): Value {
  const { op } = expr;

  // Cortocircuito lógico con propagación conservadora de UNKNOWN.
  if (op === '&&') {
    const l = evalExpr(expr.left, ctx, root);
    if (l === false) return false;
    const r = evalExpr(expr.right, ctx, root);
    if (r === false) return false;
    if (isUnknown(l) || isUnknown(r)) return UNKNOWN;
    return Boolean(l) && Boolean(r);
  }
  if (op === '||') {
    const l = evalExpr(expr.left, ctx, root);
    if (l === true) return true;
    const r = evalExpr(expr.right, ctx, root);
    if (r === true) return true;
    if (isUnknown(l) || isUnknown(r)) return UNKNOWN;
    return Boolean(l) || Boolean(r);
  }

  const l = evalExpr(expr.left, ctx, root);
  const r = evalExpr(expr.right, ctx, root);
  if (isUnknown(l) || isUnknown(r)) return UNKNOWN;

  switch (op) {
    case '==':
      return deepEqual(l, r);
    case '!=':
      return !deepEqual(l, r);
    case '<':
      return num(l) < num(r);
    case '<=':
      return num(l) <= num(r);
    case '>':
      return num(l) > num(r);
    case '>=':
      return num(l) >= num(r);
    case '+':
      return (num(l) as number) + (num(r) as number);
    case '-':
      return (num(l) as number) - (num(r) as number);
    case '*':
      return (num(l) as number) * (num(r) as number);
    case '/':
      return (num(l) as number) / (num(r) as number);
    case '%':
      return (num(l) as number) % (num(r) as number);
    case 'in':
      if (Array.isArray(r)) return r.some((x) => deepEqual(x, l));
      if (r && typeof r === 'object') return String(l) in (r as Record<string, unknown>);
      return UNKNOWN;
    case 'is':
      return UNKNOWN; // comprobación de tipo: no la resolvemos con certeza
    default:
      return UNKNOWN;
  }
}

function evalCall(expr: { callee: Expr; args: Expr[] }, ctx: EvalContext, root: Record<string, Value>): Value {
  // Llamada a función auxiliar definida en las reglas.
  if (expr.callee.type === 'ident') {
    const fn = ctx.functions.get(expr.callee.name);
    if (fn) {
      const args = expr.args.map((a) => evalExpr(a, ctx, root));
      const locals: Record<string, Value> = { ...ctx.locals };
      fn.params.forEach((p, i) => {
        locals[p] = args[i];
      });
      return evalExpr(fn.body, { ...ctx, locals }, root);
    }
    // Builtins reconocidos.
    const name = expr.callee.name;
    if (name === 'exists') return evalExists(expr.args[0], ctx, root);
    if (name === 'get') return evalGet(expr.args[0], ctx, root);
  }
  // getAfter/existsAfter/debug/timestamp/etc.: no resolvibles con certeza.
  return UNKNOWN;
}

function pathString(arg: Expr | undefined, ctx: EvalContext, root: Record<string, Value>): string | null {
  if (!arg) return null;
  if (arg.type === 'path') {
    // Sustituye $(var) por su binding cuando se pueda; deja el path relativo a documents.
    let src = arg.source;
    src = src.replace(/\$\(([^)]+)\)/g, (_m, inner: string) => {
      const key = inner.trim();
      if (key in ctx.bindings) return ctx.bindings[key];
      return `$(${key})`;
    });
    // Nos quedamos con la parte tras "/documents".
    const idx = src.indexOf('/documents');
    if (idx >= 0) src = src.slice(idx + '/documents'.length);
    return src;
  }
  const v = evalExpr(arg, ctx, root);
  return typeof v === 'string' ? v : null;
}

function evalExists(arg: Expr | undefined, ctx: EvalContext, root: Record<string, Value>): Value {
  const p = pathString(arg, ctx, root);
  if (p == null || !ctx.req.db) return UNKNOWN;
  return Object.prototype.hasOwnProperty.call(ctx.req.db, p);
}

function evalGet(arg: Expr | undefined, ctx: EvalContext, root: Record<string, Value>): Value {
  const p = pathString(arg, ctx, root);
  if (p == null || !ctx.req.db) return UNKNOWN;
  const doc = ctx.req.db[p];
  if (!doc) return UNKNOWN;
  return { data: doc };
}

function num(v: Value): number {
  return typeof v === 'number' ? v : NaN;
}

function deepEqual(a: Value, b: Value): boolean {
  if (a === b) return true;
  if (a === null || b === null) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a === 'object') return JSON.stringify(a) === JSON.stringify(b);
  return false;
}

// ---------------------------------------------------------------------------
// API principal
// ---------------------------------------------------------------------------

/** Lista plana de reglas allow con su path absoluto (relativo a documents). */
export interface FlatAllow {
  segments: PathSegment[];
  pathSource: string;
  allow: AllowRule;
  functions: FunctionDef[];
}

export function listRules(rules: RulesFile, service?: string): FlatAllow[] {
  return collectRules(rules, service);
}

/** Genera un path de ejemplo para un patrón, rellenando variables con "x". */
export function samplePath(segments: PathSegment[]): string {
  const parts = segments.map((s) => {
    if (s.literal) return s.raw;
    return s.recursive ? 'x/y' : 'x';
  });
  return '/' + parts.join('/');
}

/**
 * Evalúa la condición de UNA regla allow bajo una petición dada, de forma
 * aislada. Lo usa el análisis estático para sondear "¿un atacante anónimo
 * obtiene ALLOW aquí?" sin depender de que otras reglas interfieran.
 */
export function probeAllow(fr: FlatAllow, req: AccessRequest): Verdict {
  const pathSegs = splitPath(req.path);
  const bindings = matchSegments(fr.segments, pathSegs, {}) ?? sampleBindings(fr.segments);
  const fnMap = new Map<string, FunctionDef>();
  for (const f of fr.functions) fnMap.set(f.name, f);
  const ctx: EvalContext = { req, bindings, functions: fnMap, locals: {} };
  const root = buildRoot(ctx);
  const result = evalExpr(fr.allow.condition, ctx, root);
  if (isUnknown(result)) return 'INDETERMINATE';
  return result === true ? 'ALLOW' : 'DENY';
}

function sampleBindings(segments: PathSegment[]): Record<string, string> {
  const b: Record<string, string> = {};
  for (const s of segments) {
    if (!s.literal && s.variable) b[s.variable] = 'x';
  }
  return b;
}

export function evaluate(rules: RulesFile, req: AccessRequest, service?: string): Decision {
  const flat = collectRules(rules, service);
  const pathSegs = splitPath(req.path);
  const matched: RuleMatch[] = [];

  for (const fr of flat) {
    if (!methodMatches(fr.allow.methods, req.method)) continue;
    const bindings = matchSegments(fr.segments, pathSegs, {});
    if (!bindings) continue;

    const fnMap = new Map<string, FunctionDef>();
    for (const f of fr.functions) fnMap.set(f.name, f);

    const ctx: EvalContext = { req, bindings, functions: fnMap, locals: {} };
    const root = buildRoot(ctx);
    const result = evalExpr(fr.allow.condition, ctx, root);
    const normalized = isUnknown(result) ? UNKNOWN : Boolean(result);
    matched.push({ rule: fr.allow, matchPath: fr.pathSource, bindings, result: normalized });
  }

  const granted = matched.find((m) => m.result === true);
  if (granted) {
    return { verdict: 'ALLOW', matched, grantedBy: granted };
  }
  if (matched.some((m) => m.result === UNKNOWN)) {
    return { verdict: 'INDETERMINATE', matched };
  }
  return { verdict: 'DENY', matched };
}
