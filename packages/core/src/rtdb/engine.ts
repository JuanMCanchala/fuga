/**
 * Motor de FUGA para reglas de Firebase Realtime Database (RTDB).
 *
 * Las reglas de RTDB son un árbol JSON con `.read`/`.write`/`.validate` en cada
 * nodo. La regla clave: el acceso CASCADEA — si un ancestro concede `.read`,
 * todo lo de abajo es legible (no se puede revocar más profundo). El antipatrón
 * de los vibe coders es el clásico `{ "rules": { ".read": true, ".write": true } }`.
 *
 * Reutiliza los tipos de reporte de Firestore para que la UI sea uniforme. El
 * evaluador es conservador: solo afirma ALLOW cuando puede derivarlo (true, o un
 * ancestro público); ante expresiones que dependen de datos devuelve
 * INDETERMINATE, nunca un ALLOW falso.
 */

import { Finding, ScanReport, Severity, SEVERITY_ORDER } from '../scan/types';
import { ExploitAttempt, ExploitReport, SeededDb } from '../prove/attacker';
import { sensitivityOf, classifyFieldByLexicon } from '../rag/schema';
import type { SchemaModel } from '../rag/schema';

export type Verdict = 'ALLOW' | 'DENY' | 'INDETERMINATE';

interface RtdbNode {
  read?: string;
  write?: string;
  validate?: string;
  children: Map<string, RtdbNode>; // clave: segmento literal o "$var"
}

// ---------------------------------------------------------------------------
// Parseo
// ---------------------------------------------------------------------------

/** Quita comentarios //... y /* *​/ que la consola de RTDB permite. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n\r]*/g, '$1');
}

function toExpr(v: unknown): string | undefined {
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'string') return v;
  return undefined;
}

function buildNode(obj: Record<string, unknown>): RtdbNode {
  const node: RtdbNode = { children: new Map() };
  for (const [key, val] of Object.entries(obj)) {
    if (key === '.read') node.read = toExpr(val);
    else if (key === '.write') node.write = toExpr(val);
    else if (key === '.validate') node.validate = toExpr(val);
    else if (key === '.indexOn') continue;
    else if (val && typeof val === 'object' && !Array.isArray(val)) {
      node.children.set(key, buildNode(val as Record<string, unknown>));
    }
  }
  return node;
}

export interface RtdbRules {
  root: RtdbNode;
}

export function parseRtdbRules(src: string): RtdbRules {
  const parsed = JSON.parse(stripComments(src)) as Record<string, unknown>;
  const rulesObj = (parsed.rules ?? parsed) as Record<string, unknown>;
  return { root: buildNode(rulesObj) };
}

/** Nombres de nodos de primer nivel (colecciones), excluyendo capturas $var. */
export function rtdbCollections(rules: RtdbRules): string[] {
  return [...rules.root.children.keys()].filter((k) => !k.startsWith('$'));
}

// ---------------------------------------------------------------------------
// Evaluador de expresiones RTDB (subconjunto para el atacante anónimo)
// ---------------------------------------------------------------------------

const UNKNOWN = Symbol('UNKNOWN');
type Val = boolean | number | string | null | typeof UNKNOWN;

/** Evalúa una expresión de regla RTDB con auth=null (atacante anónimo). */
function evalRtdbExpr(expr: string): Verdict {
  const trimmed = expr.trim();
  if (trimmed === 'true') return 'ALLOW';
  if (trimmed === 'false') return 'DENY';
  try {
    const tokens = tokenize(trimmed);
    const p = new ExprParser(tokens);
    const v = p.parseExpr();
    if (v === true) return 'ALLOW';
    if (v === false) return 'DENY';
    return 'INDETERMINATE';
  } catch {
    return 'INDETERMINATE';
  }
}

type Tok = { t: string; v: string };

function tokenize(s: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  const two = ['===', '!==', '==', '!=', '<=', '>=', '&&', '||'];
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      let v = '';
      i++;
      while (i < s.length && s[i] !== c) v += s[i++];
      i++;
      out.push({ t: 'str', v });
      continue;
    }
    const three = s.slice(i, i + 3);
    if (three === '===' || three === '!==') {
      out.push({ t: 'op', v: three });
      i += 3;
      continue;
    }
    const twoc = s.slice(i, i + 2);
    if (two.includes(twoc)) {
      out.push({ t: 'op', v: twoc });
      i += 2;
      continue;
    }
    if ('<>!().'.includes(c)) {
      out.push({ t: c === '.' ? 'dot' : c === '(' ? 'lp' : c === ')' ? 'rp' : 'op', v: c });
      i++;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let v = '';
      while (i < s.length && /[0-9.]/.test(s[i])) v += s[i++];
      out.push({ t: 'num', v });
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let v = '';
      while (i < s.length && /[A-Za-z0-9_$]/.test(s[i])) v += s[i++];
      out.push({ t: 'id', v });
      continue;
    }
    // carácter no soportado
    out.push({ t: 'op', v: c });
    i++;
  }
  return out;
}

class ExprParser {
  private i = 0;
  constructor(private toks: Tok[]) {}
  private peek(): Tok | undefined {
    return this.toks[this.i];
  }
  private next(): Tok | undefined {
    return this.toks[this.i++];
  }

  parseExpr(): Val {
    return this.parseOr();
  }
  private parseOr(): Val {
    let l = this.parseAnd();
    while (this.peek()?.v === '||') {
      this.next();
      const r = this.parseAnd();
      if (l === true || r === true) l = true;
      else if (l === UNKNOWN || r === UNKNOWN) l = UNKNOWN;
      else l = Boolean(l) || Boolean(r);
    }
    return l;
  }
  private parseAnd(): Val {
    let l = this.parseCmp();
    while (this.peek()?.v === '&&') {
      this.next();
      const r = this.parseCmp();
      if (l === false || r === false) l = false;
      else if (l === UNKNOWN || r === UNKNOWN) l = UNKNOWN;
      else l = Boolean(l) && Boolean(r);
    }
    return l;
  }
  private parseCmp(): Val {
    let l = this.parseUnary();
    const op = this.peek()?.v;
    if (op && ['===', '!==', '==', '!=', '<', '>', '<=', '>='].includes(op)) {
      this.next();
      const r = this.parseUnary();
      if (l === UNKNOWN || r === UNKNOWN) return UNKNOWN;
      switch (op) {
        case '===':
        case '==':
          return l === r;
        case '!==':
        case '!=':
          return l !== r;
        default:
          return UNKNOWN;
      }
    }
    return l;
  }
  private parseUnary(): Val {
    if (this.peek()?.v === '!') {
      this.next();
      const v = this.parseUnary();
      if (v === UNKNOWN) return UNKNOWN;
      return !v;
    }
    return this.parsePrimary();
  }
  private parsePrimary(): Val {
    const t = this.next();
    if (!t) return UNKNOWN;
    if (t.t === 'lp') {
      const v = this.parseExpr();
      if (this.peek()?.t === 'rp') this.next();
      return v;
    }
    if (t.t === 'num') return Number(t.v);
    if (t.t === 'str') return t.v;
    if (t.t === 'id') {
      // Cadena de acceso: auth, auth.uid, data.child(...).val(), $var, null, ...
      if (t.v === 'null') return null;
      if (t.v === 'true') return true;
      if (t.v === 'false') return false;
      if (t.v === 'auth') {
        // El atacante es anónimo: auth === null. Si sigue con .algo, es acceso a
        // propiedad de null => en RTDB deniega; lo marcamos UNKNOWN salvo que sea
        // directamente comparado (auth == null lo maneja parseCmp con null).
        if (this.peek()?.t === 'dot') {
          this.skipMemberChain();
          return UNKNOWN;
        }
        return null;
      }
      // data/newData/root/now/$var u otros: no resolubles para anónimo.
      this.skipMemberChain();
      return UNKNOWN;
    }
    return UNKNOWN;
  }
  private skipMemberChain(): void {
    // Consume .foo, .child('x'), .val(), [..] hasta que no haya más cadena.
    for (;;) {
      const p = this.peek();
      if (p?.t === 'dot') {
        this.next();
        this.next(); // id del miembro
        if (this.peek()?.t === 'lp') this.skipParens();
      } else {
        break;
      }
    }
  }
  private skipParens(): void {
    let depth = 0;
    do {
      const t = this.next();
      if (t?.t === 'lp') depth++;
      else if (t?.t === 'rp') depth--;
      else if (!t) break;
    } while (depth > 0);
  }
}

// ---------------------------------------------------------------------------
// Evaluación de acceso (con cascada)
// ---------------------------------------------------------------------------

function splitPath(path: string): string[] {
  return path.replace(/^\//, '').replace(/\/$/, '').split('/').filter(Boolean);
}

/**
 * Recolecta las expresiones read/write aplicables a un path: la del nodo destino
 * y las de todos sus ancestros (por la cascada de RTDB).
 */
function collectRules(root: RtdbNode, segs: string[], kind: 'read' | 'write'): string[] {
  const exprs: string[] = [];
  let node: RtdbNode | undefined = root;
  const pushIf = (n: RtdbNode) => {
    const e = kind === 'read' ? n.read : n.write;
    if (e !== undefined) exprs.push(e);
  };
  pushIf(root);
  for (const seg of segs) {
    if (!node) break;
    let child = node.children.get(seg);
    if (!child) {
      // Prueba una captura $var.
      for (const [k, v] of node.children) {
        if (k.startsWith('$')) {
          child = v;
          break;
        }
      }
    }
    if (child) {
      pushIf(child);
      node = child;
    } else {
      node = undefined;
    }
  }
  return exprs;
}

export function evaluateRtdb(rules: RtdbRules, path: string, kind: 'read' | 'write'): Verdict {
  const segs = splitPath(path);
  const exprs = collectRules(rules.root, segs, kind);
  let sawIndet = false;
  for (const e of exprs) {
    const v = evalRtdbExpr(e);
    if (v === 'ALLOW') return 'ALLOW'; // cascada: un ancestro público concede todo
    if (v === 'INDETERMINATE') sawIndet = true;
  }
  if (exprs.length === 0) return 'DENY'; // sin regla = denegado por defecto
  return sawIndet ? 'INDETERMINATE' : 'DENY';
}

// ---------------------------------------------------------------------------
// Análisis estático (scan)
// ---------------------------------------------------------------------------

/** Recorre el árbol juntando (path, read?, write?) de cada nodo con reglas. */
function walkNodes(node: RtdbNode, prefix: string, out: { path: string; node: RtdbNode }[]): void {
  if (node.read !== undefined || node.write !== undefined) out.push({ path: prefix || '/', node });
  for (const [seg, child] of node.children) {
    walkNodes(child, prefix + '/' + seg, out);
  }
}

export function analyzeRtdb(rules: RtdbRules, schema?: SchemaModel): ScanReport {
  const nodes: { path: string; node: RtdbNode }[] = [];
  walkNodes(rules.root, '', nodes);
  const findings: Finding[] = [];

  for (const { path, node } of nodes) {
    const collection = splitPath(path)[0];
    const sensitive = collection ? sensitivityOf(collection, schema) : undefined;
    const piiFields = sensitive?.piiFields;

    if (node.read !== undefined) {
      const v = evaluateRtdb(rules, path === '/' ? '/x' : path + '/x', 'read');
      if (v === 'ALLOW' || evalRtdbExpr(node.read) === 'ALLOW') {
        findings.push({
          code: 'FUGA-RTDB-READ',
          title: piiFields?.length ? 'Fuga de datos personales (lectura pública RTDB)' : 'Lectura pública en Realtime Database',
          severity: piiFields?.length ? 'critical' : 'high',
          matchPath: path,
          line: 0,
          methods: ['read'],
          condition: node.read,
          rationale:
            `El nodo "${path}" es legible por cualquiera sin autenticarse. En RTDB esto CASCADEA: ` +
            `todo lo que cuelga de aquí queda expuesto.`,
          recommendation: 'Exigir autenticación: `".read": "auth != null && auth.uid === $uid"`.',
          proven: true,
          collection,
          piiFields,
        });
      }
    }
    if (node.write !== undefined && evalRtdbExpr(node.write) === 'ALLOW') {
      findings.push({
        code: 'FUGA-RTDB-WRITE',
        title: 'Escritura pública en Realtime Database',
        severity: 'critical',
        matchPath: path,
        line: 0,
        methods: ['write'],
        condition: node.write,
        rationale: `Cualquiera puede escribir/borrar en "${path}" sin autenticarse (y cascadea a los hijos).`,
        recommendation: 'Restringir la escritura al dueño autenticado.',
        proven: true,
        collection,
        piiFields,
      });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  const riskScore = Math.min(100, findings.reduce((s, f) => s + SEVERITY_ORDER[f.severity] * 15, 0));

  return { service: 'firebase.database', version: null, findings, summary, riskScore };
}

// ---------------------------------------------------------------------------
// Atacante (prove)
// ---------------------------------------------------------------------------

export function proveRtdb(rules: RtdbRules, db: SeededDb): ExploitReport {
  const attempts: ExploitAttempt[] = [];
  const paths = Object.keys(db);
  const grouped = new Map<string, { path: string; doc: Record<string, unknown> }[]>();
  for (const p of paths) {
    const top = splitPath(p)[0] ?? '';
    if (!grouped.has(top)) grouped.set(top, []);
    grouped.get(top)!.push({ path: p, doc: db[p] });
  }

  for (const [collection, docs] of grouped) {
    const sample = docs[0];
    // PII por documento real: campos cuyo nombre es sensible según el léxico.
    const docPii = Object.keys(sample.doc).filter((k) => classifyFieldByLexicon(k) !== 'ninguno');

    const readV = evaluateRtdb(rules, sample.path, 'read');
    const readProven = readV === 'ALLOW';
    attempts.push({
      collection,
      path: sample.path,
      method: 'read',
      verdict: readV,
      proven: readProven,
      exfiltrated: readProven ? docs.map((d) => d.doc) : undefined,
      piiFields: docPii,
    });

    const writeV = evaluateRtdb(rules, `/${collection}/fuga_poc`, 'write');
    attempts.push({
      collection,
      path: `/${collection}/fuga_poc`,
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

export function hardenRtdb(collections: string[]): { rules: string; source: string; validated: boolean } {
  const children: Record<string, unknown> = {};
  for (const c of collections) {
    const isUsers = /^(users|usuarios|perfiles|profiles)$/i.test(c);
    children[c] = isUsers
      ? { $uid: { '.read': 'auth != null && auth.uid === $uid', '.write': 'auth != null && auth.uid === $uid' } }
      : { $id: { '.read': "auth != null && auth.uid === data.child('ownerId').val()", '.write': 'auth != null && auth.uid === newData.child(\'ownerId\').val()' } };
  }
  const rulesObj = {
    rules: {
      '.read': false,
      '.write': false,
      ...children,
    },
  };
  const rules = JSON.stringify(rulesObj, null, 2);
  // Validación: denegar por defecto + auth garantizan que el anónimo no lee.
  const ast = parseRtdbRules(rules);
  let clean = true;
  for (const c of collections) {
    if (evaluateRtdb(ast, `/${c}/x`, 'read') === 'ALLOW') clean = false;
  }
  return { rules, source: 'plantilla', validated: clean };
}
