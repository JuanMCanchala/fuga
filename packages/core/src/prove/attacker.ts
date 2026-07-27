/**
 * Atacante portátil. En vez de solo advertir, *ejecuta* el ataque que haría un
 * intruso anónimo contra las reglas usando el evaluador como oráculo, y captura
 * los datos que lograría exfiltrar. Es la diferencia entre "esta regla parece
 * insegura" y "mira, aquí está el JSON de tus pagos que cualquiera puede leer".
 *
 * El mismo atacante se re-lanza tras el fix (`verify`): si sigue habiendo fugas,
 * el fix no está terminado.
 */

import { RulesFile } from '../rules/ast';
import { AccessRequest, evaluate, Verdict } from '../rules/evaluator';
import { SchemaModel, sensitivityOf } from '../rag/schema';

export interface SeededDb {
  /** path relativo a documents -> documento. Ej: { "/pagos/p1": { monto: 500 } } */
  [path: string]: Record<string, unknown>;
}

export interface ExploitAttempt {
  collection: string;
  path: string;
  method: 'read' | 'write';
  verdict: Verdict;
  proven: boolean;
  /** Documentos que el atacante lograría leer (para read probado). */
  exfiltrated?: Record<string, unknown>[];
  piiFields?: string[];
}

export interface ExploitReport {
  attempts: ExploitAttempt[];
  leaks: ExploitAttempt[];
  totalDocsExposed: number;
  /** true si NO se probó ninguna fuga (base segura o ya endurecida). */
  clean: boolean;
}

function collectionOf(path: string): string {
  return path.replace(/^\//, '').split('/')[0] ?? '';
}

/** Agrupa el db sembrado por colección de nivel superior. */
function groupByCollection(db: SeededDb): Map<string, { path: string; doc: Record<string, unknown> }[]> {
  const map = new Map<string, { path: string; doc: Record<string, unknown> }[]>();
  for (const [path, doc] of Object.entries(db)) {
    const c = collectionOf(path);
    if (!map.has(c)) map.set(c, []);
    map.get(c)!.push({ path, doc });
  }
  return map;
}

export interface ProveOptions {
  db: SeededDb;
  schema?: SchemaModel;
}

export function prove(rules: RulesFile, opts: ProveOptions): ExploitReport {
  const groups = groupByCollection(opts.db);
  const attempts: ExploitAttempt[] = [];

  for (const [collection, docs] of groups) {
    const sensitivity = sensitivityOf(collection, opts.schema);

    // --- Intento de LECTURA anónima ---
    const sample = docs[0];
    const readReq: AccessRequest = {
      path: sample.path,
      method: 'get',
      auth: null,
      resource: sample.doc,
      db: opts.db,
    };
    const readDecision = evaluate(rules, readReq);
    const readProven = readDecision.verdict === 'ALLOW';
    attempts.push({
      collection,
      path: sample.path,
      method: 'read',
      verdict: readDecision.verdict,
      proven: readProven,
      exfiltrated: readProven ? docs.map((d) => d.doc) : undefined,
      piiFields: sensitivity.piiFields,
    });

    // --- Intento de ESCRITURA anónima (inyección de documento) ---
    const writeReq: AccessRequest = {
      path: `/${collection}/fuga_poc`,
      method: 'create',
      auth: null,
      data: { fuga_poc: true, injectedBy: 'anonymous' },
      db: opts.db,
    };
    const writeDecision = evaluate(rules, writeReq);
    attempts.push({
      collection,
      path: `/${collection}/fuga_poc`,
      method: 'write',
      verdict: writeDecision.verdict,
      proven: writeDecision.verdict === 'ALLOW',
      piiFields: sensitivity.piiFields,
    });
  }

  const leaks = attempts.filter((a) => a.proven);
  const totalDocsExposed = leaks
    .filter((a) => a.method === 'read')
    .reduce((sum, a) => sum + (a.exfiltrated?.length ?? 0), 0);

  return { attempts, leaks, totalDocsExposed, clean: leaks.length === 0 };
}
