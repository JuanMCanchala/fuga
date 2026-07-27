/**
 * RAG ligero sobre el código cliente. En vez de embeddings pesados, hace
 * "retrieval" dirigido: extrae de los fuentes React/JS/TS las colecciones de
 * Firestore que la app usa y los campos que lee/escribe. Con eso construye un
 * SchemaModel que da contexto de dominio al análisis de reglas: las reglas
 * solas no dicen qué datos hay detrás; el código sí.
 */

import { CollectionInfo, FieldInfo, SchemaModel, classifyFieldByLexicon, collectionSensitivity } from './schema';

export interface IndexInput {
  /** path relativo o nombre del archivo (para trazabilidad). */
  file: string;
  content: string;
}

// collection(db, 'name') | collection('name') | .collection('name') | doc(db,'name',...)
const COLLECTION_RE =
  /\b(?:collection|collectionGroup)\s*\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?['"`]([A-Za-z0-9_\-]+)['"`]/g;
const DOTCOLLECTION_RE = /\.collection\s*\(\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;
const DOC_RE = /\bdoc\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;

// Campos: where('f', ...), orderBy('f'), y claves de objetos en set/add/updateDoc.
const WHERE_RE = /\b(?:where|orderBy)\s*\(\s*['"`]([A-Za-z0-9_\-.]+)['"`]/g;
const WRITE_CALL_RE = /\b(?:setDoc|addDoc|updateDoc)\s*\([^,]*,\s*\{([^}]*)\}/gs;

/**
 * Extrae nombres de campo del cuerpo de un objeto literal. Soporta tanto la
 * forma `clave: valor` como la abreviada `{ clave1, clave2 }` (shorthand), que
 * es muy común en JS moderno. Toma el primer identificador de cada segmento
 * separado por comas.
 */
function extractObjectKeys(body: string): string[] {
  const keys: string[] = [];
  for (const seg of body.split(',')) {
    const m = seg.match(/^\s*([A-Za-z_$][\w$]*)/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

function collectMatches(re: RegExp, text: string, group = 1): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) {
    out.push(m[group]);
  }
  return out;
}

export function indexClientCode(inputs: IndexInput[]): SchemaModel {
  const collections = new Set<string>();
  const fields = new Set<string>();

  for (const { content } of inputs) {
    for (const c of collectMatches(COLLECTION_RE, content)) collections.add(c);
    for (const c of collectMatches(DOTCOLLECTION_RE, content)) collections.add(c);
    for (const c of collectMatches(DOC_RE, content)) collections.add(c);

    for (const f of collectMatches(WHERE_RE, content)) fields.add(f.split('.')[0]);

    // Claves de objetos escritos a Firestore (soporta `clave: valor` y shorthand).
    let wm: RegExpExecArray | null;
    WRITE_CALL_RE.lastIndex = 0;
    while ((wm = WRITE_CALL_RE.exec(content)) !== null) {
      for (const k of extractObjectKeys(wm[1])) fields.add(k);
    }
  }

  // Clasifica el pool global de campos por léxico.
  const classified: FieldInfo[] = [...fields].map((name) => {
    const category = classifyFieldByLexicon(name);
    return { name, pii: category !== 'ninguno', category, source: 'lexico' };
  });
  const piiFields = classified.filter((f) => f.pii);

  const model: SchemaModel = { collections: {} };
  for (const name of collections) {
    const byName = collectionSensitivity(name);
    const info: CollectionInfo = {
      name,
      // Adjuntamos el pool de campos PII detectado (heurística de enriquecimiento).
      fields: piiFields,
      sensitiveByName: byName !== 'ninguno',
    };
    model.collections[name] = info;
  }

  return model;
}
