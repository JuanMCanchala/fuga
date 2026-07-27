/**
 * RAG ligero sobre el código cliente. En vez de embeddings pesados, hace
 * "retrieval" dirigido: extrae de los fuentes React/JS/TS las colecciones de
 * Firestore que la app usa y, POR COLECCIÓN, los campos que escribe. Con eso
 * construye un SchemaModel que da contexto de dominio al análisis de reglas: las
 * reglas solas no dicen qué datos hay detrás; el código sí, y por colección.
 */

import { CollectionInfo, FieldInfo, SchemaModel, classifyFieldByLexicon, collectionSensitivity } from './schema';

export interface IndexInput {
  /** path relativo o nombre del archivo (para trazabilidad). */
  file: string;
  content: string;
}

// Descubrimiento de colecciones (para no perder ninguna aunque no tenga writes).
const COLLECTION_RE =
  /\b(?:collection|collectionGroup)\s*\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?['"`]([A-Za-z0-9_\-]+)['"`]/g;
const DOTCOLLECTION_RE = /\.collection\s*\(\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;
const DOC_RE = /\bdoc\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;

// Asignaciones `const x = collection(db,'name')` / `= doc(collection(db,'name'))`
// / `= doc(db,'name', ...)`, para resolver refs por variable.
const VAR_COLLECTION_RE =
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:doc\s*\(\s*)?collection\s*\(\s*[^,]*,\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;
const VAR_DOC_RE =
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*doc\s*\(\s*[A-Za-z_$][\w$]*\s*,\s*['"`]([A-Za-z0-9_\-]+)['"`]/g;

// Llamada de escritura: captura el primer argumento (ref) hasta el objeto {...}.
const WRITE_RE = /\b(?:setDoc|addDoc|updateDoc)\s*\(([\s\S]*?)\{([^{}]*)\}/g;

// Dentro del ref, encuentra el nombre de colección inline.
const REF_COLLECTION_RE = /(?:collection|doc)\s*\(\s*[^,()]*,\s*['"`]([A-Za-z0-9_\-]+)['"`]/;

function collectMatches(re: RegExp, text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) out.push(m[1]);
  return out;
}

/** Extrae claves de un objeto literal (soporta `clave: valor` y shorthand). */
function extractObjectKeys(body: string): string[] {
  const keys: string[] = [];
  for (const seg of body.split(',')) {
    const m = seg.match(/^\s*([A-Za-z_$][\w$]*)/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

function toFieldInfo(names: Iterable<string>): FieldInfo[] {
  const out: FieldInfo[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) continue;
    seen.add(name);
    const category = classifyFieldByLexicon(name);
    out.push({ name, pii: category !== 'ninguno', category, source: 'lexico' });
  }
  return out;
}

export function indexClientCode(inputs: IndexInput[]): SchemaModel {
  const collections = new Set<string>();
  // Campos por colección.
  const fieldsByCollection = new Map<string, Set<string>>();
  const addField = (coll: string, field: string) => {
    collections.add(coll);
    if (!fieldsByCollection.has(coll)) fieldsByCollection.set(coll, new Set());
    fieldsByCollection.get(coll)!.add(field);
  };

  for (const { content } of inputs) {
    // 1. Descubre todas las colecciones.
    for (const c of collectMatches(COLLECTION_RE, content)) collections.add(c);
    for (const c of collectMatches(DOTCOLLECTION_RE, content)) collections.add(c);
    for (const c of collectMatches(DOC_RE, content)) collections.add(c);

    // 2. Mapa variable -> colección.
    const varMap = new Map<string, string>();
    for (const re of [VAR_COLLECTION_RE, VAR_DOC_RE]) {
      re.lastIndex = 0;
      let vm: RegExpExecArray | null;
      while ((vm = re.exec(content)) !== null) varMap.set(vm[1], vm[2]);
    }

    // 3. Asocia claves de cada escritura con SU colección.
    WRITE_RE.lastIndex = 0;
    let wm: RegExpExecArray | null;
    while ((wm = WRITE_RE.exec(content)) !== null) {
      const ref = wm[1];
      const keys = extractObjectKeys(wm[2]);
      // Colección: inline en el ref, o por variable líder.
      let coll: string | undefined;
      const inline = ref.match(REF_COLLECTION_RE);
      if (inline) {
        coll = inline[1];
      } else {
        const varLead = ref.match(/([A-Za-z_$][\w$]*)/);
        if (varLead && varMap.has(varLead[1])) coll = varMap.get(varLead[1]);
      }
      if (coll) for (const k of keys) addField(coll, k);
    }
  }

  const model: SchemaModel = { collections: {} };
  for (const name of collections) {
    const byName = collectionSensitivity(name);
    const fieldNames = fieldsByCollection.get(name) ?? new Set<string>();
    const info: CollectionInfo = {
      name,
      fields: toFieldInfo(fieldNames),
      sensitiveByName: byName !== 'ninguno',
    };
    model.collections[name] = info;
  }

  return model;
}
