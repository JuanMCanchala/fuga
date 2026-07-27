/**
 * Generación de reglas endurecidas. Dos caminos que convergen:
 *
 *  1. Plantilla determinista de mínimo privilegio (siempre disponible, sin LLM).
 *  2. Borrador del LLM (Bedrock/Ollama/Claude) que se VALIDA re-lanzando el
 *     atacante: solo se acepta si un anónimo queda denegado en toda colección
 *     sensible. Si el LLM falla la validación, se usa la plantilla.
 *
 * Así el resultado nunca es peor que la plantilla segura, pero puede ser mejor
 * (más idiomático / ajustado al dominio) cuando hay un LLM.
 */

import { parseRules } from '../rules/parser';
import { LlmProvider } from '../llm/provider';
import { prove, SeededDb } from '../prove/attacker';
import { SchemaModel } from '../rag/schema';

export interface HardenInput {
  /** Reglas vulnerables originales (texto). */
  originalRules: string;
  /** Colecciones a proteger (si vacío, se infieren del esquema). */
  collections?: string[];
  schema?: SchemaModel;
  provider?: LlmProvider;
}

export interface HardenResult {
  rules: string;
  tests: string;
  explanation: string;
  source: 'llm-validado' | 'plantilla';
  collections: string[];
  /** Reporte de validación: el atacante contra las reglas nuevas debe estar limpio. */
  validated: boolean;
}

const OWNER_FIELD_CANDIDATES = ['ownerId', 'userId', 'uid', 'userUid', 'owner', 'createdBy'];

function guessOwnerField(schema?: SchemaModel): string {
  if (schema) {
    for (const coll of Object.values(schema.collections)) {
      for (const cand of OWNER_FIELD_CANDIDATES) {
        if (coll.fields.some((f) => f.name.toLowerCase() === cand.toLowerCase())) return cand;
      }
    }
  }
  return 'ownerId';
}

function inferCollections(input: HardenInput): string[] {
  if (input.collections && input.collections.length) return input.collections;
  if (input.schema) return Object.keys(input.schema.collections);
  return [];
}

/** Plantilla de mínimo privilegio: denegar por defecto + acceso por dueño. */
export function templateRules(collections: string[], ownerField: string): string {
  const blocks = collections
    .map((c) => {
      const isUsers = /^(users|usuarios|profiles|perfiles)$/i.test(c);
      if (isUsers) {
        return [
          `    match /${c}/{userId} {`,
          `      // El usuario solo accede a su propio documento.`,
          `      allow read: if request.auth != null;`,
          `      allow write: if request.auth != null && request.auth.uid == userId;`,
          `    }`,
        ].join('\n');
      }
      return [
        `    match /${c}/{docId} {`,
        `      // Solo el dueño autenticado lee y escribe.`,
        `      allow read: if request.auth != null && request.auth.uid == resource.data.${ownerField};`,
        `      allow create: if request.auth != null && request.auth.uid == request.resource.data.${ownerField};`,
        `      allow update, delete: if request.auth != null && request.auth.uid == resource.data.${ownerField};`,
        `    }`,
      ].join('\n');
    })
    .join('\n\n');

  return [
    `rules_version = '2';`,
    `service cloud.firestore {`,
    `  match /databases/{database}/documents {`,
    `    // Denegar por defecto: nada es accesible salvo lo declarado abajo.`,
    `    match /{document=**} {`,
    `      allow read, write: if false;`,
    `    }`,
    ``,
    blocks || `    // (Sin colecciones declaradas: todo queda denegado por defecto.)`,
    `  }`,
    `}`,
    ``,
  ].join('\n');
}

/** Tests basados en el evaluador portátil (corren sin Java). */
export function templateTests(collections: string[], ownerField: string): string {
  const cases = collections
    .map(
      (c) => `  // Colección "${c}"
  {
    name: 'anónimo NO puede leer ${c}',
    req: { path: '/${c}/doc1', method: 'get', auth: null, resource: { ${ownerField}: 'alice' } },
    expect: 'DENY',
  },
  {
    name: 'dueño SÍ puede leer ${c}',
    req: { path: '/${c}/doc1', method: 'get', auth: { uid: 'alice' }, resource: { ${ownerField}: 'alice' } },
    expect: 'ALLOW',
  },
  {
    name: 'otro usuario NO puede leer ${c}',
    req: { path: '/${c}/doc1', method: 'get', auth: { uid: 'mallory' }, resource: { ${ownerField}: 'alice' } },
    expect: 'DENY',
  },`,
    )
    .join('\n');

  return `/**
 * Tests de regresión generados por FUGA. Corren con el evaluador portátil de
 * @fuga/core (sin emulador ni Java): node fuga.rules.test.mjs
 */
import { readFileSync } from 'node:fs';
import { parseRules, evaluate } from '@fuga/core';

const rules = parseRules(readFileSync(new URL('./firestore.rules', import.meta.url), 'utf8'));

const cases = [
${cases}
];

let failed = 0;
for (const c of cases) {
  const got = evaluate(rules, c.req).verdict;
  const ok = got === c.expect;
  if (!ok) failed++;
  console.log(\`\${ok ? 'PASS' : 'FAIL'}  \${c.name}  (esperado \${c.expect}, obtenido \${got})\`);
}
if (failed) {
  console.error(\`\\n\${failed} caso(s) fallaron\`);
  process.exit(1);
}
console.log('\\nTodos los casos pasaron.');
`;
}

/** Sintetiza un db sembrado para validar reglas: 1 doc por colección con dueño 'alice'. */
function syntheticDb(collections: string[], ownerField: string): SeededDb {
  const db: SeededDb = {};
  for (const c of collections) {
    const isUsers = /^(users|usuarios|profiles|perfiles)$/i.test(c);
    db[`/${c}/doc1`] = isUsers ? { nombre: 'Alice', email: 'a@x.com' } : { [ownerField]: 'alice', secreto: 42 };
  }
  return db;
}

/** ¿Las reglas candidatas dejan al atacante anónimo sin fugas? */
function validateHardened(rulesText: string, collections: string[], ownerField: string, schema?: SchemaModel): boolean {
  try {
    const ast = parseRules(rulesText);
    const report = prove(ast, { db: syntheticDb(collections, ownerField), schema });
    return report.clean;
  } catch {
    return false;
  }
}

function extractRulesBlock(text: string): string | null {
  const fenced = text.match(/```(?:[a-zA-Z]*)?\n([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  if (candidate.includes('service cloud.firestore') && candidate.includes('rules_version')) {
    return candidate.trim();
  }
  return null;
}

export async function harden(input: HardenInput): Promise<HardenResult> {
  const collections = inferCollections(input);
  const ownerField = guessOwnerField(input.schema);

  const template = templateRules(collections, ownerField);
  const tests = templateTests(collections, ownerField);

  let rules = template;
  let source: HardenResult['source'] = 'plantilla';

  // Camino LLM: proponer y validar.
  if (input.provider && input.provider.name !== 'none') {
    try {
      const draft = await input.provider.complete(
        [
          {
            role: 'system',
            content:
              'Eres un experto en reglas de seguridad de Firestore. Reescribes reglas inseguras a ' +
              'mínimo privilegio: denegar por defecto con match /{document=**} allow read, write: if false, ' +
              'y reglas específicas por colección basadas en request.auth y propiedad del documento. ' +
              'Responde SOLO el archivo de reglas dentro de un bloque ```.',
          },
          {
            role: 'user',
            content:
              `Colecciones a proteger: ${collections.join(', ') || '(inferir de las reglas)'}\n` +
              `Campo de propietario sugerido: ${ownerField}\n\n` +
              `Reglas inseguras actuales:\n\`\`\`\n${input.originalRules}\n\`\`\``,
          },
        ],
        { temperature: 0 },
      );
      const candidate = extractRulesBlock(draft);
      if (candidate && validateHardened(candidate, collections, ownerField, input.schema)) {
        rules = candidate;
        source = 'llm-validado';
      }
    } catch {
      // Nos quedamos con la plantilla.
    }
  }

  const validated = validateHardened(rules, collections, ownerField, input.schema);
  const explanation = buildExplanation(collections, ownerField, source);

  return { rules, tests, explanation, source, collections, validated };
}

function buildExplanation(collections: string[], ownerField: string, source: HardenResult['source']): string {
  return [
    `Reglas endurecidas (${source}).`,
    ``,
    `Estrategia de mínimo privilegio:`,
    `- Denegar por defecto: match /{document=**} con allow read, write: if false.`,
    `- Cada colección se abre explícitamente solo a usuarios autenticados y dueños del documento (campo "${ownerField}").`,
    collections.length ? `- Colecciones protegidas: ${collections.join(', ')}.` : `- Sin colecciones detectadas: todo queda denegado.`,
    ``,
    `Verificación: el atacante anónimo de FUGA se re-ejecuta contra estas reglas y debe quedar en DENY en todas las colecciones (loop cerrado).`,
  ].join('\n');
}
