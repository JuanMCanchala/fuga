/**
 * Oráculo de alta fidelidad (opcional): el emulador oficial de Firebase.
 *
 * El evaluador portátil de FUGA (rules/evaluator) es el oráculo por defecto:
 * corre en cualquier lado, sin Java, y sirve para el playground web y CI. Pero
 * la fuente de verdad definitiva es el MOTOR REAL de reglas que Google embebe en
 * el emulador. Este módulo genera una spec de @firebase/rules-unit-testing lista
 * para ejecutarse con:
 *
 *   firebase emulators:exec "node fuga.emulator.test.mjs"
 *
 * Requiere firebase-tools y Java 11+. FUGA no lo exige para funcionar; lo ofrece
 * como verificación cruzada de máxima fidelidad.
 */

export function emulatorFirebaseJson(): string {
  return JSON.stringify(
    {
      firestore: { rules: 'firestore.rules' },
      emulators: { firestore: { port: 8080 }, ui: { enabled: false } },
    },
    null,
    2,
  );
}

export function emulatorTestSpec(collections: string[], ownerField = 'ownerId'): string {
  const targets = collections.length ? collections : ['pagos', 'usuarios'];
  const cases = targets
    .map(
      (c) => `  // Colección "${c}"
  await assertFails(getDoc(doc(anon, '${c}/d1')));            // anónimo NO lee
  await assertSucceeds(getDoc(doc(alice, '${c}/d1')));        // dueño SÍ lee
  await assertFails(getDoc(doc(mallory, '${c}/d1')));         // otro NO lee`,
    )
    .join('\n\n');

  return `/**
 * Verificación de alta fidelidad con el motor REAL de reglas de Firebase.
 * Ejecutar:  firebase emulators:exec "node fuga.emulator.test.mjs"
 * Requiere: firebase-tools y Java 11+.
 */
import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} from '@firebase/rules-unit-testing';
import { doc, getDoc, setDoc } from 'firebase/firestore';
import { readFileSync } from 'node:fs';

const env = await initializeTestEnvironment({
  projectId: 'fuga-demo',
  firestore: { rules: readFileSync('firestore.rules', 'utf8'), host: '127.0.0.1', port: 8080 },
});

// Sembramos un documento de dueño 'alice' saltando las reglas.
await env.withSecurityRulesDisabled(async (ctx) => {
  const db = ctx.firestore();
${targets.map((c) => `  await setDoc(doc(db, '${c}/d1'), { ${ownerField}: 'alice', secreto: 42 });`).join('\n')}
});

const anon = env.unauthenticatedContext().firestore();
const alice = env.authenticatedContext('alice').firestore();
const mallory = env.authenticatedContext('mallory').firestore();

${cases}

await env.cleanup();
console.log('Emulador: todas las aserciones de seguridad pasaron.');
`;
}
