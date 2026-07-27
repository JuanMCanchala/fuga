/**
 * Tests de regresión generados por FUGA. Corren con el evaluador portátil de
 * @fuga/core (sin emulador ni Java): node fuga.rules.test.mjs
 */
import { readFileSync } from 'node:fs';
import { parseRules, evaluate } from '@fuga/core';

const rules = parseRules(readFileSync(new URL('./firestore.rules', import.meta.url), 'utf8'));

const cases = [
  // Colección "pagos"
  {
    name: 'anónimo NO puede leer pagos',
    req: { path: '/pagos/doc1', method: 'get', auth: null, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
  {
    name: 'dueño SÍ puede leer pagos',
    req: { path: '/pagos/doc1', method: 'get', auth: { uid: 'alice' }, resource: { ownerId: 'alice' } },
    expect: 'ALLOW',
  },
  {
    name: 'otro usuario NO puede leer pagos',
    req: { path: '/pagos/doc1', method: 'get', auth: { uid: 'mallory' }, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
  // Colección "usuarios"
  {
    name: 'anónimo NO puede leer usuarios',
    req: { path: '/usuarios/doc1', method: 'get', auth: null, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
  {
    name: 'dueño SÍ puede leer usuarios',
    req: { path: '/usuarios/doc1', method: 'get', auth: { uid: 'alice' }, resource: { ownerId: 'alice' } },
    expect: 'ALLOW',
  },
  {
    name: 'otro usuario NO puede leer usuarios',
    req: { path: '/usuarios/doc1', method: 'get', auth: { uid: 'mallory' }, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
  // Colección "mensajes"
  {
    name: 'anónimo NO puede leer mensajes',
    req: { path: '/mensajes/doc1', method: 'get', auth: null, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
  {
    name: 'dueño SÍ puede leer mensajes',
    req: { path: '/mensajes/doc1', method: 'get', auth: { uid: 'alice' }, resource: { ownerId: 'alice' } },
    expect: 'ALLOW',
  },
  {
    name: 'otro usuario NO puede leer mensajes',
    req: { path: '/mensajes/doc1', method: 'get', auth: { uid: 'mallory' }, resource: { ownerId: 'alice' } },
    expect: 'DENY',
  },
];

let failed = 0;
for (const c of cases) {
  const got = evaluate(rules, c.req).verdict;
  const ok = got === c.expect;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name}  (esperado ${c.expect}, obtenido ${got})`);
}
if (failed) {
  console.error(`\n${failed} caso(s) fallaron`);
  process.exit(1);
}
console.log('\nTodos los casos pasaron.');
