import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseRules } from './rules/parser';
import { evaluate } from './rules/evaluator';
import { analyze } from './scan/analyzer';
import { prove } from './prove/attacker';
import { harden } from './fix/harden';
import { indexClientCode } from './rag/indexer';
import { synthSeed } from './prove/seed';
import { classifyFieldByLexicon, collectionSensitivity } from './rag/schema';
import { parseRtdbRules, analyzeRtdb, proveRtdb } from './rtdb/engine';
import { parseSupabase, proveSupabase } from './supabase/engine';
import { detectBackend, runFuga } from './backends';
import { proveCrossTenantFirestore, proveCrossTenantSupabase } from './prove/multitenant';

const IF_TRUE = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if true; }
  }
}`;

const OWNER = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if false; }
    match /pagos/{id} {
      allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;
      allow write: if request.auth != null && request.auth.uid == request.resource.data.ownerId;
    }
  }
}`;

test('parser: reconoce versión, servicio y match recursivo', () => {
  const ast = parseRules(IF_TRUE);
  assert.equal(ast.version, '2');
  assert.equal(ast.services[0].name, 'cloud.firestore');
});

test('evaluator: if true concede a un anónimo', () => {
  const ast = parseRules(IF_TRUE);
  const d = evaluate(ast, { path: '/pagos/x', method: 'get', auth: null });
  assert.equal(d.verdict, 'ALLOW');
});

test('evaluator: regla de dueño deniega a anónimo', () => {
  const ast = parseRules(OWNER);
  const d = evaluate(ast, { path: '/pagos/x', method: 'get', auth: null, resource: { ownerId: 'alice' } });
  assert.equal(d.verdict, 'DENY');
});

test('evaluator: regla de dueño concede al dueño y niega a otro', () => {
  const ast = parseRules(OWNER);
  const owner = evaluate(ast, {
    path: '/pagos/x',
    method: 'get',
    auth: { uid: 'alice' },
    resource: { ownerId: 'alice' },
  });
  const other = evaluate(ast, {
    path: '/pagos/x',
    method: 'get',
    auth: { uid: 'mallory' },
    resource: { ownerId: 'alice' },
  });
  assert.equal(owner.verdict, 'ALLOW');
  assert.equal(other.verdict, 'DENY');
});

test('analyzer: if true produce hallazgos críticos probados', () => {
  const report = analyze(parseRules(IF_TRUE));
  assert.equal(report.riskScore, 100);
  assert.ok(report.findings.some((f) => f.code === 'FUGA002' && f.proven));
  assert.ok(report.findings.some((f) => f.code === 'FUGA003' && f.proven));
});

test('analyzer: reglas de dueño no producen fugas públicas', () => {
  const report = analyze(parseRules(OWNER));
  assert.ok(!report.findings.some((f) => f.proven && f.severity === 'critical'));
});

test('prove: exfiltra datos sembrados con if true', () => {
  const db = { '/pagos/p1': { ownerId: 'alice', numeroTarjeta: '4111', cvv: '321' } };
  const report = prove(parseRules(IF_TRUE), { db });
  assert.equal(report.clean, false);
  assert.ok(report.totalDocsExposed >= 1);
});

test('prove: reglas de dueño resisten al atacante anónimo', () => {
  const db = { '/pagos/p1': { ownerId: 'alice', cvv: '321' } };
  const report = prove(parseRules(OWNER), { db });
  assert.equal(report.clean, true);
});

test('harden: el fix elimina la fuga y se auto-valida (loop cerrado)', async () => {
  const schema = indexClientCode([
    { file: 'a.js', content: "collection(db,'pagos'); addDoc(r,{numeroTarjeta:1,cvv:2,ownerId:3})" },
  ]);
  const result = await harden({ originalRules: IF_TRUE, collections: ['pagos'], schema });
  assert.equal(result.validated, true);
  const after = prove(parseRules(result.rules), { db: synthSeed(schema) });
  assert.equal(after.clean, true);
});

test('rag: léxico clasifica PII en ES/EN', () => {
  assert.equal(classifyFieldByLexicon('numeroTarjeta'), 'financiero');
  assert.equal(classifyFieldByLexicon('userEmail'), 'contacto');
  assert.notEqual(classifyFieldByLexicon('createdAt'), 'contacto');
  assert.notEqual(collectionSensitivity('pagos'), 'ninguno');
  assert.equal(collectionSensitivity('logs'), 'ninguno');
});

// --- Regresiones de la auditoría (Kiro) ---

test('auditoría: parser no crashea con guiones en la colección', () => {
  const src =
    "rules_version='2';service cloud.firestore{match /databases/{db}/documents{match /admin-data/{id}{allow read: if true;}}}";
  const d = evaluate(parseRules(src), { path: '/admin-data/x', method: 'get', auth: null });
  assert.equal(d.verdict, 'ALLOW');
});

test('auditoría: operador is resuelve tipos concretos', () => {
  const src =
    "rules_version='2';service cloud.firestore{match /databases/{db}/documents{match /posts/{id}{allow create: if request.resource.data.nombre is string;}}}";
  const ast = parseRules(src);
  const ok = evaluate(ast, { path: '/posts/x', method: 'create', auth: null, data: { nombre: 'hola' } });
  const bad = evaluate(ast, { path: '/posts/x', method: 'create', auth: null, data: { nombre: 123 } });
  assert.equal(ok.verdict, 'ALLOW');
  assert.equal(bad.verdict, 'DENY');
});

test('auditoría: rol vía get() no genera falso positivo FUGA005', () => {
  const src =
    "rules_version='2';service cloud.firestore{match /databases/{db}/documents{match /admin/{id}{allow write: if get(/databases/$(db)/documents/roles/$(request.auth.uid)).data.admin==true;}}}";
  const report = analyze(parseRules(src));
  assert.ok(!report.findings.some((f) => f.code === 'FUGA005'));
});

test('auditoría: prove detecta list público aunque get sea privado', () => {
  const src =
    "rules_version='2';service cloud.firestore{match /databases/{db}/documents{match /posts/{id}{allow get: if false; allow list: if true;}}}";
  const report = prove(parseRules(src), { db: { '/posts/p1': { x: 1 } } });
  assert.equal(report.clean, false);
});

// --- Multi-backend: RTDB + Supabase ---

test('rtdb: read/write público probado; reglas seguras limpias', () => {
  const vuln = parseRtdbRules(JSON.stringify({ rules: { '.read': true, '.write': true } }));
  assert.equal(analyzeRtdb(vuln).riskScore, 100);
  const ex = proveRtdb(vuln, { '/usuarios/u1': { email: 'a@x.com' } });
  assert.equal(ex.clean, false);

  const safe = parseRtdbRules(
    JSON.stringify({ rules: { '.read': false, '.write': false, usuarios: { $uid: { '.read': 'auth != null && auth.uid === $uid' } } } }),
  );
  assert.equal(analyzeRtdb(safe).riskScore, 0);
  assert.equal(proveRtdb(safe, { '/usuarios/u1': { email: 'a@x.com' } }).clean, true);
});

test('supabase: RLS off es fuga; RLS + policy de dueño es seguro', () => {
  const sql =
    'create table pagos (id uuid, user_id uuid, numeroTarjeta text);\n' +
    'create table perfiles (id uuid);\nalter table perfiles enable row level security;\n' +
    "create policy own on perfiles for select to authenticated using (auth.uid() = id);";
  const s = parseSupabase(sql);
  const ex = proveSupabase(s, { '/pagos/1': { numeroTarjeta: '4111' }, '/perfiles/1': { id: 'x' } });
  const pagos = ex.leaks.find((l) => l.collection === 'pagos' && l.method === 'read');
  const perfiles = ex.attempts.find((a) => a.collection === 'perfiles' && a.method === 'read');
  assert.ok(pagos && pagos.proven); // RLS off => fuga
  assert.equal(perfiles?.proven, false); // RLS + auth => sin fuga
});

test('detectBackend: distingue firestore, rtdb y supabase', () => {
  assert.equal(detectBackend('rules_version = "2"; service cloud.firestore {}'), 'firestore');
  assert.equal(detectBackend('{"rules":{".read":true}}'), 'rtdb');
  assert.equal(detectBackend('create table x (id uuid); alter table x enable row level security;'), 'supabase');
});

// --- Fuga ENTRE USUARIOS (IDOR / cross-tenant): el diferenciador ---

// Regla clásica de vibe coder: exige login, pero NO comprueba el dueño.
const AUTHED_NOT_OWNER = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /perfiles/{userId} {
      allow read, write: if request.auth != null;
    }
  }
}`;

// Regla correcta: acotada al dueño por el id del path.
const OWNER_SCOPED = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /perfiles/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}`;

test('cross-tenant firestore: "auth != null" es fuga entre usuarios probada', () => {
  const rep = proveCrossTenantFirestore(parseRules(AUTHED_NOT_OWNER));
  assert.equal(rep.clean, false);
  assert.ok(rep.leaks.some((l) => l.collection === 'perfiles' && l.method === 'read'));
  assert.ok(rep.leaks.some((l) => l.collection === 'perfiles' && l.method === 'write'));
});

test('cross-tenant firestore: regla acotada al dueño NO es fuga', () => {
  const rep = proveCrossTenantFirestore(parseRules(OWNER_SCOPED));
  assert.equal(rep.clean, true);
});

test('cross-tenant firestore: lo que ya es público NO se cuenta como entre-usuarios', () => {
  // if true => el anónimo ya entra; es fuga pública, no cross-tenant.
  const rep = proveCrossTenantFirestore(parseRules(IF_TRUE));
  assert.equal(rep.clean, true);
});

test('cross-tenant supabase: policy "authenticated" sin dueño es fuga entre usuarios', () => {
  const sql =
    'create table pagos (id uuid, user_id uuid, numeroTarjeta text);\n' +
    'alter table pagos enable row level security;\n' +
    "create policy p on pagos for select to authenticated using (true);";
  const rep = proveCrossTenantSupabase(parseSupabase(sql));
  assert.equal(rep.clean, false);
  assert.ok(rep.leaks.some((l) => l.collection === 'pagos' && l.method === 'read'));
});

test('cross-tenant supabase: policy con auth.uid() = user_id NO es fuga', () => {
  const sql =
    'create table pagos (id uuid, user_id uuid);\n' +
    'alter table pagos enable row level security;\n' +
    "create policy own on pagos for select to authenticated using (auth.uid() = user_id);";
  const rep = proveCrossTenantSupabase(parseSupabase(sql));
  assert.equal(rep.clean, true);
});

test('runFuga: reporta cross-tenant y el fix lo cierra (loop cerrado)', async () => {
  const res = await runFuga({ rules: AUTHED_NOT_OWNER });
  assert.ok(res.crossTenant.length >= 1, 'debe probar la fuga entre usuarios');
  assert.ok(res.scan.findings.some((f) => f.code === 'FUGA-IDOR-READ'));
  assert.equal(res.verify.clean, true, 'el fix debe cerrar también la fuga entre usuarios');
});
