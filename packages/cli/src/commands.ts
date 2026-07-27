import { writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import {
  parseRules,
  analyze,
  prove,
  harden,
  indexClientCode,
  selectProvider,
  synthSeed,
  emulatorTestSpec,
  emulatorFirebaseJson,
  type SchemaModel,
  type SeededDb,
} from '@fuga/core';
import { c, severityTag, banner, riskBar, rule } from './render';
import { findRulesFile, readText, collectClientCode } from './fsutil';

export interface CliOptions {
  rules?: string;
  code?: string;
  seed?: string;
  write?: boolean;
  json?: boolean;
  cwd: string;
}

function loadSchema(opts: CliOptions): SchemaModel {
  const root = opts.code ?? opts.cwd;
  const inputs = collectClientCode(root);
  return indexClientCode(inputs);
}

function loadSeed(opts: CliOptions, schema: SchemaModel): SeededDb {
  if (opts.seed && existsSync(opts.seed)) {
    return JSON.parse(readText(opts.seed)) as SeededDb;
  }
  return synthSeed(schema);
}

function requireRules(opts: CliOptions): { path: string; text: string } {
  const path = findRulesFile(opts.rules, opts.cwd);
  if (!path) {
    console.error(c.red('No encontré firestore.rules. Usa --rules <ruta>.'));
    process.exit(2);
  }
  return { path, text: readText(path) };
}

// ---------------------------------------------------------------------------

export async function cmdScan(opts: CliOptions): Promise<number> {
  const { path, text } = requireRules(opts);
  const rules = parseRules(text);
  const schema = loadSchema(opts);
  const report = analyze(rules, { schema });

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
    return report.riskScore >= 40 ? 1 : 0;
  }

  console.log('\n' + banner());
  console.log(c.dim(`  reglas: ${path}   servicio: ${report.service}`));
  console.log('\n  Riesgo  ' + riskBar(report.riskScore) + '\n');
  console.log(rule());

  if (report.findings.length === 0) {
    console.log('  ' + c.green('Sin hallazgos. Las reglas no exponen acceso anónimo.'));
    return 0;
  }

  for (const f of report.findings) {
    const provenTag = f.proven ? c.red(' [PROBADO]') : c.gray(' [potencial]');
    console.log(`\n  ${severityTag(f.severity)}  ${c.bold(f.code)} ${f.title}${provenTag}`);
    console.log(`  ${c.gray('match')} ${f.matchPath}  ${c.gray('línea')} ${f.line}`);
    console.log(`  ${c.gray('condición')} ${c.yellow(f.condition)}`);
    if (f.piiFields?.length) console.log(`  ${c.gray('PII')} ${c.magenta(f.piiFields.join(', '))}`);
    console.log(`  ${f.rationale}`);
    console.log(`  ${c.cyan('→')} ${f.recommendation}`);
  }
  console.log('\n' + rule());
  console.log(
    `  ${c.bold(String(report.summary.critical))} críticos · ${report.summary.high} altos · ${report.summary.medium} medios`,
  );
  console.log(c.dim('  Siguiente: fuga prove   (demuestra la fuga con datos reales)\n'));
  return report.riskScore >= 40 ? 1 : 0;
}

export async function cmdProve(opts: CliOptions): Promise<number> {
  const { path, text } = requireRules(opts);
  const rules = parseRules(text);
  const schema = loadSchema(opts);
  const db = loadSeed(opts, schema);
  const report = prove(rules, { db, schema });

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
    return report.clean ? 0 : 1;
  }

  console.log('\n' + banner());
  console.log(c.dim(`  Simulando un atacante ANÓNIMO (no autenticado) contra ${path}\n`));

  if (report.clean) {
    console.log('  ' + c.green('✔ No se pudo probar ninguna fuga. El atacante quedó denegado.\n'));
    return 0;
  }

  for (const leak of report.leaks) {
    const verb = leak.method === 'read' ? 'LEER' : 'ESCRIBIR EN';
    console.log(`  ${c.red('✖ FUGA')}  el anónimo puede ${c.bold(verb)} ${c.cyan(leak.path)}`);
    if (leak.piiFields?.length) console.log(`         ${c.gray('PII en riesgo:')} ${c.magenta(leak.piiFields.join(', '))}`);
    if (leak.exfiltrated) {
      console.log(c.gray('         datos exfiltrados:'));
      for (const doc of leak.exfiltrated) {
        console.log('         ' + c.red(JSON.stringify(doc)));
      }
    }
    console.log('');
  }
  console.log(rule());
  console.log(
    `  ${c.red(c.bold(String(report.leaks.length) + ' fugas probadas'))} · ${report.totalDocsExposed} documentos exfiltrables`,
  );
  console.log(c.dim('  Siguiente: fuga fix   (genera reglas endurecidas y verifícalas)\n'));
  return 1;
}

export async function cmdFix(opts: CliOptions): Promise<number> {
  const { path, text } = requireRules(opts);
  const schema = loadSchema(opts);
  const collections = Object.keys(schema.collections);
  const provider = await selectProvider();

  console.log('\n' + banner());
  console.log(c.dim(`  Motor LLM: ${provider.name}   ·   colecciones: ${collections.join(', ') || '(ninguna detectada)'}\n`));

  const result = await harden({ originalRules: text, collections, schema, provider });

  const outRules = join(dirname(path), 'firestore.rules.fuga');
  const outTests = join(dirname(path), 'fuga.rules.test.mjs');

  if (opts.write) {
    if (!existsSync(path + '.bak')) copyFileSync(path, path + '.bak');
    writeFileSync(path, result.rules, 'utf8');
    writeFileSync(outTests, result.tests, 'utf8');
    console.log(`  ${c.green('✔')} Reglas endurecidas escritas en ${c.bold(path)} (backup en ${path}.bak)`);
    console.log(`  ${c.green('✔')} Tests de regresión en ${c.bold(outTests)}`);
  } else {
    writeFileSync(outRules, result.rules, 'utf8');
    writeFileSync(outTests, result.tests, 'utf8');
    console.log(`  ${c.green('✔')} Propuesta en ${c.bold(outRules)}   (usa --write para reemplazar el original)`);
    console.log(`  ${c.green('✔')} Tests de regresión en ${c.bold(outTests)}`);
  }

  console.log(`\n  Origen del fix: ${c.cyan(result.source)}   validado: ${result.validated ? c.green('sí') : c.red('no')}`);
  console.log(c.dim('\n' + result.explanation.split('\n').map((l) => '  ' + l).join('\n')) + '\n');
  console.log(c.dim('  Siguiente: fuga verify --rules ' + (opts.write ? path : outRules) + '\n'));
  return result.validated ? 0 : 1;
}

export async function cmdVerify(opts: CliOptions): Promise<number> {
  const { path, text } = requireRules(opts);
  const rules = parseRules(text);
  const schema = loadSchema(opts);
  const db = loadSeed(opts, schema);
  const report = prove(rules, { db, schema });

  console.log('\n' + banner());
  console.log(c.dim(`  Verificando ${path} contra el atacante anónimo\n`));

  if (report.clean) {
    console.log('  ' + c.green(c.bold('✔ VERIFICADO: sin fugas. El loop está cerrado.')) + '\n');
    return 0;
  }
  console.log('  ' + c.red(c.bold(`✖ TODAVÍA HAY ${report.leaks.length} FUGA(S). El fix no está completo.`)));
  for (const leak of report.leaks) {
    console.log(`    ${c.red('·')} ${leak.method} ${leak.path}`);
  }
  console.log('');
  return 1;
}

export async function cmdEmulator(opts: CliOptions): Promise<number> {
  const { path } = requireRules(opts);
  const schema = loadSchema(opts);
  const collections = Object.keys(schema.collections);
  const specPath = join(dirname(path), 'fuga.emulator.test.mjs');
  const fbPath = join(dirname(path), 'firebase.json');

  writeFileSync(specPath, emulatorTestSpec(collections), 'utf8');
  if (!existsSync(fbPath)) writeFileSync(fbPath, emulatorFirebaseJson(), 'utf8');

  console.log('\n' + banner());
  console.log(`  ${c.green('✔')} Spec de alta fidelidad escrita en ${c.bold(specPath)}`);
  console.log(`  ${c.green('✔')} Config del emulador en ${c.bold(fbPath)}\n`);
  console.log('  Ejecútala con el motor REAL de reglas de Firebase (requiere Java 11+):');
  console.log('  ' + c.cyan('firebase emulators:exec "node fuga.emulator.test.mjs"') + '\n');
  return 0;
}

// Ejemplo vulnerable embebido (idéntico al patrón real de Kallpa).
const DEMO_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`;

export async function cmdDemo(): Promise<number> {
  const schema = indexClientCode([
    {
      file: 'demo.js',
      content:
        "collection(db,'pagos'); collection(db,'usuarios'); " +
        "addDoc(c,{email:'x',telefono:'y',ownerId:'u'}); setDoc(d,{numeroTarjeta:'z',monto:1})",
    },
  ]);
  const db: SeededDb = {
    '/pagos/p1': { ownerId: 'alice', monto: 1250000, numeroTarjeta: '4111 1111 1111 1111', cvv: '321' },
    '/usuarios/alice': { nombre: 'Alice Pérez', email: 'alice@correo.com', telefono: '+57 300 123 4567' },
  };

  console.log('\n' + banner());
  console.log(c.dim('  DEMO sobre reglas vulnerables (patrón real: allow read, write: if true)\n'));
  console.log(rule());

  const rules = parseRules(DEMO_RULES);
  const report = analyze(rules, { schema });
  console.log('\n  1) SCAN   riesgo ' + riskBar(report.riskScore));
  for (const f of report.findings) console.log(`       ${severityTag(f.severity)} ${f.code} ${f.title}`);

  const ex = prove(rules, { db, schema });
  console.log('\n  2) PROVE  ' + c.red(`${ex.leaks.length} fugas, ${ex.totalDocsExposed} documentos exfiltrables`));
  for (const l of ex.leaks.filter((x) => x.exfiltrated)) {
    console.log('       ' + c.red(JSON.stringify(l.exfiltrated?.[0])));
  }

  const provider = await selectProvider();
  const fix = await harden({ originalRules: DEMO_RULES, collections: ['pagos', 'usuarios'], schema, provider });
  console.log(`\n  3) FIX    reglas endurecidas (${fix.source})`);

  const ex2 = prove(parseRules(fix.rules), { db, schema });
  console.log('\n  4) VERIFY ' + (ex2.clean ? c.green(c.bold('✔ fuga eliminada y verificada')) : c.red('todavía hay fuga')));
  console.log('\n' + rule() + '\n');
  return 0;
}
