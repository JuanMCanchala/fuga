/**
 * Servidor MCP de FUGA. Expone el motor como herramientas que cualquier agente
 * compatible (Kiro, Claude Desktop, Cursor) puede invocar a media conversación.
 * Multi-backend (Firestore / Realtime Database / Supabase) y consciente de la
 * FUGA ENTRE USUARIOS (IDOR), que es el diferenciador:
 *
 *   fuga_scan   -> hallazgos con severidad (incluye fugas entre usuarios)
 *   fuga_prove  -> lanza los atacantes y devuelve los datos exfiltrables
 *   fuga_fix    -> reglas endurecidas + tests, validadas por el evaluador
 *   fuga_audit  -> el loop completo scan -> prove -> fix -> verify en una llamada
 *
 * Uso típico en un agente: "revisa la seguridad de estas reglas" -> el agente
 * llama fuga_audit, ve las fugas reales (incluida la de entre usuarios), aplica
 * el fix y confirma que el atacante queda bloqueado.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  runFuga,
  detectBackend,
  crossTenantFindings,
  proveCrossTenantFirestore,
  proveCrossTenantSupabase,
  parseRules,
  analyze,
  prove,
  parseRtdbRules,
  analyzeRtdb,
  proveRtdb,
  rtdbCollections,
  parseSupabase,
  analyzeSupabase,
  proveSupabase,
  indexClientCode,
  synthSeed,
  synthSeedFor,
  type SeededDb,
  type IndexInput,
  type TenantLeak,
} from '@fuga/core';

function buildSchema(codeFiles?: { file: string; content: string }[]) {
  const inputs: IndexInput[] = codeFiles ?? [];
  return indexClientCode(inputs);
}

/** Colecciones de nivel superior a partir de los match de Firestore. */
function firestoreCollections(rules: string): string[] {
  const set = new Set<string>();
  const re = /match\s+\/([A-Za-z0-9_-]+)\//g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rules)) !== null) if (m[1] !== 'databases') set.add(m[1]);
  return [...set];
}

/** Scan multi-backend SIN LLM, con las fugas entre usuarios ya fundidas. */
function scanMultibackend(rules: string, schema: ReturnType<typeof buildSchema>) {
  const backend = detectBackend(rules);
  let scan;
  let tenantLeaks: TenantLeak[] = [];
  if (backend === 'supabase') {
    const s = parseSupabase(rules);
    scan = analyzeSupabase(s, schema);
    tenantLeaks = proveCrossTenantSupabase(s, schema).leaks;
  } else if (backend === 'rtdb') {
    const a = parseRtdbRules(rules);
    scan = analyzeRtdb(a, schema);
  } else {
    const a = parseRules(rules);
    scan = analyze(a, { schema });
    tenantLeaks = proveCrossTenantFirestore(a, schema).leaks;
  }
  if (tenantLeaks.length) {
    scan.findings = [...crossTenantFindings({ leaks: tenantLeaks, clean: false }), ...scan.findings];
  }
  return { backend, scan, crossTenant: tenantLeaks };
}

/** Prove multi-backend con las fugas entre usuarios incluidas. */
function proveMultibackend(rules: string, schema: ReturnType<typeof buildSchema>, seed?: SeededDb) {
  const backend = detectBackend(rules);
  if (backend === 'supabase') {
    const s = parseSupabase(rules);
    const targets = [...s.tables.keys()];
    const db = seed ?? synthSeedFor(targets, schema);
    const exploit = proveSupabase(s, db);
    return { backend, exploit, crossTenant: proveCrossTenantSupabase(s, schema).leaks };
  }
  if (backend === 'rtdb') {
    const a = parseRtdbRules(rules);
    const db = seed ?? synthSeedFor(rtdbCollections(a), schema);
    return { backend, exploit: proveRtdb(a, db), crossTenant: [] };
  }
  const a = parseRules(rules);
  const codeCols = Object.keys(schema.collections);
  const db = seed ?? (codeCols.length ? synthSeed(schema) : synthSeedFor(firestoreCollections(rules), schema));
  const exploit = prove(a, { db, schema });
  return { backend, exploit, crossTenant: proveCrossTenantFirestore(a, schema).leaks };
}

const CODE_FILES = z
  .array(z.object({ file: z.string(), content: z.string() }))
  .optional()
  .describe('Archivos de código cliente para inferir esquema y PII (RAG)');

export function createServer(): McpServer {
  const server = new McpServer({ name: 'fuga', version: '0.2.0' });

  server.tool(
    'fuga_scan',
    'Analiza reglas de Firestore, Realtime Database o Supabase (auto-detecta) y devuelve hallazgos con severidad y puntaje de riesgo. Incluye la FUGA ENTRE USUARIOS (IDOR): reglas que exigen login pero no comprueban el dueño. Cada hallazgo "proven" está confirmado por el evaluador.',
    {
      rules: z.string().describe('Contenido de las reglas (firestore.rules, JSON de RTDB o SQL de políticas Supabase)'),
      codeFiles: CODE_FILES,
    },
    async ({ rules, codeFiles }) => {
      const schema = buildSchema(codeFiles);
      const { backend, scan, crossTenant } = scanMultibackend(rules, schema);
      return { content: [{ type: 'text', text: JSON.stringify({ backend, ...scan, crossTenant }, null, 2) }] };
    },
  );

  server.tool(
    'fuga_prove',
    'Lanza los atacantes contra las reglas y devuelve las fugas PROBADAS con los documentos exfiltrables. Prueba dos cosas: (1) atacante anónimo, y (2) la FUGA ENTRE USUARIOS — una segunda cuenta ("Mallory") accediendo a los datos de otra ("Alice"). Es una demostración, no una advertencia.',
    {
      rules: z.string().describe('Contenido de las reglas'),
      seed: z
        .record(z.record(z.any()))
        .optional()
        .describe('Datos sembrados: { "/coleccion/doc": {campo: valor} }'),
      codeFiles: CODE_FILES,
    },
    async ({ rules, seed, codeFiles }) => {
      const schema = buildSchema(codeFiles);
      const { backend, exploit, crossTenant } = proveMultibackend(rules, schema, seed as SeededDb | undefined);
      return { content: [{ type: 'text', text: JSON.stringify({ backend, exploit, crossTenant }, null, 2) }] };
    },
  );

  server.tool(
    'fuga_fix',
    'Genera reglas endurecidas (mínimo privilegio, acotadas al dueño para cerrar la fuga entre usuarios) + tests de regresión. Usa un LLM si hay disponible y VALIDA el resultado re-lanzando los atacantes; si no pasa, cae a una plantilla segura.',
    {
      rules: z.string().describe('Reglas inseguras actuales'),
      code: z.string().optional().describe('Código cliente (texto) para inferir esquema/PII'),
    },
    async ({ rules, code }) => {
      const result = await runFuga({ rules, code });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ backend: result.backend, fix: result.fix, verify: result.verify }, null, 2),
          },
        ],
      };
    },
  );

  server.tool(
    'fuga_audit',
    'Ejecuta el loop COMPLETO de FUGA en una sola llamada: scan -> prove -> fix -> verify, multi-backend. Devuelve un resumen legible + el reporte. Ideal como primer paso: "audita la seguridad de estas reglas".',
    {
      rules: z.string().describe('Contenido de las reglas (Firestore / RTDB / Supabase)'),
      code: z.string().optional().describe('Código cliente (texto) para inferir esquema/PII'),
    },
    async ({ rules, code }) => {
      const r = await runFuga({ rules, code });
      const proven = r.exploit.leaks.filter((l) => l.proven).length;
      const idorRead = r.crossTenant.filter((l) => l.method === 'read').length;
      const idorWrite = r.crossTenant.filter((l) => l.method === 'write').length;
      const lines = [
        `FUGA — auditoría de ${r.backend} (motor LLM: ${r.llm})`,
        `Riesgo: ${r.scan.riskScore}/100 · ${proven} fugas probadas · ${r.exploit.totalDocsExposed} documentos exfiltrables`,
        r.crossTenant.length
          ? `FUGA ENTRE USUARIOS: ${idorRead} de lectura, ${idorWrite} de escritura — un usuario cualquiera accede a datos de otro (${r.crossTenant.map((l) => l.collection).join(', ')}).`
          : `Sin fuga entre usuarios detectada.`,
        `Hallazgos: ${r.scan.findings.map((f) => f.code).join(', ') || '(ninguno)'}`,
        `Fix (${r.fix.source}) validado: ${r.fix.validated} · Verificación tras el fix: ${r.verify.clean ? 'atacantes BLOQUEADOS' : `quedan ${r.verify.remaining} fugas`}`,
      ];
      return {
        content: [
          { type: 'text', text: lines.join('\n') },
          { type: 'text', text: JSON.stringify(r, null, 2) },
        ],
      };
    },
  );

  return server;
}

export async function startMcpServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
