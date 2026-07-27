/**
 * Servidor MCP de FUGA. Expone el motor como herramientas que cualquier agente
 * compatible (Kiro, Claude Desktop, Cursor) puede invocar a media conversación:
 *
 *   fuga_scan   -> hallazgos con severidad sobre un texto de reglas
 *   fuga_prove  -> lanza el atacante anónimo y devuelve datos exfiltrables
 *   fuga_fix    -> reglas endurecidas + tests, ya validadas por el evaluador
 *
 * Uso típico en un agente: "revisa la seguridad de estas reglas" -> el agente
 * llama fuga_prove, ve las fugas reales, llama fuga_fix, y re-verifica.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  parseRules,
  analyze,
  prove,
  harden,
  indexClientCode,
  selectProvider,
  type SeededDb,
  type IndexInput,
} from '@fuga/core';

function buildSchema(codeFiles?: { file: string; content: string }[]) {
  const inputs: IndexInput[] = codeFiles ?? [];
  return indexClientCode(inputs);
}

export function createServer(): McpServer {
  const server = new McpServer({ name: 'fuga', version: '0.1.0' });

  server.tool(
    'fuga_scan',
    'Analiza reglas de Firestore y devuelve hallazgos de seguridad con severidad y puntaje de riesgo. Cada hallazgo "proven" está confirmado por el evaluador.',
    {
      rules: z.string().describe('Contenido del archivo firestore.rules'),
      codeFiles: z
        .array(z.object({ file: z.string(), content: z.string() }))
        .optional()
        .describe('Archivos de código cliente para inferir esquema y PII (RAG)'),
    },
    async ({ rules, codeFiles }) => {
      const ast = parseRules(rules);
      const schema = buildSchema(codeFiles);
      const report = analyze(ast, { schema });
      return { content: [{ type: 'text', text: JSON.stringify(report, null, 2) }] };
    },
  );

  server.tool(
    'fuga_prove',
    'Lanza un atacante ANÓNIMO contra las reglas y devuelve las fugas probadas junto con los documentos exfiltrables. Es una demostración, no una advertencia.',
    {
      rules: z.string().describe('Contenido del archivo firestore.rules'),
      seed: z
        .record(z.record(z.any()))
        .optional()
        .describe('Datos sembrados: { "/coleccion/doc": {campo: valor} }'),
      codeFiles: z.array(z.object({ file: z.string(), content: z.string() })).optional(),
    },
    async ({ rules, seed, codeFiles }) => {
      const ast = parseRules(rules);
      const schema = buildSchema(codeFiles);
      const db: SeededDb =
        (seed as SeededDb) ??
        Object.fromEntries(
          Object.keys(schema.collections).map((c) => [`/${c}/ejemplo`, { ownerId: 'alice', dato: 'sensible' }]),
        );
      const report = prove(ast, { db, schema });
      return { content: [{ type: 'text', text: JSON.stringify(report, null, 2) }] };
    },
  );

  server.tool(
    'fuga_fix',
    'Genera reglas de Firestore endurecidas (mínimo privilegio) y tests de regresión. Usa un LLM si hay disponible y VALIDA el resultado re-lanzando el atacante; si no pasa, cae a una plantilla segura.',
    {
      rules: z.string().describe('Reglas inseguras actuales'),
      collections: z.array(z.string()).optional().describe('Colecciones a proteger'),
      codeFiles: z.array(z.object({ file: z.string(), content: z.string() })).optional(),
    },
    async ({ rules, collections, codeFiles }) => {
      const schema = buildSchema(codeFiles);
      const provider = await selectProvider();
      const cols = collections ?? Object.keys(schema.collections);
      const result = await harden({ originalRules: rules, collections: cols, schema, provider });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    },
  );

  return server;
}

export async function startMcpServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
