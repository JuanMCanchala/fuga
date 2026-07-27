#!/usr/bin/env node
/**
 * FUGA CLI. Uso:
 *   fuga scan     [--rules f] [--code dir] [--json]
 *   fuga prove    [--rules f] [--seed f.json] [--json]
 *   fuga fix      [--rules f] [--write]
 *   fuga verify   [--rules f] [--seed f.json]
 *   fuga demo
 *   fuga mcp                      (inicia el servidor MCP)
 */

import { cmdScan, cmdProve, cmdFix, cmdVerify, cmdDemo, cmdEmulator, type CliOptions } from './commands';
import { c } from './render';

function parseArgs(argv: string[]): { command: string; opts: CliOptions } {
  const command = argv[0] ?? 'help';
  const opts: CliOptions = { cwd: process.cwd() };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--rules') opts.rules = argv[++i];
    else if (a === '--code') opts.code = argv[++i];
    else if (a === '--seed') opts.seed = argv[++i];
    else if (a === '--write') opts.write = true;
    else if (a === '--json') opts.json = true;
  }
  return { command, opts };
}

function help(): void {
  console.log(`
${c.bold(c.magenta('FUGA'))} — detecta, PRUEBA y repara fugas de datos en reglas de Firestore.

${c.bold('Comandos')}
  ${c.cyan('scan')}     Análisis estático: qué reglas exponen acceso anónimo.
  ${c.cyan('prove')}    Lanza un atacante anónimo y captura los datos exfiltrables.
  ${c.cyan('fix')}      Genera reglas endurecidas (LLM + validación) y tests.
  ${c.cyan('verify')}   Re-lanza el atacante: confirma que ya no hay fuga.
  ${c.cyan('demo')}     Corre el loop completo sobre un ejemplo vulnerable.
  ${c.cyan('emulator')} Genera una spec de alta fidelidad para el emulador de Firebase.
  ${c.cyan('mcp')}      Inicia el servidor MCP (para Kiro/Claude/Cursor).

${c.bold('Opciones')}
  --rules <ruta>   Archivo de reglas (por defecto: ./firestore.rules)
  --code <dir>     Directorio del código cliente para el RAG (por defecto: cwd)
  --seed <json>    Datos sembrados para prove/verify
  --write          fix reemplaza el archivo original (crea .bak)
  --json           Salida en JSON

${c.dim('Motor LLM (opcional): FUGA_LLM=bedrock|ollama|anthropic|none')}
`);
}

async function main(): Promise<void> {
  const { command, opts } = parseArgs(process.argv.slice(2));
  let code = 0;
  switch (command) {
    case 'scan':
      code = await cmdScan(opts);
      break;
    case 'prove':
      code = await cmdProve(opts);
      break;
    case 'fix':
      code = await cmdFix(opts);
      break;
    case 'verify':
      code = await cmdVerify(opts);
      break;
    case 'demo':
      code = await cmdDemo();
      break;
    case 'emulator':
      code = await cmdEmulator(opts);
      break;
    case 'mcp': {
      // Import diferido: el servidor MCP vive en su propio paquete.
      try {
        const mod = '@fuga/mcp';
        const { startMcpServer } = await import(mod);
        await startMcpServer();
      } catch (err) {
        console.error(c.red('El servidor MCP no está disponible. Instala @fuga/mcp.'));
        console.error(c.dim(String(err)));
        code = 1;
      }
      break;
    }
    case 'help':
    case '--help':
    case '-h':
      help();
      break;
    default:
      console.error(c.red(`Comando desconocido: ${command}`));
      help();
      code = 2;
  }
  process.exit(code);
}

main().catch((err) => {
  console.error(c.red('Error inesperado:'), err);
  process.exit(1);
});
