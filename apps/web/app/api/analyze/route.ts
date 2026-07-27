import { NextRequest, NextResponse } from 'next/server';
import {
  parseRules,
  analyze,
  prove,
  harden,
  indexClientCode,
  selectProvider,
  synthSeed,
  type SeededDb,
  type IndexInput,
} from '@fuga/core';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface Body {
  rules: string;
  code?: string;
  seed?: SeededDb;
}

// Límites de entrada: evitan DoS por payloads enormes (parser recursivo / regex
// del indexer sobre megabytes). Las reglas reales caben de sobra en 50 KB.
const MAX_RULES_LEN = 50_000;
const MAX_CODE_LEN = 500_000;
const MAX_SEED_ENTRIES = 200;

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Body;
    if (!body?.rules || typeof body.rules !== 'string') {
      return NextResponse.json({ error: 'Falta el campo "rules".' }, { status: 400 });
    }
    if (body.rules.length > MAX_RULES_LEN) {
      return NextResponse.json({ error: `El campo "rules" excede ${MAX_RULES_LEN} caracteres.` }, { status: 413 });
    }
    if (typeof body.code === 'string' && body.code.length > MAX_CODE_LEN) {
      return NextResponse.json({ error: `El campo "code" excede ${MAX_CODE_LEN} caracteres.` }, { status: 413 });
    }
    if (body.seed !== undefined) {
      if (typeof body.seed !== 'object' || body.seed === null || Array.isArray(body.seed)) {
        return NextResponse.json({ error: 'El campo "seed" debe ser un objeto.' }, { status: 400 });
      }
      if (Object.keys(body.seed).length > MAX_SEED_ENTRIES) {
        return NextResponse.json({ error: `"seed" excede ${MAX_SEED_ENTRIES} entradas.` }, { status: 413 });
      }
    }

    const ast = parseRules(body.rules);
    const codeInputs: IndexInput[] = body.code ? [{ file: 'cliente', content: body.code }] : [];
    const schema = indexClientCode(codeInputs);

    // Semilla: la del usuario, o una sintetizada a partir del esquema inferido.
    const collections = Object.keys(schema.collections);
    const db: SeededDb = body.seed ?? synthSeed(schema);

    const scan = analyze(ast, { schema });
    const exploit = prove(ast, { db, schema });

    const provider = await selectProvider();
    const fix = await harden({
      originalRules: body.rules,
      collections,
      schema,
      provider,
    });

    // Verify: re-lanzar el atacante contra las reglas endurecidas.
    const verify = prove(parseRules(fix.rules), { db, schema });

    return NextResponse.json({
      llm: provider.name,
      schema: { collections },
      scan,
      exploit,
      fix,
      verify: { clean: verify.clean, remaining: verify.leaks.length },
    });
  } catch (err) {
    // No exponemos stack traces ni rutas internas al cliente. El detalle solo
    // aparece fuera de producción para depurar.
    console.error('[fuga/api/analyze]', err);
    const body: { error: string; detail?: string } = { error: 'No se pudieron analizar las reglas.' };
    if (process.env.NODE_ENV !== 'production') body.detail = String(err);
    return NextResponse.json(body, { status: 500 });
  }
}
