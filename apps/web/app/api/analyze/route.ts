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

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as Body;
    if (!body?.rules || typeof body.rules !== 'string') {
      return NextResponse.json({ error: 'Falta el campo "rules".' }, { status: 400 });
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
    return NextResponse.json(
      { error: 'No se pudieron analizar las reglas.', detail: String(err) },
      { status: 500 },
    );
  }
}
