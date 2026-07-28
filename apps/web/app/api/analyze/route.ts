import { NextRequest, NextResponse } from 'next/server';
import { runFuga, type SeededDb, type Backend } from '@fuga/core';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

interface Body {
  rules: string;
  code?: string;
  seed?: SeededDb;
  backend?: Backend;
}

// Límites de entrada: evitan DoS por payloads enormes.
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

    const result = await runFuga({
      rules: body.rules,
      code: body.code,
      seed: body.seed,
      backend: body.backend,
    });

    // Forma compatible con el command center (+ backend, targets y cross-tenant).
    return NextResponse.json({
      backend: result.backend,
      llm: result.llm,
      schema: { collections: result.targets },
      scan: result.scan,
      exploit: result.exploit,
      fix: result.fix,
      verify: result.verify,
      crossTenant: result.crossTenant,
    });
  } catch (err) {
    console.error('[fuga/api/analyze]', err);
    const body: { error: string; detail?: string } = { error: 'No se pudieron analizar las reglas.' };
    if (process.env.NODE_ENV !== 'production') body.detail = String(err);
    return NextResponse.json(body, { status: 500 });
  }
}
