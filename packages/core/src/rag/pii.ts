/**
 * Clasificación de PII. Arranca del léxico (determinista, offline) y, para los
 * campos que el léxico no reconoce, puede consultar un modelo LOCAL (Ollama) por
 * privacidad: nunca enviamos el esquema del usuario a la nube solo para saber si
 * "nroCuentaClabe" es sensible. El léxico siempre gobierna; el LLM solo rellena
 * huecos.
 */

import { LlmProvider } from '../llm/provider';
import { FieldInfo, PiiCategory, classifyFieldByLexicon } from './schema';

const CATEGORIES: PiiCategory[] = [
  'identidad',
  'contacto',
  'financiero',
  'credencial',
  'salud',
  'ubicacion',
  'menor',
  'ninguno',
];

export async function classifyFields(fieldNames: string[], provider?: LlmProvider): Promise<FieldInfo[]> {
  const result: FieldInfo[] = fieldNames.map((name) => {
    const category = classifyFieldByLexicon(name);
    return { name, pii: category !== 'ninguno', category, source: 'lexico' };
  });

  const unknown = result.filter((f) => f.category === 'ninguno');
  if (unknown.length === 0 || !provider || provider.name === 'none') return result;

  // Solo consultamos el modelo local para no filtrar el esquema a la nube.
  if (provider.name !== 'ollama') return result;

  try {
    const raw = await provider.complete(
      [
        {
          role: 'system',
          content:
            'Clasificas nombres de campos de una base de datos por sensibilidad de datos personales. ' +
            `Responde SOLO JSON: un objeto {campo: categoria} donde categoria ∈ ${JSON.stringify(CATEGORIES)}. ` +
            'Sin explicaciones.',
        },
        { role: 'user', content: `Campos: ${unknown.map((f) => f.name).join(', ')}` },
      ],
      { temperature: 0 },
    );
    const parsed = extractJson(raw);
    if (parsed) {
      for (const f of unknown) {
        const cat = parsed[f.name];
        if (cat && CATEGORIES.includes(cat as PiiCategory) && cat !== 'ninguno') {
          f.category = cat as PiiCategory;
          f.pii = true;
          f.source = 'llm';
        }
      }
    }
  } catch {
    // Si el modelo local falla, nos quedamos con el léxico.
  }

  return result;
}

function extractJson(text: string): Record<string, string> | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}
