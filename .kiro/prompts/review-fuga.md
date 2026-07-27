# Orquestación: auditoría crítica de FUGA por Kiro

Actúa como auditor senior de seguridad y calidad. Haz una revisión crítica y
HONESTA del proyecto FUGA (agente de seguridad de reglas de Firestore) en este
repositorio, buscando puntos débiles, bugs, edge cases y áreas de mejora. NO
cambies código fuente; produce un reporte en `docs/kiro-review.md`. El objetivo
es mejorar, no felicitar: sé específico y menciona archivo:línea o el caso de
prueba concreto.

## Fase 1 — Revisión de código (leer y analizar)
Lee y analiza:
- `packages/core/src/rules/parser.ts` y `evaluator.ts`
- `packages/core/src/scan/analyzer.ts`
- `packages/core/src/rag/indexer.ts`, `schema.ts`, `pii.ts`
- `packages/core/src/prove/attacker.ts`, `fix/harden.ts`, `llm/provider.ts`
- `apps/web/app/api/analyze/route.ts` (validación de entrada, límites, seguridad)

Busca: bugs de correctitud, suposiciones frágiles, manejo de errores, riesgos de
seguridad (validación de entrada, tamaño, abuso de la API), y calidad/DX.

## Fase 2 — Pruebas de estrés del oráculo (EJECUTAR)
Crea archivos de reglas de prueba (por ejemplo en `docs/review-cases/`) y corre
sobre cada uno:
`node packages/cli/dist/index.js scan --rules <archivo> --json` y también `prove`.
Prueba al menos estos patrones y anota si FUGA los maneja BIEN, los marca
INDETERMINATE, o se EQUIVOCA (falso positivo/negativo):
  a) Auth por función auxiliar: `function signedIn(){ return request.auth != null; } ... allow read: if signedIn();`
  b) Rol por get(): `allow write: if get(/databases/$(database)/documents/roles/$(request.auth.uid)).data.admin == true;`
  c) list vs get: `allow get: if true; allow list: if false;`
  d) Comprobación de tipo: `allow create: if request.resource.data.nombre is string;`
  e) Regla YA segura por dueño (NO debe reportar fuga): `allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;`
  f) Pertenencia: `allow read: if request.auth.uid in resource.data.members;`

Reporta la tasa de INDETERMINATE y cualquier falso positivo o falso negativo que
detectes. Estas son las limitaciones reales del evaluador portátil.

## Fase 3 — Web / UX
Revisa `apps/web/public/site.html`: accesibilidad (contraste, labels de los
textarea, aria, foco), diseño responsive, y rendimiento del canvas del hero.

## Reporte: `docs/kiro-review.md` (en español)
Agrupa los hallazgos en secciones: Correctitud, Seguridad, Robustez/Edge-cases,
RAG/Heurísticas, Web/UX, DX/Tooling. Cada hallazgo con: severidad
(crítico/alto/medio/bajo), evidencia (archivo:línea o caso de prueba con el
verdict observado) y recomendación concreta. Encabeza indicando que la auditoría
la ejecutó Kiro CLI. Termina con una sección "Top 5 mejoras priorizadas".
