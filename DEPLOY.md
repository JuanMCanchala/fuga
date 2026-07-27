# Despliegue del playground

El demo en línea es la app Next.js de `apps/web`. Corre el loop completo
(scan → prove → fix → verify) con el motor portátil: **no necesita Java, ni
emulador, ni claves de LLM** para funcionar.

## Local

```bash
npm install && npm run build
npm run web          # http://localhost:3939
```

## Vercel (recomendado)

El `vercel.json` de la raíz ya deja todo configurado para el monorepo:

- **Framework:** Next.js
- **Build:** `npm run build -w @fuga/core && npm run build -w @fuga/web`
- **Output:** `apps/web/.next`

Pasos:

```bash
npm i -g vercel
vercel login
vercel --prod        # desde la raíz del repo
```

O conecta el repo en https://vercel.com/new (Root Directory = raíz del repo; el
`vercel.json` hace el resto).

### Motor LLM en producción (opcional)

Por defecto el fix usa la plantilla determinista. Para activar un LLM en la nube,
define variables de entorno en Vercel:

| Variable | Efecto |
|----------|--------|
| `FUGA_LLM=bedrock` + `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | Usa Amazon Bedrock para reescribir reglas |
| `FUGA_LLM=anthropic` + `ANTHROPIC_API_KEY` | Usa Claude API |
| (sin nada) | Plantilla determinista — el demo funciona igual |

## AWS (alternativa)

El mismo build se puede desplegar en **AWS Amplify Hosting** (Next.js SSR) o
empaquetar la API en **Lambda**. El único requisito de runtime es Node ≥ 18.
Amazon Bedrock encaja de forma nativa como motor LLM cuando se corre dentro de AWS
(usa el rol de la tarea, sin claves embebidas).
