# FUGA × AWS (Amazon Bedrock)

FUGA usa **Amazon Bedrock** como motor LLM en la nube para reescribir reglas
inseguras a mínimo privilegio. Todo lo que el LLM propone se **re-valida** con el
evaluador de FUGA, así que Bedrock nunca es la única fuente de verdad.

## Habilitar (una vez)

1. En la consola de Bedrock → **Model access**, habilita los modelos de
   **Anthropic (Claude)** y completa el *use case details form*.
   `https://us-east-2.console.aws.amazon.com/bedrock/home?region=us-east-2#/modelaccess`
2. Bedrock exige un **inference profile** (prefijo `us.`/`eu.`/`apac.`). Lista
   los disponibles:
   ```bash
   aws bedrock list-inference-profiles \
     --query "inferenceProfileSummaries[?contains(inferenceProfileId,'claude')].inferenceProfileId" \
     --output text
   ```

## Usar en local (CLI)

Con credenciales de `aws configure` ya presentes:

```powershell
$env:FUGA_LLM='bedrock'
$env:FUGA_BEDROCK_MODEL='us.anthropic.claude-3-haiku-20240307-v1:0'
node packages\cli\dist\index.js fix --rules examples\vulnerable-firestore\firestore.rules --code examples\vulnerable-firestore
```

El encabezado mostrará `Motor LLM: bedrock` y el fix vendrá `source: llm-validado`.

## Credenciales de mínimo privilegio (para producción / Vercel)

No uses llaves de admin. Crea un usuario/rol con SOLO `bedrock:InvokeModel`
usando la política de [`bedrock-invoke-policy.json`](./bedrock-invoke-policy.json):

```bash
aws iam create-policy --policy-name FugaBedrockInvoke --policy-document file://aws/bedrock-invoke-policy.json
# crea un usuario dedicado, adjunta la política, genera access keys y úsalas
# como AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY en el entorno de despliegue.
```

En Vercel: define `FUGA_LLM`, `AWS_REGION`, `FUGA_BEDROCK_MODEL`,
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (llaves con alcance mínimo).
