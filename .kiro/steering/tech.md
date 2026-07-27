---
inclusion: always
---

# Stack técnico — FUGA

## Lenguaje y runtime
- TypeScript sobre Node.js ≥ 18 (fetch nativo, `node:test`).
- Monorepo con npm workspaces.

## Paquetes
- `@fuga/core` — parser + evaluador de reglas, análisis estático, RAG de
  esquema/PII, atacante, generador de fix. **Cero dependencias en runtime.**
- `@fuga/cli` — binario `fuga` (scan/prove/fix/verify/emulator/demo/mcp).
- `@fuga/mcp` — servidor MCP (`@modelcontextprotocol/sdk`).
- `@fuga/web` — playground Next.js 14 (el demo en línea).

## Decisiones clave
- **Evaluador de reglas propio en TS**: para tener un oráculo portátil sin Java.
  El emulador oficial de Firebase (motor real, requiere Java 11+) queda como
  verificación cruzada opcional de alta fidelidad.
- **LLM pluggable, nunca autoritativo**: el LLM *propone* reglas/explicaciones;
  el evaluador las *valida*. Orden: Amazon Bedrock (nube/AWS) → Ollama (local,
  privacidad) → Anthropic → fallback determinista (plantilla). Configurable con
  `FUGA_LLM`.
- **Privacidad**: la clasificación de PII de campos desconocidos solo se delega a
  un modelo **local** (Ollama); nunca se envía el esquema a la nube para eso.

## AWS
- **Amazon Bedrock** como motor LLM en la nube (import dinámico de
  `@aws-sdk/client-bedrock-runtime`, dependencia opcional).
- Objetivo de despliegue del playground: Vercel (rápido) o AWS Amplify/App Runner.

## Pruebas
- `node:test` en `@fuga/core` cubre parser, evaluador, análisis, atacante y el
  loop de fix (auto-validación).
