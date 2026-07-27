# Estructura del repositorio — FUGA

```
fuga/
├─ packages/
│  ├─ core/                 @fuga/core — el motor (sin deps de runtime)
│  │  └─ src/
│  │     ├─ rules/          lexer + parser + AST + evaluador portátil
│  │     ├─ scan/           análisis estático -> hallazgos con severidad
│  │     ├─ rag/            indexador de código, esquema y léxico PII
│  │     ├─ prove/          atacante anónimo, seed sintético, spec emulador
│  │     ├─ fix/            generación de reglas endurecidas + tests
│  │     └─ llm/            proveedores Bedrock/Ollama/Anthropic/none
│  ├─ cli/                  @fuga/cli — binario `fuga`
│  └─ mcp/                  @fuga/mcp — servidor MCP (tools fuga_scan/prove/fix)
├─ apps/
│  └─ web/                  @fuga/web — playground Next.js (demo en línea)
├─ examples/
│  └─ vulnerable-firestore/ app de ejemplo con `if true` para probar FUGA
└─ .kiro/                   steering + specs (construido con Kiro)
```

## Convenciones
- Código y mensajes al usuario en español; identificadores en inglés/español
  según el dominio.
- El `core` no importa nada específico de Node en sus rutas puras (parser,
  evaluador) para poder correr en el navegador vía el bundler de Next.
- Todo lo que el LLM genere se re-valida con el evaluador antes de aceptarse.
