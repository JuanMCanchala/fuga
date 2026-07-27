# Diseño — Agente FUGA

## Arquitectura

```
                       ┌──────────────────────────────────────────┐
   firestore.rules ───▶│  Parser  →  AST de reglas                 │
   código cliente ────▶│  RAG (indexer) → SchemaModel + PII        │
                       └───────────────┬──────────────────────────┘
                                       │
             ┌─────────────────────────┼─────────────────────────┐
             ▼                         ▼                         ▼
      ┌────────────┐           ┌──────────────┐          ┌──────────────┐
      │  SCAN      │           │  PROVE       │          │  FIX         │
      │ análisis   │           │ atacante     │          │ LLM propone  │
      │ estático   │           │ anónimo      │          │ + plantilla  │
      │ + sonda    │           │ (evaluador)  │          │ (mínimo priv)│
      └─────┬──────┘           └──────┬───────┘          └──────┬───────┘
            │                         │                         │
            │                         ▼                         ▼
            │                  datos exfiltrados         reglas endurecidas
            │                                                   │
            └───────────────── VERIFY ◀─────────────────────────┘
                        (re-ejecuta el atacante: debe ser DENY)
```

## Componentes

### Oráculo de acceso (doble)
1. **Evaluador portátil en TS** (`rules/evaluator`): decide ALLOW/DENY/
   INDETERMINATE para una petición concreta. Conservador: ante lo no resoluble
   devuelve INDETERMINATE y nunca afirma un ALLOW falso. Es el oráculo por
   defecto (web, CI, sin Java).
2. **Emulador oficial de Firebase** (`prove/emulator`): genera una spec de
   `@firebase/rules-unit-testing` que corre contra el motor real de Google.
   Verificación cruzada de alta fidelidad (requiere Java 11+).

### RAG
Retrieval dirigido sobre el código cliente (regex sobre llamadas
`collection()/doc()/where()/setDoc()`), no embeddings, para inferir el esquema.
Un léxico ES/EN de colecciones y campos aporta el juicio de sensibilidad. Un
modelo local (Ollama) clasifica campos desconocidos preservando privacidad.

### LLM (proponer / disponer)
El LLM propone reglas endurecidas y explicaciones; el evaluador las valida. Si el
borrador del LLM no deja al atacante en DENY, se descarta y se usa la plantilla
determinista. Providers: Bedrock (AWS) → Ollama → Anthropic → none.

### Interfaces
- CLI `fuga` (scan/prove/fix/verify/emulator/demo/mcp).
- Servidor MCP con tools `fuga_scan`, `fuga_prove`, `fuga_fix`.
- Playground web (Next.js) que corre el loop completo en una API route.

## Decisiones y trade-offs
- **Reimplementar un subconjunto de CEL** en vez de depender del emulador: gana
  portabilidad y velocidad; cubre los patrones reales de producción y degrada a
  INDETERMINATE en lo exótico, con el emulador como red de seguridad.
- **Fix determinista por defecto**: en seguridad no se acepta que un LLM alucine
  reglas; por eso todo pasa por validación con el evaluador.
