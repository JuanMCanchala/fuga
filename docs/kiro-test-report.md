# Reporte de pruebas FUGA — Generado por Kiro CLI

**Fecha:** 2026-07-26  
**Generado por:** Kiro CLI ejecutando FUGA sobre `examples/vulnerable-firestore/`

---

## 1. Tests unitarios (`@fuga/core`)

| Resultado | Cantidad |
|-----------|----------|
| Total     | 10       |
| Pasan     | 10       |
| Fallan    | 0        |

**Todos los tests pasan.** Cubren: parser, evaluador, análisis estático, atacante, loop de fix y clasificación RAG/PII.

---

## 2. SCAN — Análisis estático

**Puntaje de riesgo: 100 / 100**

| Código | Severidad | Título |
|--------|-----------|--------|
| FUGA002 | CRÍTICO | Escritura pública sin restricciones |
| FUGA004 | CRÍTICO | Comodín recursivo con acceso global |
| FUGA003 | ALTO | Lectura pública sin restricciones |

Resumen: 2 hallazgos críticos, 1 alto. La regla `allow read, write: if true` sobre `/{document=**}` deja toda la base de datos expuesta.

---

## 3. PROVE — Ataque anónimo demostrado

| Métrica | Valor |
|---------|-------|
| Fugas probadas (leaks) | 6 |
| Documentos exfiltrables | 3 |
| Colecciones afectadas | usuarios, pagos, mensajes |

### Ejemplo de datos exfiltrados

**Colección `pagos`** — lectura anónima concedida:

```json
{
  "ownerId": "alice",
  "monto": 1250000,
  "numeroTarjeta": "4111 1111 1111 1111",
  "cvv": "321"
}
```

**Colección `usuarios`** — lectura anónima concedida:

```json
{
  "ownerId": "alice",
  "nombre": "Alice Pérez",
  "email": "alice@correo.com",
  "telefono": "+57 300 123 4567",
  "cedula": "1.032.456.789"
}
```

**Colección `mensajes`** — lectura anónima concedida:

```json
{
  "ownerId": "alice",
  "de": "alice@correo.com",
  "para": "bob@correo.com",
  "texto": "Te presto los 2 millones, mi cuenta es 0021-3456-7890"
}
```

Campos PII detectados: `numeroTarjeta`, `cvv`, `nombre`, `email`, `telefono`, `cedula`.

---

## 4. FIX — Reglas endurecidas

FUGA generó reglas de mínimo privilegio (motor: plantilla determinista, sin LLM) y las validó automáticamente contra el atacante anónimo.

Estrategia aplicada:
- Denegar por defecto: `match /{document=**}` con `allow read, write: if false`.
- Cada colección (`pagos`, `usuarios`, `mensajes`) se abre solo a usuarios autenticados y dueños del documento (campo `ownerId`).

Archivo generado: `examples/vulnerable-firestore/firestore.rules.fuga`

---

## 5. VERIFY — Verificación post-fix

```
✔ VERIFICADO: sin fugas. El loop está cerrado.
```

El mismo atacante anónimo que previamente exfiltró 3 documentos ahora recibe **DENY** en todas las colecciones. La fuga fue eliminada y verificada.

---

## Resumen

| Paso | Resultado |
|------|-----------|
| Tests unitarios | ✔ 10/10 pasan |
| SCAN | Riesgo 100/100 — 2 críticos, 1 alto |
| PROVE | 6 fugas, 3 documentos exfiltrados (PII financiera y personal) |
| FIX | Reglas de mínimo privilegio generadas y auto-validadas |
| VERIFY | ✔ Sin fugas — loop cerrado |

**Conclusión:** FUGA detectó, demostró con datos reales y reparó una configuración completamente abierta de Firestore en un flujo automatizado de cuatro pasos. Tras el fix, el atacante anónimo queda denegado en todas las colecciones — el loop de seguridad está cerrado.
