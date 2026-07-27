# 🏥 MediCloud — Clínica vulnerable (ejemplo para FUGA)

**Escenario:** una startup de telemedicina desplegó su app con reglas de Firestore
"temporales" que nunca se endurecieron. El resultado: historias clínicas, tarjetas
de crédito y la agenda completa de pacientes quedan expuestas a cualquier persona
en Internet.

Este ejemplo demuestra el loop completo de FUGA:
**scan → prove → fix → verify** en menos de 30 segundos.

---

## Colecciones y vulnerabilidades

| Colección | Regla vulnerable | Problema | Impacto |
|-----------|-----------------|----------|---------|
| `pacientes` | `allow read: if true` | Lectura pública de historias clínicas | Fuga de datos de salud (HIPAA, Ley 1581). Cédulas, diagnósticos, tipo de sangre. |
| `pagos` | `allow read, write: if true` | Acceso público total | Tarjetas de crédito (PAN + CVV) expuestas. Cualquiera puede escribir pagos falsos. |
| `citas` | `allow list: if true` | Listado público de la agenda | Un atacante enumera todas las citas: sabe quién va al médico, cuándo y por qué. |
| `resenas` | `allow create: if request.resource.data.texto is string` | Escritura anónima sin rate-limit | Spam, inyección de contenido, manipulación de reputación. |
| `usuarios` | `allow read: if request.auth != null; allow write: if ... uid == userId` | ✅ **Segura** (requiere auth + owner) | FUGA no debe reportar fuga aquí. Sirve como control positivo. |

---

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `firestore.rules` | Las reglas vulnerables tal cual están en producción |
| `client.js` | Código cliente React que usa las colecciones (FUGA lo usa para RAG) |
| `fuga.seed.json` | Datos ficticios sembrados para el ataque de demostración |

---

## Ejecutar la demostración

Desde la raíz del monorepo (`fuga/`):

```bash
# 1. Construir (si no lo has hecho)
npm run build

# 2. Escanear: análisis estático + RAG sobre el código cliente
node packages/cli/dist/index.js scan \
  --rules examples/clinica-vulnerable/firestore.rules \
  --code  examples/clinica-vulnerable

# 3. Probar la fuga: atacante anónimo exfiltra los datos sembrados
node packages/cli/dist/index.js prove \
  --rules examples/clinica-vulnerable/firestore.rules \
  --seed  examples/clinica-vulnerable/fuga.seed.json \
  --code  examples/clinica-vulnerable

# 4. Generar fix de mínimo privilegio
node packages/cli/dist/index.js fix \
  --rules examples/clinica-vulnerable/firestore.rules \
  --code  examples/clinica-vulnerable

# 5. Verificar: el mismo atacante ahora queda DENEGADO
node packages/cli/dist/index.js verify \
  --rules firestore.rules.fuga \
  --seed  examples/clinica-vulnerable/fuga.seed.json
```

---

## Resultado esperado

### `scan`
```
Riesgo: ████████████████████ 95/100

CRÍTICO  FUGA002  Escritura pública sin restricciones (/pagos)
CRÍTICO  FUGA004  Lectura pública de datos de salud (/pacientes)
ALTO     FUGA003  Listado público de agenda médica (/citas)
MEDIO    FUGA005  Escritura anónima sin validación completa (/resenas)
```

### `prove`
```
4 fugas demostradas, 2 documentos con PII exfiltrados:

  /pacientes/p_ana → {"nombre":"Ana María Ríos Gutiérrez","cedula":"1.032.456.789",
                       "diagnostico":"Diabetes tipo 2 — control con metformina 850mg",...}

  /pagos/pg_1     → {"numeroTarjeta":"4111 1111 1111 1111","cvv":"321","monto":480000,...}
```

### `fix`
Genera `firestore.rules.fuga` con reglas de mínimo privilegio:
- `/pacientes`: solo el médico dueño (`ownerId == uid`) lee y escribe.
- `/pagos`: solo el dueño lee; escritura requiere auth + validación de campos.
- `/citas`: get y list requieren auth.
- `/resenas`: lectura pública, creación requiere auth + validación.

### `verify`
```
✔ Atacante anónimo → DENEGADO en todas las colecciones protegidas.
  Fuga eliminada y verificada.
```

---

## Licencia

MIT — datos ficticios generados para demostración. Ningún dato real.
