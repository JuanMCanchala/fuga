# Guion del Video — FUGA

**Duración máxima:** 5:00  
**Evento:** Hackatón Código Facilito × Kiro — Reto 3: Agentes especializados  
**Proyecto:** FUGA · https://github.com/JuanMCanchala/fuga  
**Demo:** https://fuga-two.vercel.app

---

## ESCENA 1 — Hook + El problema

| | |
|---|---|
| **Tiempo** | 0:00 – 0:30 |
| **En pantalla** | Código de reglas de Firestore con `allow read, write: if true;` resaltado en rojo. Transición a una terminal que muestra un JSON con datos personales (cédula, tarjeta de crédito) accesibles sin autenticación. |
| **Narración** | «Una sola línea. Con esta línea, cualquier persona en Internet puede leer toda tu base de datos: historias clínicas, tarjetas de crédito, cédulas. Miles de apps en producción tienen exactamente esto. Los linters te dicen "parece inseguro"… y tú lo ignoras porque no ves el impacto. ¿Y si en vez de advertirte, te mostrara tus datos filtrándose en vivo?» |

---

## ESCENA 2 — Qué es FUGA y su diferencia

| | |
|---|---|
| **Tiempo** | 0:30 – 1:10 |
| **En pantalla** | Logo de FUGA. Diagrama animado del loop: SCAN → PROVE → FIX → VERIFY con flechas cíclicas. Texto en pantalla: "No advierte. Demuestra." |
| **Narración** | «FUGA es un agente especializado que no advierte sobre fugas de datos: las demuestra, las repara y lo verifica. El loop es simple: primero escanea tus reglas y calcula el riesgo. Luego lanza un atacante anónimo real y te muestra exactamente qué datos se filtran. Después genera reglas endurecidas de mínimo privilegio —un LLM propone, pero un evaluador propio valida— y finalmente re-ataca: solo acepta el fix cuando el atacante queda denegado. Prueba, no opina.» |

---

## ESCENA 3 — DEMO en vivo (Command Center – Clínica MediCloud)

| | |
|---|---|
| **Tiempo** | 1:10 – 3:00 |
| **En pantalla** | Navegador en https://fuga-two.vercel.app. Se selecciona el preset "Clínica MediCloud" en el command center. |

### 3a — SCAN (1:10 – 1:35)

| | |
|---|---|
| **En pantalla** | Click en SCAN. Aparece: riesgo 100/100, hallazgos críticos resaltados (lectura pública de historias clínicas, pagos públicos con tarjeta+CVV, list público de agenda, create anónimo). |
| **Narración** | «Cargamos el caso de MediCloud: una app de telemedicina con reglas vulnerables. El scan devuelve riesgo 100 sobre 100. Lectura pública de historias clínicas, pagos con tarjeta y CVV expuestos, agenda listable por cualquiera, y creación anónima. Pero esto todavía es solo análisis estático. Ahora viene lo que nos diferencia.» |

### 3b — PROVE (1:35 – 2:10)

| | |
|---|---|
| **En pantalla** | Click en PROVE. Aparecen en rojo los documentos exfiltrados: historia clínica de un paciente (cédula, diagnóstico) y tarjeta de crédito (número, CVV). |
| **Narración** | «PROVE lanza el atacante anónimo. Sin credenciales, sin tokens. Y aquí están los datos: la historia clínica de un paciente —su cédula, su diagnóstico— y una tarjeta de crédito completa con CVV. Esto no es una advertencia: es la prueba. Estos datos están en rojo porque son exfiltrables ahora mismo. Un atacante real haría exactamente esto.» |

### 3c — FIX (2:10 – 2:35)

| | |
|---|---|
| **En pantalla** | Click en FIX. Aparecen las reglas endurecidas generadas: cada colección con sus condiciones específicas (owner-only read en historias, authenticated write en pagos, etc.). Se resalta la diferencia con las reglas originales. |
| **Narración** | «FIX genera reglas de mínimo privilegio. Cada colección queda protegida según su contexto: las historias clínicas solo las lee su dueño, los pagos requieren autenticación, la agenda se restringe al personal. El LLM propone, pero el evaluador portátil valida: ninguna regla alucinada pasa.» |

### 3d — VERIFY (2:35 – 3:00)

| | |
|---|---|
| **En pantalla** | Click en VERIFY. El mismo atacante se re-ejecuta. Resultado: todas las peticiones quedan en DENY (verde). Mensaje: "Fuga eliminada y verificada ✔". |
| **Narración** | «Y VERIFY cierra el loop. El mismo atacante anónimo se lanza de nuevo contra las reglas endurecidas. Resultado: todo denegado. La fuga ya no existe. No lo creemos: lo probamos. Loop cerrado.» |

---

## ESCENA 4 — Cómo funciona por dentro

| | |
|---|---|
| **Tiempo** | 3:00 – 4:00 |
| **En pantalla** | Diagrama de arquitectura (del README): Parser → Evaluador → SCAN/PROVE/FIX. Se resaltan los componentes uno a uno. Código del evaluador en TypeScript. Vista del RAG infiriendo esquema desde código cliente. Logo de MCP con los tres tools. |
| **Narración** | «Por dentro, FUGA tiene cuatro piezas clave. Primero: un evaluador de reglas propio escrito en TypeScript. Es un oráculo portátil que decide ALLOW o DENY sin necesitar Java ni el emulador de Firebase. Corre en CI, en el navegador, en cualquier lado. Segundo: RAG sobre tu código cliente. Lee tus archivos, infiere qué colecciones existen y qué campos tienen. Sabe que una fuga en "pagos" con campo "numeroTarjeta" no es igual a una en "logs". Tercero: el LLM es pluggable y nunca autoritativo. Propone reglas, pero solo se aceptan si el evaluador las valida contra el atacante. Y cuarto: FUGA se expone como servidor MCP con tres tools —fuga_scan, fuga_prove, fuga_fix— para que cualquier agente de IA lo use a media conversación.» |

---

## ESCENA 5 — AWS (Bedrock) + Kiro

| | |
|---|---|
| **Tiempo** | 4:00 – 4:40 |
| **En pantalla** | Logo de Amazon Bedrock → configuración `FUGA_LLM=bedrock`. Logo de Kiro → carpeta `.kiro/` abierta mostrando specs, steering, agents. Fragmento de `fuga-auditor`. Resultado de la auditoría de Kiro (docs/kiro-review.md). |
| **Narración** | «En la nube usamos Amazon Bedrock como motor LLM para la reescritura de reglas. Es una opción: también puedes correr Ollama local para no enviar tu esquema a ningún servidor. Y todo el proyecto se construyó con el flujo spec-driven de Kiro: requirements, design, tasks, steering, hooks y un agente dedicado —fuga-auditor— que auditó y probó FUGA de punta a punta. Kiro no solo escribió código: validó que el agente funciona.» |

---

## ESCENA 6 — Cierre

| | |
|---|---|
| **Tiempo** | 4:40 – 5:00 |
| **En pantalla** | Pantalla dividida: a la izquierda el demo con "Fuga eliminada ✔", a la derecha el repo de GitHub. URL del demo y del repo en texto grande. |
| **Narración** | «FUGA convierte "no sabía que mi base estaba abierta" en "vi mis datos filtrarse, apliqué el fix y verifiqué que ya no ocurre"… en menos de dos minutos. El demo está en vivo, el código es open source. Pruébalo. Gracias.» |

---

## Checklist de grabación

- [ ] Navegador abierto en https://fuga-two.vercel.app con el preset "Clínica MediCloud" precargado.
- [ ] Repo abierto en https://github.com/JuanMCanchala/fuga (pestaña o ventana secundaria).
- [ ] Resolución de grabación: 1080p mínimo, fuente legible (≥14px).
- [ ] No mostrar datos sensibles reales (los datos del demo son sintéticos/ficticios).
- [ ] Verificar que el demo responde correctamente antes de grabar (probar SCAN/PROVE/FIX/VERIFY).
- [ ] Micrófono configurado, sin ruido de fondo.
- [ ] Cronómetro visible durante la grabación para respetar el límite de 5:00.
- [ ] Tener el diagrama de arquitectura listo (se puede usar el del README o una versión limpia).
- [ ] Mostrar brevemente la carpeta `.kiro/` en el editor (specs, steering, agents).
- [ ] Cerrar notificaciones del sistema operativo y pestañas irrelevantes.

---

## Frases clave (memorables)

1. **«No advierte. Demuestra.»**
2. **«Esto no es una advertencia: es la prueba.»**
3. **«El LLM propone, el evaluador dispone.»**
4. **«No lo creemos: lo probamos. Loop cerrado.»**
5. **«Una sola línea expone toda tu base de datos.»**
6. **«Prueba, no opina.»**
7. **«Vi mis datos filtrarse, apliqué el fix y verifiqué que ya no ocurre.»**
