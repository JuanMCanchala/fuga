# Requisitos — Agente FUGA

## Introducción
FUGA es un agente especializado que detecta, **demuestra** y repara fugas de datos
causadas por reglas de seguridad permisivas en Cloud Firestore, con un loop de
verificación cerrado.

## Requisitos

### R1 — Detectar reglas que exponen acceso anónimo
**Historia:** Como desarrollador, quiero saber qué reglas permiten acceso sin
autenticación, para priorizar el riesgo real.
- **CUANDO** se analiza un archivo `firestore.rules`, **EL SISTEMA DEBERÁ**
  identificar cada `allow` que conceda acceso a un usuario no autenticado.
- **CUANDO** una regla usa `{document=**}` con condición permisiva, **EL SISTEMA
  DEBERÁ** marcarla como crítica por alcance global.
- **EL SISTEMA DEBERÁ** asignar severidad ponderada por la sensibilidad de la
  colección afectada.

### R2 — Probar la fuga con datos
**Historia:** Como desarrollador, no quiero una advertencia teórica sino la prueba.
- **CUANDO** se ejecuta `prove`, **EL SISTEMA DEBERÁ** simular una petición de un
  atacante no autenticado y, si es concedida, **capturar los documentos
  exfiltrables**.
- **SI** no hay datos reales disponibles, **EL SISTEMA DEBERÁ** sembrar datos de
  ejemplo verosímiles a partir del esquema inferido.

### R3 — Contexto de dominio vía RAG
**Historia:** Como auditor, quiero que la severidad refleje qué datos hay detrás.
- **CUANDO** hay código cliente disponible, **EL SISTEMA DEBERÁ** inferir
  colecciones y campos, y clasificar PII (ES/EN).
- **EL SISTEMA DEBERÁ** poder usar un modelo **local** para clasificar campos
  desconocidos sin enviar el esquema a la nube.

### R4 — Reparar y verificar (loop cerrado)
**Historia:** Como desarrollador, quiero un fix que funcione, no que rompa mi app.
- **CUANDO** se ejecuta `fix`, **EL SISTEMA DEBERÁ** generar reglas de mínimo
  privilegio (denegar por defecto + acceso por dueño autenticado) y tests.
- **CUANDO** un LLM propone reglas, **EL SISTEMA DEBERÁ** validarlas re-ejecutando
  el atacante y **rechazarlas si no eliminan la fuga**, cayendo a una plantilla.
- **CUANDO** se ejecuta `verify`, **EL SISTEMA DEBERÁ** confirmar que el atacante
  anónimo queda denegado y devolver un código de salida distinto de cero si no.

### R5 — Publicación y usabilidad
- **EL SISTEMA DEBERÁ** ejecutarse en terminal (`npx fuga`) y en una UI web.
- **EL SISTEMA DEBERÁ** exponerse como servidor MCP para agentes (Kiro, Claude).
- **EL SISTEMA DEBERÁ** funcionar sin claves ni Java (motor portátil por defecto).
