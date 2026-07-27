# Orquestación: interfaz de presentación de FUGA (ejecutada por Kiro)

Crea una página de presentación (pitch) para el proyecto FUGA: un archivo HTML
autocontenido en `presentacion/index.html` dentro de este repositorio.

## Contenido (FUGA es un agente de seguridad para reglas de Firestore)

- **Hero:** nombre "FUGA" + tagline: "No advierte sobre fugas de datos: las
  demuestra, las repara y lo verifica." Dos botones: Demo
  (https://fuga-two.vercel.app) y Repo (https://github.com/JuanMCanchala/fuga).
- **El problema:** el antipatrón `allow read, write: if true` en Firestore deja
  toda la base de datos legible y escribible por cualquiera (tarjetas, cédulas,
  mensajes privados). Es una de las causas #1 de fuga de datos en apps Firebase.
- **La solución (loop de 4 pasos, en tarjetas numeradas):**
  1. SCAN — análisis estático con severidad y puntaje de riesgo.
  2. PROVE — lanza un atacante anónimo y captura el JSON exfiltrable.
  3. FIX — reglas de mínimo privilegio; el LLM propone y el evaluador valida.
  4. VERIFY — re-ataca: debe quedar en DENY (loop cerrado).
  Diferenciador: FUGA **prueba** con datos reales, no solo advierte.
- **Arquitectura / tecnología:** evaluador de reglas Firestore propio en
  TypeScript (oráculo portátil, sin Java); RAG sobre el código cliente para
  inferir esquema y PII (ES/EN); LLM pluggable (Amazon Bedrock / Ollama local /
  plantilla determinista); servidor MCP con tools fuga_scan / fuga_prove /
  fuga_fix para Kiro, Claude y Cursor.
- **AWS + Kiro:** Amazon Bedrock como motor LLM en la nube; construido con el
  flujo spec-driven de Kiro; se integra a Kiro como servidor MCP.
- **Reto:** Hackatón Código Facilito × Kiro — Reto 3: Agentes especializados.
- **Footer:** enlaces a repo y demo.

## Diseño (ESTRICTO)

- Un solo archivo HTML autocontenido: TODO el CSS inline en `<style>`. Sin
  dependencias externas, sin CDNs, sin frameworks, sin fuentes remotas.
- Tema oscuro tipo FUGA: fondo `#0b0e14`, paneles `#121722`, acentos morados
  `#7c5cff` y `#a78bfa`, texto `#e6ebf2`, peligro `#ff5c72`, ok `#37d399`.
  Tipografía `system-ui`.
- PROHIBIDO usar emojis o símbolos unicode geométricos. Todos los iconos deben
  ser SVG inline (`<svg>` con `stroke="currentColor"`).
- Responsive (grid/flex, contenedor centrado max-width ~1100px). Animaciones
  sutiles con CSS (fade/hover).
- Incluye un bloque de código que muestre `allow read, write: if true;` marcado
  como peligroso (rojo) y, al lado, las reglas endurecidas de mínimo privilegio.

Escribe SOLO el archivo `presentacion/index.html`. No modifiques otros archivos.
