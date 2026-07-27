# Orquestación: sitio web completo de FUGA (ejecutada por Kiro)

Construye un sitio web de una sola página, impresionante y "para ganar un
hackatón", en `apps/web/public/site.html`. Un solo archivo HTML autocontenido:
TODO el CSS y JS inline, SIN dependencias externas, SIN CDNs, SIN fuentes
remotas, SIN imágenes rasterizadas (solo SVG/canvas). Nada de emojis: iconos SVG
inline (`stroke="currentColor"`).

## Qué es FUGA
Un agente de seguridad especializado que NO advierte sobre fugas de datos: las
**demuestra** (lanza un atacante anónimo contra tus reglas de Firestore y captura
los datos que se filtrarían), las **repara** (reglas de mínimo privilegio; el LLM
propone y un evaluador propio valida) y lo **verifica** (re-ataca hasta DENY).
Reto: Hackatón Código Facilito × Kiro — Reto 3: Agentes especializados.

## Paleta y estilo
Fondo `#0b0e14`, paneles `#121722`, bordes `#1e2636`, texto `#e6ebf2`, texto
tenue `#8892a4`, acentos morados `#7c5cff` y `#a78bfa`, peligro `#ff5c72`, ok
`#37d399`. Tipografía `system-ui`. Tipografía de titulares MUY grande y en negrita
(estilo editorial impactante). Bordes redondeados, sombras sutiles, mucho aire.

## Estructura (una sola página con scroll y nav sticky)

1. **Nav sticky** (arriba, semi-transparente con blur): a la izquierda el logo de
   FUGA (INCLUYE este SVG inline exactamente):
   `<svg viewBox="0 0 180 48" width="132" height="35"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs><path d="M24 4 L40 10 L40 24 C40 34 33 40 24 44 C15 40 8 34 8 24 L8 10 Z" fill="url(#lg)"/><path d="M24 14 C24 14 19 20 19 24 C19 27.3 21.2 29.5 24 29.5 C26.8 29.5 29 27.3 29 24 C29 20 24 14 24 14 Z" fill="#0b0e14" opacity="0.85"/><rect x="18" y="22" width="12" height="3" rx="1.5" fill="#e6ebf2"/><text x="54" y="33" font-family="system-ui,sans-serif" font-weight="800" font-size="24" fill="#e6ebf2" letter-spacing="1">FUGA</text></svg>`
   A la derecha, enlaces ancla: Problema, Cómo funciona, Command Center,
   Arquitectura, y un botón a GitHub (https://github.com/JuanMCanchala/fuga).

2. **Hero con fondo ANIMADO en `<canvas>`**: una red de nodos y líneas que se
   conectan/mueven (efecto "grafo de datos") en tonos morados sobre el fondo
   oscuro, a baja opacidad. Encima: un badge ("Agente especializado · Reto 3"),
   un titular ENORME a dos líneas: "TUS DATOS ESTÁN EXPUESTOS." / "FUGA LO
   DEMUESTRA." (la segunda línea con degradado morado). Subtítulo explicando la
   propuesta en 1-2 frases. Dos botones: "Probar en vivo" (ancla a #command-center,
   estilo primario morado) y "Ver el código" (a GitHub, secundario). Indicador de
   scroll abajo.

3. **El Problema**: tarjeta con acento rojo. Explica el antipatrón
   `allow read, write: if true;` (mostrado como bloque de código resaltado) que
   deja toda la base legible y escribible por cualquiera: tarjetas, cédulas,
   mensajes. "Una de las causas #1 de fuga de datos en apps con Firebase."

4. **Cómo funciona**: 4 tarjetas numeradas con icono SVG: 1) SCAN (análisis
   estático + riesgo), 2) PROVE (atacante anónimo captura el JSON exfiltrable),
   3) FIX (mínimo privilegio; LLM propone, evaluador valida), 4) VERIFY (re-ataca:
   DENY). Debajo, una frase destacada: "No advierte. Prueba."

5. **Command Center** (id="command-center"): un panel tipo consola/dashboard, el
   corazón interactivo. Contiene:
   - Un `<textarea>` con reglas de Firestore, PRECARGADO con:
     `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}`
   - Un `<textarea>` opcional de código cliente, precargado con:
     `collection(db,'pagos'); collection(db,'usuarios'); addDoc(r,{numeroTarjeta,cvv,email,telefono,ownerId})`
   - Un botón "EJECUTAR ATAQUE" que hace `fetch('/api/analyze', {method:'POST',
     headers:{'content-type':'application/json'}, body: JSON.stringify({rules, code})})`.
   - Con la respuesta, muestra en 4 bloques animados (aparecen en secuencia):
     (a) SCAN: un medidor/gauge de `scan.riskScore` (0-100) con color según nivel,
         y la lista `scan.findings[]` (cada uno: `severity`, `code`, `title`).
     (b) PROVE: por cada `exploit.leaks[]`, una tarjeta roja con
         `method` + `path`; si trae `exfiltrated`, muestra el JSON en `<pre>` rojo
         (efecto "datos filtrándose"). Encabeza con
         `exploit.leaks.length` fugas y `exploit.totalDocsExposed` documentos.
     (c) FIX: bloque verde con `fix.rules` en `<pre>` y una etiqueta `fix.source`.
     (d) VERIFY: si `verify.clean === true`, banner verde "Fuga eliminada y
         verificada"; si no, rojo con `verify.remaining` restantes.
   - Estado de carga ("Atacando…") y manejo de error (muestra el mensaje).
   - IMPORTANTE: el JSON de respuesta tiene esta forma exacta:
     `{ llm, scan:{riskScore, summary, findings:[{code,title,severity,matchPath,line,condition,rationale}]}, exploit:{leaks:[{collection,path,method,verdict,proven,exfiltrated,piiFields}], totalDocsExposed, clean}, fix:{rules, source, validated}, verify:{clean, remaining} }`

6. **Arquitectura**: 4 tarjetas con icono SVG y descripción: Evaluador de reglas
   propio en TypeScript (oráculo portátil sin Java); RAG sobre el código cliente
   (esquema + PII, ES/EN); LLM pluggable (Amazon Bedrock / Ollama local /
   plantilla determinista); Servidor MCP (tools fuga_scan/fuga_prove/fuga_fix para
   Kiro, Claude, Cursor).

7. **Por qué FUGA** (comparativa): una tabla o dos columnas "Linters tradicionales
   (solo advierten)" vs "FUGA (demuestra + repara + verifica)".

8. **AWS + Kiro**: franja destacando Amazon Bedrock como motor LLM en la nube y
   que el proyecto se construyó con el flujo spec-driven de Kiro y se integra como
   servidor MCP.

9. **CTA final + Footer**: botones a Demo (https://fuga-two.vercel.app) y Repo
   (https://github.com/JuanMCanchala/fuga). Footer: "FUGA — MIT © Juan Manuel
   Canchala · Hackatón Código Facilito × Kiro".

## Detalles técnicos
- Animaciones de entrada con IntersectionObserver (fade/slide).
- Scroll suave para los anclas del nav.
- Responsive completo (móvil: nav colapsa, grids a 1 columna, titulares reducen).
- El `<title>` = "FUGA — Demuestra, repara y verifica fugas de datos en Firestore".
- Que se vea premium y moderno, nivel producto real.

Escribe SOLO `apps/web/public/site.html`. No modifiques otros archivos.
