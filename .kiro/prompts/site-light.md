# Orquestación: rediseño CLARO y profesional de la web de FUGA (ejecutado por Kiro)

Crea un archivo NUEVO `apps/web/public/site-light.html`: un rediseño de la landing
de FUGA con tema CLARO, profesional y con personalidad propia. Autocontenido
(CSS y JS inline), sin emojis (iconos SVG). Puedes cargar fuentes de Google Fonts
por link.

## PASO OBLIGATORIO ANTES DE DISEÑAR
Lee el archivo `apps/web/public/site.html`. De ahí debes REUTILIZAR TAL CUAL (sin
cambiar su lógica ni sus id/clases) dos cosas, porque ya funcionan en producción:

1. El bloque del "Command Center": el `div class="console"` con los botones de
   preset (setPreset), los dos `textarea` (`id="rules-input"` y `id="code-input"`),
   el botón `id="btn-run"` (runAttack), y TODO el contenedor de resultados
   `div class="results" id="results"` con sus bloques `res-scan`, `res-prove`,
   `res-fix`, `res-verify` y sus ids internos (`scan-score`, `gauge-fill`,
   `scan-findings`, `prove-summary`, `prove-leaks`, `fix-source`, `fix-rules`,
   `verify-banner`). Cópialo con los MISMOS id y clases.

2. Todo el JavaScript del final (el bloque `script`): el revelado de secciones,
   el objeto PRESETS, setPreset, runAttack, showScan/showProve/showFix/showVerify,
   escapeHtml y el cierre del menú. Cópialo VERBATIM. Puedes quitar solo la parte
   del canvas del hero (el nuevo hero no usa canvas). No cambies nada más del JS.

Debes definir en el CSS del tema claro las clases que ese JS usa, para que se vean
bien sobre fondo claro: `.result-block` y `.result-block.visible`, `.results.show`,
`.gauge` y `.gauge-fill`, `.finding` (+ `.critical` rojo, `.high` naranja),
`.leak-card` (con su `pre` de datos exfiltrados en ROJO sobre fondo claro rojizo),
`.verify-banner.clean` (verde) y `.verify-banner.dirty` (rojo), `.btn-attack`,
`.fade-in` y `.fade-in.visible`, `.nav-links.open`. Y las variables CSS
`--accent`, `--danger`, `--ok`, `--muted` con los valores del tema (abajo).

## Sistema de diseño (tema CLARO, con carácter — NO genérico)

Concepto: "claridad forense". Un producto de seguridad que no advierte: prueba.
El acento dramático es la EVIDENCIA (datos filtrados en rojo) sobre una interfaz
limpia y confiable.

Paleta (usa estos hex):
- Fondo página: `#F6F8FC` (blanco frío, NO crema).
- Superficie/tarjetas: `#FFFFFF` con sombras suaves y borde `#E4E9F2`.
- Tinta/títulos: `#111725`. Texto secundario `--muted`: `#5B6675`.
- Acento marca `--accent`: `#5B3DF5` (índigo-violeta).
- Peligro/fuga `--danger`: `#E5322D`. Verificado `--ok`: `#0FA968`.
- Gradientes sutiles violeta→cian permitidos para fondos de sección.

Tipografía (Google Fonts, con fallback de sistema y font-display swap):
- Display/titulares: "Space Grotesk" (técnica, con carácter), pesos 600–700.
- Cuerpo: "Inter".
- Código y datos: "JetBrains Mono" (refuerza el tema de datos/seguridad).
- Escala de tipo clara y jerárquica; titulares grandes y con tracking ajustado.

## Estructura de la página

1. **Nav sticky** clara (blanco translúcido con blur, sombra sutil al hacer
   scroll): logo FUGA (usa el SVG inline del logo del site.html actual, adaptando
   el color del wordmark a la tinta `#111725`), enlaces (Problema, Cómo funciona,
   Command Center, Comparativa, Arquitectura) y un botón primario "Probar gratis"
   (violeta) que ancla al command center.

2. **Hero (split, con IMAGEN de producto — el elemento firma):**
   - Izquierda: un eyebrow ("Seguridad de reglas de Firestore"), un titular grande
     de 2 líneas: "No detecta fugas de datos. / Las demuestra." (segunda línea con
     el acento violeta). Subcopy de 1–2 frases. Dos botones: "Probar en vivo"
     (primario) y "Ver en GitHub" (secundario, a https://github.com/JuanMCanchala/fuga).
     Debajo, una microlínea de confianza: "Open source · MIT · 14 tests en verde".
   - Derecha: el ELEMENTO FIRMA = un MOCKUP de producto tipo ventana de navegador
     (barra con tres puntos y una URL falsa "medicloud.app") que muestra una FICHA
     FILTRADA realista: un registro de paciente en JSON con campos resaltados en
     ROJO (nombre "Ana Ríos", cedula, diagnostico "Diabetes tipo 2", numeroTarjeta,
     cvv) con una etiqueta roja "EXPUESTO / read público", y superpuesto un pequeño
     badge/sello verde "Verificado · DENY" indicando el después. Añade una tarjetita
     flotante "Riesgo 100/100". Datos realistas, nunca vacíos.
   - Fondo del hero: gradientes/blobs muy suaves y una retícula de puntos tenue
     (blueprint), sin saturar.

3. **Franja de confianza:** "Funciona con" + chips/wordmarks monocromos de
   Firebase, Cloud Firestore, Cloud Storage (texto simple, sin logos de terceros).

4. **El Problema:** tarjeta con acento rojo mostrando `allow read, write: if true;`
   como bloque de código y el impacto (historias clínicas, tarjetas, cédulas).

5. **Cómo funciona:** 4 pasos numerados (es una secuencia real): SCAN, PROVE, FIX,
   VERIFY, cada uno con icono SVG y una frase. Debajo: "No detecta. Demuestra."

6. **Command Center:** el bloque interactivo reutilizado (ver arriba), con estilo
   claro. Título "Pruébalo ahora" y subtítulo. Mantén los presets (Clínica
   MediCloud, básico, seguro).

7. **Comparativa (aprovecha esto):** una tabla "Otros escáneres vs FUGA". Filas:
   Detecta acceso abierto (ambos sí), Muestra los datos exfiltrados (otros no,
   FUGA sí), Genera el fix (otros no, FUGA sí), Re-verifica el fix (otros no,
   FUGA sí), Corre sin backend/Java (FUGA sí), Open source (FUGA sí). Usa checks
   verdes y equis grises.

8. **Arquitectura:** bento/grid de 4 tarjetas: Evaluador de reglas propio en
   TypeScript (oráculo sin Java), RAG por colección (esquema + PII), LLM pluggable
   (Amazon Bedrock / Ollama / plantilla), Servidor MCP (fuga_scan/prove/fix).

9. **AWS + Kiro:** franja clara destacando Amazon Bedrock como motor LLM y que se
   construyó con el flujo spec-driven de Kiro (specs, steering, agente, hooks).

10. **CTA final + Footer:** botones a Demo (https://fuga-two.vercel.app) y Repo,
    y "FUGA — MIT · Hackatón Código Facilito × Kiro".

## Calidad
- Responsive completo (el hero pasa a una columna en móvil; nav colapsa).
- Foco visible en teclado; respeta `prefers-reduced-motion`.
- Animaciones sutiles de entrada (reutiliza la clase `.fade-in`).
- Sombras suaves y bordes de 1px; nada de sombras exageradas.

Escribe SOLO `apps/web/public/site-light.html`.
