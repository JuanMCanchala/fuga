# Orquestación: identidad visual de FUGA (ejecutada por Kiro)

Crea la identidad visual de FUGA, un agente de seguridad que detecta y prueba
fugas de datos en reglas de Firestore. Genera estos archivos SVG en
`apps/web/public/`:

1. `logo.svg` — logotipo principal (marca + símbolo). Concepto: un **escudo**
   hexagonal/redondeado que contiene una **gota de datos** (representa la "fuga")
   que está siendo sellada. Degradado morado `#7c5cff → #a78bfa`. A la derecha,
   el wordmark "FUGA" en tipografía sans-serif gruesa (font-weight 800), color
   `#e6ebf2`. Debe verse bien sobre fondo oscuro `#0b0e14`. viewBox limpio,
   ~180x48.

2. `logo-mark.svg` — solo el símbolo (el escudo con la gota), cuadrado ~48x48,
   para usar como isotipo.

3. `favicon.svg` — versión mínima del símbolo, 32x32, legible en tamaño pequeño.

Requisitos ESTRICTOS:
- SVG puro, vectorial, sin imágenes rasterizadas ni fuentes externas (usa
  `font-family="system-ui, sans-serif"` para el texto o convierte a paths simples).
- Nada de emojis. Estética moderna, tech, minimalista.
- Usa `<linearGradient>` para el degradado morado.
- El símbolo debe funcionar en monocromo si se le quita el color (formas claras).

Escribe SOLO esos tres archivos SVG. No modifiques nada más.
