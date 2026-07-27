# Orquestación: panel/dashboard profesional de FUGA (ejecutado por Kiro)

Crea `apps/web/public/panel.html`: un dashboard de seguridad profesional (estilo
Snyk / GitHub Security) para gestionar escaneos de FUGA. Un solo archivo HTML
autocontenido (CSS y JS inline), sin emojis (iconos SVG), responsive, accesible.
Puedes usar Google Fonts.

## Tema (igual que el sitio claro)
Fondo `#F6F8FC`, superficies `#FFFFFF`, borde `#E4E9F2`, tinta `#111725`, texto
tenue `#5B6675`, acento `#5B3DF5`, peligro `#E5322D`, alto `#F59E0B`, medio
`#EAB308`, ok `#0FA968`. Fuentes: Space Grotesk (títulos), Inter (cuerpo),
JetBrains Mono (código/datos). Sombras suaves, bordes de 1px.

## Layout (SPA con secciones, sin recargar)
- **Sidebar izquierda fija**: logo FUGA arriba (un escudo SVG morado + wordmark),
  navegación con iconos SVG: Resumen, Proyectos, Escaneo nuevo, Reportes. Abajo,
  un enlace "Volver al sitio" a `/`.
- **Área principal** con una topbar (título de la sección + botón primario
  "Nuevo escaneo") y el contenido de la sección activa.

## Secciones

1. **Resumen**: fila de tarjetas KPI (Proyectos, Escaneos totales, Riesgo
   promedio con color, Fugas abiertas). Debajo: un desglose por severidad
   (contadores Crítico/Alto/Medio con sus colores) y una lista "Escaneos
   recientes" (proyecto, backend, riesgo, fecha). Estado vacío con un CTA
   "Crear tu primer escaneo".

2. **Proyectos**: tabla/tarjetas de proyectos guardados: nombre, badge de backend
   (Firestore / Realtime DB / Supabase), último riesgo (gauge o número con
   color), fecha del último escaneo, y acción "Ver". Al hacer clic, abre el
   detalle del proyecto.

3. **Escaneo nuevo** (el corazón): formulario con nombre del proyecto, un
   selector de backend (Auto-detectar / Firestore / Realtime DB / Supabase), un
   textarea grande de reglas/políticas y un textarea opcional de código cliente.
   Botones de ejemplo que rellenan casos vulnerables (uno Firestore, uno RTDB,
   uno Supabase). Botón "Escanear" que llama a la API (ver contrato abajo),
   guarda el resultado en el proyecto (localStorage) y muestra el resultado.

4. **Detalle de proyecto / Resultado de escaneo**: 
   - Cabecera con nombre, badge de backend y fecha.
   - Un gauge/medidor de riesgo grande (0-100) con color según nivel.
   - Tarjetas de severidad (conteos Crítico/Alto/Medio).
   - Tabla de hallazgos FILTRABLE por severidad: columnas Severidad (badge),
     Código, Título, Ubicación (matchPath), y al expandir muestra rationale +
     recommendation + PII en riesgo.
   - Bloque "Datos exfiltrados" (del prove): por cada leak, method + path y, si
     hay `exfiltrated`, el JSON en rojo sobre fondo rojizo claro (JetBrains Mono).
     Encabezado con número de fugas y documentos.
   - Bloque "Fix generado": las reglas endurecidas en `pre` con botón "Copiar".
   - Banner de verificación: verde "Fuga eliminada y verificada" si verify.clean,
     rojo si no.
   - Historial de escaneos del proyecto (fecha + riesgo), como mini-tendencia.

5. **Reportes**: por cada proyecto, botón "Descargar reporte" que genera y
   descarga un archivo (JSON o Markdown) con el resumen del último escaneo.

## Contrato de la API (úsalo tal cual)
`POST /api/analyze` con cuerpo JSON `{ rules, code, backend }` (backend opcional:
uno de firestore | rtdb | supabase; si se omite se auto-detecta). Devuelve JSON
con esta forma exacta: `{ backend, llm, schema: { collections }, scan: { riskScore, summary: { critical, high, medium, low, info }, findings: [ { code, title, severity, matchPath, line, condition, rationale, recommendation, proven, collection, piiFields } ] }, exploit: { leaks: [ { collection, path, method, verdict, proven, exfiltrated, piiFields } ], totalDocsExposed, clean }, fix: { rules, source, validated }, verify: { clean, remaining } }`. La severidad viene en minúsculas: critical | high | medium | low | info. Maneja estados de carga y error (muestra el mensaje del campo `error`).

## Ejemplos vulnerables para los botones de "Escanear" (rellena los textarea)
- Firestore: `rules_version = '2'; service cloud.firestore { match /databases/{db}/documents { match /pacientes/{id} { allow read: if true; } match /pagos/{id} { allow read, write: if true; } } }`
- Realtime DB: `{ "rules": { "usuarios": { ".read": true }, "pagos": { ".read": true, ".write": true } } }`
- Supabase: `create table pagos (id uuid, user_id uuid, numeroTarjeta text, cvv text); create table usuarios (id uuid, email text); alter table usuarios enable row level security; create policy public_read on usuarios for select using (true);`

## Persistencia (localStorage)
Clave `fuga_projects`: un array de proyectos `{ id, name, backend, rules, code, createdAt, scans: [ { at, risk, backend, scan, exploit, fix, verify } ] }`. Al escanear, agrega un scan al proyecto (o crea el proyecto). Todo en el cliente; sin login.

## Calidad
Responsive (sidebar colapsable en móvil), foco visible, `prefers-reduced-motion`
respetado, badges de severidad con color, botón copiar con feedback, estados
vacíos con guía. Que se vea como un producto SaaS de seguridad real.

Escribe SOLO `apps/web/public/panel.html`.
