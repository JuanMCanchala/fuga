# Orquestación: app SaaS profesional de FUGA (ejecutada por Kiro)

Crea `apps/web/public/app.html`: la consola/app SaaS de FUGA, de nivel PRODUCTO
PROFESIONAL (piensa Snyk, Vercel, Supabase Studio), dirigida a VIBE CODERS (gente
que construye apps con IA como Lovable, Bolt, v0, Cursor y no es experta en
seguridad). Un solo archivo HTML autocontenido: CSS y JS inline, iconos SVG (SIN
emojis), responsive, accesible. Puedes cargar Google Fonts. NADA de mostrar JSON
crudo al usuario: todo debe estar VISUALIZADO con componentes diseñados.

## Principio de producto (vibe coders)
El usuario no sabe de seguridad. Habla en lenguaje simple, tranquilizador y
accionable. En vez de "riskScore 100", di "Tu base de datos está expuesta ahora
mismo". Cada problema viene con "qué significa" y "cómo arreglarlo" en pasos
copiables. El objetivo: de "no sabía que tenía un problema" a "lo arreglé" en
minutos.

## Tema (igual que el sitio claro, profesional)
Fondo `#F6F8FC`, superficies `#FFFFFF`, borde `#E4E9F2`, tinta `#111725`, texto
tenue `#5B6675`, acento `#5B3DF5`, acento claro `#EEF0FE`. Fuentes: Space Grotesk
(títulos), Inter (cuerpo/UI), JetBrains Mono (código). Sombras suaves, radios
12-16px, bordes 1px. Densidad de datos alta pero legible.

Colores de ESTADO (severidad — reservados, siempre con icono + etiqueta, nunca
solo color): crítico `#E5322D`, alto `#F59E0B`, medio `#EAB308`, bajo `#64748B`,
ok/verificado `#0FA968`. Colores CATEGÓRICOS para backends (orden fijo, no
cicles): Firestore `#6D3BEB`, Realtime DB `#0EA5E9`, Supabase `#EC4899`.

## Reglas de gráficos (síguelas)
- Score de seguridad => un GAUGE RADIAL (SVG) con número grande y un GRADO (A, B,
  C, D, F) y una etiqueta ("Protegido" / "En riesgo" / "Crítico").
- Severidad => DONUT (SVG) usando los colores de estado, con leyenda + conteos.
- Riesgo en el tiempo => LÍNEA/ÁREA (SVG) de una sola serie (los últimos escaneos).
- Exposición por backend => BARRAS (SVG) con los colores categóricos.
- Gráficos con un solo eje, marcas finas, grid tenue, etiquetas legibles. Estados
  vacíos con guía. No uses librerías externas: SVG a mano.

## Estructura de la app (SPA, cambia de vista sin recargar)

### 0. Pantalla de LOGIN (si no hay sesión en localStorage)
Card centrada elegante: logo FUGA, título "Entra a tu consola de seguridad",
campos email + contraseña, botón primario "Iniciar sesión", botones secundarios
"Continuar con GitHub" y "Continuar con Google" (con sus iconos SVG), y un enlace
"Entrar en modo demo". Cualquier envío o "modo demo" crea una sesión falsa en
localStorage (`fuga_session` con email y nombre) y entra a la app. A la izquierda
o de fondo, un panel con la propuesta de valor ("Prueba, repara y verifica fugas
de datos. Hecho para apps con IA."). Look de auth de SaaS real.

### 1. Shell de la app
- Topbar: logo, buscador global (decorativo), botón primario "Nuevo escaneo", y a
  la derecha un menú de usuario (avatar con iniciales, nombre, "Configuración",
  "Cerrar sesión" que borra la sesión).
- Sidebar izquierda con iconos SVG: Dashboard, Proyectos, Nuevo escaneo, Reportes,
  Integraciones, Configuración. Colapsable en móvil.

### 2. DASHBOARD (Resumen)
- Fila superior: a la izquierda el GAUGE del Security Score (número + grado +
  etiqueta + una frase de veredicto en lenguaje simple). A la derecha, 4 KPI
  cards: Proyectos monitoreados, Fugas activas, Registros expuestos, Fugas
  corregidas — cada una con su icono, número grande y una micro-tendencia.
- Fila de gráficos: DONUT de severidad + LÍNEA de riesgo en el tiempo + BARRAS por
  backend. Con leyendas y tooltips.
- "Actividad reciente": feed de escaneos y arreglos (proyecto, backend, resultado,
  hace cuánto).
- Card de onboarding para nuevos: "¿Primera vez? 3 pasos para asegurar tu app"
  (Conecta tu proyecto, Ejecuta un escaneo, Aplica el fix), con CTA.
- Todo alimentado desde los proyectos guardados en localStorage; si no hay,
  estados vacíos con CTA "Crear tu primer escaneo".

### 3. NUEVO ESCANEO (wizard amigable)
- Paso 1: elige backend con 3 cards grandes (Firebase Firestore, Realtime
  Database, Supabase) con su color/mark.
- Paso 2: nombre del proyecto + textarea de reglas/políticas (con un enlace de
  ayuda "¿Dónde encuentro mis reglas?" que abre un popover con instrucciones por
  plataforma) + textarea opcional de código cliente. Botones de ejemplo
  vulnerable por backend (rellenan los textarea).
- Paso 3: botón "Escanear ahora". Estado de carga con pasos animados ("Analizando
  reglas… Lanzando ataque anónimo… Generando el fix… Verificando…"). Llama a la
  API (contrato abajo), guarda el resultado en el proyecto y navega al REPORTE.

### 4. REPORTE (la pieza central — VISUALIZADA, jamás JSON crudo)
- Cabecera: nombre del proyecto, badge de backend, fecha, y a la derecha el gauge
  de score + grado.
- "Veredicto" en una frase grande de lenguaje simple (ej: "Cualquiera en internet
  puede leer y modificar los datos de tus usuarios ahora mismo").
- Chips de resumen de severidad (conteos por nivel con icono).
- HALLAZGOS como tarjetas expandibles. Cada tarjeta:
  - Badge de severidad + título + ubicación (colección/tabla/path).
  - "Qué significa" en lenguaje simple.
  - "Datos que exponemos": la evidencia exfiltrada FORMATEADA como una tabla de
    campo -> valor, marcando en ROJO los campos sensibles (PII). NADA de volcar el
    JSON; una tabla legible. Encabeza con cuántos registros y qué tipo de datos.
  - "Cómo arreglarlo": el fragmento de fix relevante con botón "Copiar".
- Sección "Tu fix" completo: las reglas endurecidas en bloque de código con botón
  "Copiar todo" y un mini-instructivo "Cómo aplicarlo" por plataforma (3 pasos).
- Banner de "Verificación": verde con check "Verificado: aplicando este fix, el
  atacante queda bloqueado" si verify.clean.
- Acciones: "Descargar reporte" (genera y descarga un reporte limpio en HTML o
  Markdown, con branding, NO el JSON), "Compartir" (copia un resumen), y un toggle
  discreto "Ver datos técnicos (JSON)" para quien lo quiera — secundario, colapsado.

### 5. PROYECTOS
Lista/tabla de proyectos: nombre, badge de backend, grado/score con color, fugas
activas, último escaneo, y acciones (Ver reporte, Re-escanear, Eliminar). Estado
vacío con CTA.

### 6. INTEGRACIONES (haz FÁCIL usar FUGA)
- "Conecta FUGA a tu editor de IA" — cards para Cursor, Kiro y Claude Desktop,
  cada una con un bloque de configuración MCP copiable (servidor `fuga`) y botón
  "Copiar". Usa esta config de ejemplo:
  `{ "mcpServers": { "fuga": { "command": "npx", "args": ["-y", "@fuga/mcp"] } } }`
  y explica en una línea que así el agente de IA revisa la seguridad mientras
  programas.
- "Línea de comandos": bloque `npx fuga scan` / `npx fuga fix` con botón copiar.
- "Escaneo automático al guardar": explica el hook de Kiro (revisa las reglas cada
  vez que guardas un archivo .rules) con un bloque copiable.
- Un badge "Instalado" de ejemplo y un enlace al repo.

### 7. CONFIGURACIÓN
Secciones en tarjetas: Perfil (nombre, email, avatar de iniciales), Plan (Free vs
Pro con lista de features y botón "Mejorar a Pro"), Notificaciones (toggles:
alertas por email cuando aparece una fuga, resumen semanal), Proyectos conectados,
API keys (una key de ejemplo enmascarada con botón copiar/regenerar), Tema
(claro/oscuro toggle, opcional), y una Danger zone ("Borrar todos mis datos" que
limpia localStorage).

## Contrato de la API (úsalo tal cual)
`POST /api/analyze` con `{ rules, code, backend }` (backend opcional: firestore |
rtdb | supabase; si se omite se auto-detecta). Respuesta: `{ backend, llm,
schema: { collections }, scan: { riskScore, summary: { critical, high, medium,
low, info }, findings: [ { code, title, severity, matchPath, line, condition,
rationale, recommendation, proven, collection, piiFields } ] }, exploit: { leaks:
[ { collection, path, method, verdict, proven, exfiltrated, piiFields } ],
totalDocsExposed, clean }, fix: { rules, source, validated }, verify: { clean,
remaining } }`. severity en minúsculas. Deriva el grado A-F del riskScore
(0-9 A, 10-24 B, 25-49 C, 50-74 D, 75-100 F). Maneja carga y error.

## Ejemplos vulnerables para los botones (rellena los textarea)
- Firestore: `rules_version = '2'; service cloud.firestore { match /databases/{db}/documents { match /pacientes/{id} { allow read: if true; } match /pagos/{id} { allow read, write: if true; } } }`
- Realtime DB: `{ "rules": { "usuarios": { ".read": true }, "pagos": { ".read": true, ".write": true } } }`
- Supabase: `create table pagos (id uuid, user_id uuid, numeroTarjeta text, cvv text); create table usuarios (id uuid, email text); alter table usuarios enable row level security; create policy public_read on usuarios for select using (true);`

## Persistencia (localStorage)
`fuga_session` (sesión). `fuga_projects` (array de proyectos con sus escaneos:
`{ id, name, backend, rules, code, createdAt, scans: [ { at, risk, grade, backend, scan, exploit, fix, verify } ] }`). Todo cliente, sin backend real.

## Calidad (esto separa junior de profesional)
Micro-interacciones (hover, transiciones suaves), estados vacíos/carga/error
diseñados, foco visible, `prefers-reduced-motion`, tooltips en gráficos, jerarquía
tipográfica clara, espaciado consistente (escala de 4/8px), copys en lenguaje
humano. Que se sienta como un SaaS real que pagarías.

Escribe SOLO `apps/web/public/app.html`.
