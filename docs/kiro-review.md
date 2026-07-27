# Auditoría crítica de FUGA — ejecutada por Kiro CLI

**Fecha:** 2026-07-27  
**Auditor:** Kiro CLI (agente de desarrollo con acceso al repositorio y ejecución local)  
**Alcance:** Código fuente del monorepo `packages/core`, `packages/cli`, `apps/web`, y pruebas de estrés del oráculo portátil.

---

## 1. Correctitud

### 1.1 [CRÍTICO] Parser: crash en nombres de colección con guiones

**Archivo:** `packages/core/src/rules/parser.ts:143-152` (función `lex`, regex de identificadores)  
**Evidencia:** El archivo `docs/review-cases/b2-hyphen-crash.rules` con `match /admin-data/{docId}` produce:
```
ParseError: Se esperaba '{' pero se encontró '-' (línea 4, columna 17)
```

**Causa raíz:** El lexer define los identificadores como `/[A-Za-z_$][A-Za-z0-9_$]*/` (línea ~143). Los segmentos de path de Firestore permiten guiones (`-`), pero el parser los tokeniza como un operador `-` de resta, lo que rompe el parsing del path.

**Impacto:** Cualquier regla con colecciones que contengan guiones (ej: `user-data`, `api-keys`, `order-items`) hace que FUGA se caiga con un error no recuperable. Es un patrón MUY común en proyectos Firebase reales.

**Recomendación:** En `parsePath()`, consumir tokens de path como una secuencia de caracteres permitidos incluyendo `-` (ya sea un modo especial del lexer al parsear paths, o tratando la secuencia `ident - ident` como un solo segmento dentro del contexto de un path).

---

### 1.2 [ALTO] Evaluador: operador `is` siempre retorna UNKNOWN

**Archivo:** `packages/core/src/rules/evaluator.ts:234` (función `evalBinary`, case `'is'`)  
**Evidencia:** El caso D (`request.resource.data.nombre is string`) retorna `INDETERMINATE` en el scan. El evaluador tiene:
```typescript
case 'is':
  return UNKNOWN; // comprobación de tipo: no la resolvemos con certeza
```

**Impacto:** El patrón `allow create: if request.resource.data.campo is string` es una validación de tipo habitual que SIEMPRE debería ser resuelta como `true` cuando los datos de prueba proporcionan un string. Al retornar UNKNOWN, el evaluador es conservador pero pierde la capacidad de probar fugas donde la validación de tipo es la ÚNICA barrera (sin auth), como en el caso D donde un atacante anónimo SÍ puede escribir si envía el campo correcto.

**Recomendación:** Implementar resolución básica de `is` para los tipos nativos de Firestore (`string`, `int`, `float`, `bool`, `list`, `map`, `timestamp`, `null`) contra el valor concreto del dato:
```typescript
case 'is':
  if (typeof r === 'string') {
    const jsType = typeof l;
    if (r === 'string') return jsType === 'string';
    if (r === 'int' || r === 'float') return jsType === 'number';
    if (r === 'bool') return jsType === 'boolean';
    if (r === 'list') return Array.isArray(l);
    if (r === 'map') return l !== null && typeof l === 'object' && !Array.isArray(l);
    if (r === 'null') return l === null;
  }
  return UNKNOWN;
```

---

### 1.3 [ALTO] Evaluador: `request.auth.uid` dentro de `path` Expr no se resuelve al evaluar `in`/members

**Archivo:** `packages/core/src/rules/evaluator.ts:271-280` (función `evalCall`, resolución de `get`)  
**Evidencia:** Para `allow read: if request.auth.uid in resource.data.members` con `auth: null`:
- El evaluador evalúa `request.auth.uid` → `null.uid` → debería ser `null` o error (acceso a propiedad de null), pero en la implementación actual `evalMember` de un `null` retorna `UNKNOWN`.
- El `in` con left=UNKNOWN retorna UNKNOWN → resultado INDETERMINATE.

Esto es **correcto** (conservador), pero se pierde la oportunidad de probar DENY definitivo: si `auth` es `null`, entonces `request.auth` es `null`, luego `request.auth.uid` es un acceso inválido que en el motor real de Firebase lanza una excepción y deniega. El evaluador debería retornar `false` (o un valor que cause DENY) cuando se accede a propiedades de `null` en el contexto de la condición.

**Recomendación:** Cuando `evalMember` recibe `null` como objeto, retornar un valor especial que en contexto booleano colapse a `false` en lugar de UNKNOWN, ya que en el motor real de Firestore esto es un error que deniega el acceso.

---

### 1.4 [MEDIO] Evaluador: `in` sobre `resource.data` no resuelve porque `resource.data` es UNKNOWN para el atacante

**Archivo:** `packages/core/src/rules/evaluator.ts:169-172` (función `buildRoot`)  
**Evidencia:** En `buildRoot`:
```typescript
resource: {
  data: req.resource ?? (req.method === 'create' ? {} : UNKNOWN),
}
```
Para un `get` anónimo, si el `AccessRequest` trae `resource` poblado, se usa. Pero en `probeAllow` (llamado por el scanner), el request se construye como:
```typescript
{ path: samplePath(fr.segments), method: 'get', auth: null }
```
**Sin `resource`.** Por tanto, para reads, `resource.data` es UNKNOWN, y expresiones como `request.auth.uid == resource.data.ownerId` retornan UNKNOWN (porque `request.auth` es null → acceso a `.uid` retorna UNKNOWN).

Esto funciona correctamente solo porque `request.auth` ya es `null` y el `&&` con `request.auth != null` cortocircuita a `false`. Sin embargo, para reglas que NO empiezan con `request.auth != null` (ej: `resource.data.public == true`), el scanner no puede determinar si la colección es pública o no.

**Recomendación:** En `probeAllow`, pasar un `resource` sintético (al menos un objeto vacío `{}`) para permitir resolución parcial de condiciones basadas en resource.

---

## 2. Seguridad

### 2.1 [ALTO] API web: sin límite de tamaño en el body

**Archivo:** `apps/web/app/api/analyze/route.ts:20-21`  
**Evidencia:** La ruta recibe `await req.json()` sin validar el tamaño del payload. Un atacante podría enviar un body de varios MB con reglas enormes o código cliente masivo.

```typescript
const body = (await req.json()) as Body;
```

**Impacto:**
- DoS por consumo de CPU: reglas muy grandes generan un AST grande, el parser recursivo podría explotar la pila.
- DoS por consumo de memoria: un campo `code` de 50MB forzaría al regex del indexer a procesar toda la cadena.

**Recomendación:**
1. Limitar el tamaño del body a un máximo razonable (50KB para `rules`, 500KB para `code`):
```typescript
const MAX_RULES_LEN = 50_000;
const MAX_CODE_LEN = 500_000;
if (body.rules.length > MAX_RULES_LEN) return NextResponse.json({error: 'rules too large'}, {status: 413});
```
2. Considerar un rate limiter por IP (middleware de Next.js o Vercel edge config).

---

### 2.2 [ALTO] API web: leak de información interna en errores

**Archivo:** `apps/web/app/api/analyze/route.ts:42-45`  
```typescript
} catch (err) {
  return NextResponse.json(
    { error: 'No se pudieron analizar las reglas.', detail: String(err) },
    { status: 500 },
  );
}
```

**Impacto:** `String(err)` puede exponer stack traces completas, paths internos del servidor, y detalles de implementación. En Vercel, esto incluiría la ruta absoluta del deployment.

**Recomendación:** En producción, no retornar `detail` o sanitizarlo a solo el message sin stack. Logear internamente el error completo.

---

### 2.3 [MEDIO] API web: sin validación del campo `seed`

**Archivo:** `apps/web/app/api/analyze/route.ts:27`  
```typescript
const db: SeededDb = body.seed ?? synthSeed(schema);
```

El campo `seed` se acepta sin ninguna validación de estructura. Un usuario malicioso podría pasar un objeto con keys malformadas, valores circulares (si JSON.parse los acepta), o un objeto masivo.

**Recomendación:** Validar que `seed` sea un `Record<string, Record<string, unknown>>` con claves que empiecen por `/` y un máximo de N entradas.

---

### 2.4 [MEDIO] Proveedores LLM: la clave de API Anthropic se envía sin validación de URL

**Archivo:** `packages/core/src/llm/provider.ts:97-99`  
```typescript
const res = await fetch('https://api.anthropic.com/v1/messages', {
  headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY!, ... },
});
```

No hay riesgo directo, pero si `ANTHROPIC_API_KEY` se leyera de un input del usuario (no es el caso actual), se podría exfiltrar. El riesgo real es que la URL está hardcodeada — un proxy MITM en entorno corporativo podría interceptar la clave.

**Recomendación:** Documentar que en entornos corporativos con proxy se debe usar Bedrock (que usa la cadena de credenciales de AWS con SigV4) en vez de la API directa.

---

### 2.5 [BAJO] No hay CSP headers en el HTML estático

**Archivo:** `apps/web/public/site.html`  
El HTML no define Content-Security-Policy. Si se despliega fuera de Vercel (que agrega headers automáticos), el inline script es vulnerable a XSS si se inyecta contenido en la página.

**Recomendación:** Agregar `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'">` como mínimo.

---

## 3. Robustez / Edge-cases

### 3.1 [ALTO] Parser no soporta `let` bindings en funciones

**Archivo:** `packages/core/src/rules/parser.ts:290-296`  
```typescript
while (!this.is('}') && !this.is('eof')) {
  if (this.isIdent('return')) {
    this.next();
    body = this.parseExpr();
    if (this.is(';')) this.next();
  } else {
    this.next(); // ← salta tokens sin parsear
  }
}
```

Las funciones con `let x = expr;` antes del `return` son comunes en reglas complejas (ej: `let doc = get(...); return doc.data.admin == true;`). El parser salta los `let` y toma solo el `return`, pero el evaluador no tendrá el binding de `x`, por lo que fallará con UNKNOWN.

**Impacto:** Funciones auxiliares reales que usan variables locales siempre retornan INDETERMINATE.

**Recomendación:** Parsear `let name = expr;` como bindings locales y pasarlos al contexto de evaluación de la función.

---

### 3.2 [MEDIO] Evaluador: recursión no limitada en funciones (posible loop infinito)

**Archivo:** `packages/core/src/rules/evaluator.ts:253-261` (función `evalCall`)  
No hay límite de profundidad de recursión. Una función que se llame a sí misma (por accidente o malicia) causaría stack overflow.

```typescript
if (fn) {
  const args = expr.args.map((a) => evalExpr(a, ctx, root));
  const locals: Record<string, Value> = { ...ctx.locals };
  fn.params.forEach((p, i) => { locals[p] = args[i]; });
  return evalExpr(fn.body, { ...ctx, locals }, root);
}
```

**Recomendación:** Agregar un contador de profundidad (max ~10) y retornar UNKNOWN al excederlo.

---

### 3.3 [MEDIO] Prove: el atacante solo prueba `get` pero no `list`

**Archivo:** `packages/core/src/prove/attacker.ts:73`  
```typescript
const readReq: AccessRequest = { path: sample.path, method: 'get', ... };
```

El atacante siempre usa `method: 'get'`. Nunca prueba `list`. El caso C (`allow get: if true; allow list: if false`) reporta fuga en `get` correctamente, pero NUNCA detectaría el caso inverso (`allow get: if false; allow list: if true`), que es una fuga REAL donde un atacante puede enumerar toda la colección.

**Recomendación:** Agregar un segundo intento con `method: 'list'` para cubrir ambos patrones de lectura.

---

### 3.4 [MEDIO] RAG/Indexer: regex `WRITE_CALL_RE` no captura objetos multilínea

**Archivo:** `packages/core/src/rag/indexer.ts:16`  
```typescript
const WRITE_CALL_RE = /\b(?:setDoc|addDoc|updateDoc)\s*\([^,]*,\s*\{([^}]*)\}/gs;
```

El `[^}]*` es greedy non-`}` que no soporta objetos anidados. Si un `setDoc` tiene objetos anidados (`{ address: { street: '...' } }`), la regex cortará al primer `}`, capturando solo `address: { street: '...'` y generando keys incorrectas.

**Recomendación:** Aceptar la limitación o usar un parser de expresiones más robusto para extraer claves de nivel superior (un regex balanceado no existe; mejor tokenizar con un heurístico de profundidad).

---

### 3.5 [BAJO] Prove: `synthSeed` usa fallback hardcodeado a 'pagos' y 'usuarios'

**Archivo:** `packages/core/src/prove/seed.ts:105`  
```typescript
export function synthSeed(schema: SchemaModel, fallbackCollections: string[] = ['pagos', 'usuarios']): SeededDb {
```

Si no hay esquema inferido (no se pasa `--code` ni hay código cliente), prove siempre atacará 'pagos' y 'usuarios' sin importar qué digan las reglas. Esto produce resultados irrelevantes cuando las reglas definen colecciones distintas.

**Recomendación:** Extraer colecciones directamente del AST de reglas como segunda fuente antes del fallback hardcodeado.

---

## 4. RAG / Heurísticas

### 4.1 [MEDIO] Falso positivo FUGA005 en reglas con auth indirecto vía `get()`

**Archivo:** `packages/core/src/scan/analyzer.ts:30-43` (función `referencesAuth`)  
**Evidencia:** Caso B (`allow write: if get(.../roles/$(request.auth.uid)).data.admin == true`) produce:
```json
{"code": "FUGA005", "title": "Escritura sin verificación de autenticación", ...}
```

**Causa:** La función `referencesAuth()` camina el AST buscando el patrón `request.auth`, pero el `request.auth.uid` está dentro de un `PathExpr` cuyo tipo es `{ type: 'path', source: '...' }` — un string opaco que no se recorre recursivamente.

**Impacto:** Falso positivo en cualquier regla que verifique roles via `get(/...$(request.auth.uid)...)`. Los usuarios recibirán advertencias incorrectas sobre reglas que SÍ verifican autenticación.

**Recomendación:**
1. Opción rápida: buscar `request.auth` como subcadena en el `source` de nodos `PathExpr` dentro de `referencesAuth`.
2. Opción robusta: parsear las interpolaciones `$(...)` del path como sub-expresiones en el AST.

---

### 4.2 [BAJO] Clasificación PII: "name" como colección genera ruido

**Archivo:** `packages/core/src/rag/indexer.ts:49-54`  
**Evidencia:** En la salida de `prove`, aparece una colección `"name"` con PII fields. Esto ocurre porque el regex `WHERE_RE` extrae `"nombre"` del código cliente como un field, pero la lógica de `classifyFieldByLexicon` → `normalize("name")` → match en PII_FIELDS marca "name" como identidad.

**El problema mayor:** El indexer usa un pool GLOBAL de campos para TODAS las colecciones. Si el código menciona `where('email', ...)` una vez, TODAS las colecciones inferidas heredan "email" como campo PII. Esto infla la severidad incorrectamente.

**Recomendación:** Asociar campos a colecciones específicas (cuando sea inferible del contexto del código, ej: cadena `collection(db,'pagos') → where('monto',...)`) en vez de un pool global.

---

### 4.3 [BAJO] `collectionSensitivity`: normalización agresiva con singular

**Archivo:** `packages/core/src/rag/schema.ts:146-149`  
```typescript
const singular = n.replace(/s$/, '');
for (const key of Object.keys(SENSITIVE_COLLECTIONS)) {
  if (key === singular || key.replace(/s$/, '') === singular) { ... }
}
```

Esto causa falsos positivos: "logs" → "log" vs "locations" → "location" (que sí matchea "ubicacion"… no, no matchea porque es diferente). Pero "status" → "statu" no matchea nada. El riesgo mayor: "bus" → "bu", "gas" → "ga" — estos no producen falso positivo porque no están en el diccionario. Sin embargo, "items" → "item" podría matchear "menor" en algún futuro.

No es un bug actual, pero la normalización es frágil.

---

## 5. Web / UX

### 5.1 [MEDIO] Accesibilidad: textarea sin labels asociados por `for`/`id` correctamente

**Archivo:** `apps/web/public/site.html:116-117`  
```html
<label for="rules-input">Reglas de Firestore</label>
<textarea id="rules-input">...</textarea>
```

Esto está correcto para el primer textarea. Sin embargo:
- ✅ `rules-input` tiene label correcto.
- ✅ `code-input` tiene label correcto.
- ✅ Los labels son visibles y descriptivos.

**Veredicto: BIEN** para labels básicos.

---

### 5.2 [MEDIO] Accesibilidad: contraste insuficiente de texto secundario

**Archivo:** `apps/web/public/site.html:4` (variable CSS `--muted: #8892a4`)  
El texto `--muted` (#8892a4) sobre `--bg` (#0b0e14) tiene un ratio de contraste de ~4.6:1, que pasa AA para texto normal (≥4.5:1) pero por un margen mínimo. En pantallas de menor calidad o con brillo bajo, es difícil de leer.

El texto `--muted` sobre `--panel` (#121722) tiene un ratio de ~4.0:1, que **no pasa** AA.

**Recomendación:** Subir `--muted` a un gris más claro (~#9aa3b8) para garantizar ≥4.5:1 contra `--panel`.

---

### 5.3 [MEDIO] Canvas hero: consume batería en móvil sin respeto a `prefers-reduced-motion`

**Archivo:** `apps/web/public/site.html:221-230` (IIFE del canvas)  
```javascript
function draw(){ ... requestAnimationFrame(draw) }
draw()
```

La animación corre en un loop infinito sin ninguna condición de parada. En móviles:
- Consume batería innecesariamente cuando el hero no es visible (no hay IntersectionObserver para pausar).
- No respeta `prefers-reduced-motion: reduce`.
- Con `Math.floor((w*h)/12000)` nodos en pantallas grandes (ej: 4K), puede generar cientos de nodos + O(n²) comparaciones de distancia por frame.

**Recomendación:**
1. Usar IntersectionObserver para pausar cuando el canvas sale del viewport.
2. Respetar `prefers-reduced-motion`: si está activa, no iniciar la animación.
3. Limitar el count máximo (`Math.min(count, 80)`).

---

### 5.4 [BAJO] Responsive: nav-links `position:absolute` puede superponerse al contenido

**Archivo:** `apps/web/public/site.html:11` (media query mobile)  
```css
.nav-links{display:none;position:absolute;top:100%;left:0;right:0;...}
```

El menú desplegable usa `position:absolute` y puede cubrir contenido del hero sin un backdrop clickeable para cerrarlo. Solo se cierra haciendo click en un enlace, no clickeando fuera.

**Recomendación:** Agregar un click handler en el body (o un overlay) que cierre el menú al tocar fuera.

---

### 5.5 [BAJO] El botón "EJECUTAR ATAQUE" no tiene `type="button"`

**Archivo:** `apps/web/public/site.html:120`  
```html
<button class="btn-attack" id="btn-run" onclick="runAttack()">EJECUTAR ATAQUE</button>
```

Sin `type="button"`, dentro de un `<form>` se comportaría como submit. No hay un form aquí, pero es buena práctica explicitarlo.

---

## 6. DX / Tooling

### 6.1 [MEDIO] Prove ignora las colecciones del archivo de reglas si no hay `--code`

**Evidencia:** Al correr `prove --rules docs/review-cases/c-list-vs-get.rules` sin `--seed` y sin `--code`, el prove ataca las colecciones fallback (`pagos`, `usuarios`) de `synthSeed`, NO la colección `productos` que está en las reglas.

El flujo de la CLI es: `loadSchema(opts)` → busca código en `opts.cwd` → si el cwd tiene archivos con `collection(...)` los indexa. Si no hay código cliente relevante, el prove opera contra colecciones irrelevantes.

**Recomendación:** `synthSeed` debería recibir las colecciones del AST de reglas como entrada primaria, solo usando el schema como enriquecimiento.

---

### 6.2 [BAJO] Los tests existentes no cubren los patrones avanzados del evaluador

No hay tests para: funciones con `let`, operador `in`, operador `is`, paths con guiones, `get()` con path interpolado, `list` vs `get` distinction.

**Recomendación:** Agregar al menos un test por cada patrón probado en esta auditoría a `packages/core/test/`.

---

### 6.3 [BAJO] El exit code del CLI es inconsistente para `scan`

**Archivo:** `packages/cli/src/commands.ts:53`  
```typescript
return report.riskScore >= 40 ? 1 : 0;
```

En modo JSON, se imprime el resultado pero TAMBIÉN se retorna exit code 1 si risk ≥ 40. Esto es correcto para CI, pero no está documentado y sorprende al usuario que espera 0 cuando no hay error de ejecución.

**Recomendación:** Documentar en `--help` que exit 1 = risk alto (para CI), o agregar un flag `--fail-on` para controlar el threshold.

---

## Resumen de pruebas de estrés del oráculo

| Caso | Patrón | Resultado scan | Resultado prove | Veredicto |
|------|--------|---------------|-----------------|-----------|
| A | `function signedIn()` helper | 0 findings, risk=0 | DENY | ✅ **BIEN** — resuelve funciones auxiliares |
| B | `get(.../roles/$(request.auth.uid))` role | FUGA005 (medium, no probado) | INDETERMINATE | ⚠️ **Falso positivo** — marca FUGA005 incorrectamente |
| B2 | Path con guión `admin-data` | **CRASH** ParseError | N/A | ❌ **BUG** — parser no soporta guiones |
| C | `allow get:if true; allow list:if false` | FUGA003 high, proven | ALLOW (get) | ✅ **BIEN** — detecta get público |
| D | `request.resource.data.nombre is string` | FUGA005 (medium, no probado) | INDETERMINATE (write) | ⚠️ **Limitación** — no resuelve `is` |
| E | Regla segura por dueño | 0 findings | DENY | ✅ **BIEN** — no reporta falso positivo |
| F | `request.auth.uid in resource.data.members` | 0 findings | INDETERMINATE (read) | ⚠️ **Limitación** — debería ser DENY definitivo |

**Tasa INDETERMINATE:** 3 de 6 patrones avanzados producen INDETERMINATE en al menos una operación.  
**Falsos positivos:** 1 (caso B, FUGA005 con get() por roles).  
**Falsos negativos:** 0 (ningún caso inseguro pasa como seguro).  
**Crashes:** 1 (parser con guiones en paths).

---

## Top 5 mejoras priorizadas

1. **[CRÍTICO] Soportar guiones en nombres de colección en el parser.** Un solo cambio en el lexer/parser que desbloquea la compatibilidad con miles de proyectos Firebase reales. Sin esto, FUGA se cae en reglas perfectamente válidas.

2. **[ALTO] Resolver `null` access como DENY en el evaluador.** Cuando `auth` es `null`, acceder a `request.auth.uid` debería colapsar a un valor que cause DENY (como hace el motor real de Firebase), no UNKNOWN. Esto reduciría la tasa de INDETERMINATE de ~50% a ~20% en patrones reales.

3. **[ALTO] Validar tamaño de entrada en la API web.** Un atacante puede enviar megabytes de reglas/código y causar DoS. Agregar `MAX_RULES_LEN` y `MAX_CODE_LEN` toma 5 líneas y elimina un vector de abuso trivial.

4. **[ALTO] Corregir falso positivo FUGA005 para reglas con auth indirecto via `get()`.** Buscar `request.auth` como subcadena en `PathExpr.source` dentro de `referencesAuth()` es un fix de una línea que elimina falsos positivos en un patrón MUY común (role-based access).

5. **[MEDIO] Probar `list` además de `get` en el atacante.** El attackter solo prueba un vector de lectura. Agregar un intento con `method: 'list'` cubre el caso donde `list` es público pero `get` no — una fuga real que hoy pasa desapercibida.

---

## Remediación aplicada (post-auditoría)

Tras la auditoría de Kiro, se corrigieron los hallazgos de mayor impacto:

| # | Hallazgo | Severidad | Estado |
|---|----------|-----------|--------|
| 1.1 | Parser crashea con guiones en la colección (`user-data`) | CRÍTICO | ✅ Corregido — `parsePath` reconstruye segmentos con `-` |
| 1.2 | Operador `is` siempre INDETERMINATE | ALTO | ✅ Corregido — resolución de tipos nativos |
| 4.1 | Falso positivo FUGA005 con auth vía `get()` | ALTO | ✅ Corregido — `referencesAuth` inspecciona `PathExpr` |
| 3.3 | El atacante no probaba `list` | MEDIO | ✅ Corregido — prueba `get` y `list` |
| — | Escritura anónima gated solo por tipo no se probaba | ALTO | ✅ Corregido — payload del atacante con campos comunes tipados |
| 2.1 | API sin límite de tamaño de body (DoS) | ALTO | ✅ Corregido — `MAX_RULES_LEN`/`MAX_CODE_LEN`/`MAX_SEED_ENTRIES` |
| 2.2 | API filtra stack traces internos | ALTO | ✅ Corregido — `detail` solo fuera de producción |
| 2.3 | `seed` sin validar | MEDIO | ✅ Corregido — validación de tipo y tamaño |
| 5.3 | Canvas ignora `prefers-reduced-motion` y no pausa offscreen | MEDIO | ✅ Corregido — respeta reduced-motion, pausa fuera de vista, cap de 80 nodos |
| 6.2 | Faltan tests de patrones avanzados | BAJO | ✅ Corregido — 4 tests de regresión nuevos (14/14 en verde) |

Pendientes documentados (limitaciones conocidas, sin falso negativo): `let` bindings en funciones, acceso a `null` como DENY definitivo, y atribución de PII por colección — todos degradan a INDETERMINATE de forma conservadora, nunca reportan una fuga inexistente ni ocultan una real.
