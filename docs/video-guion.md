# Guion del Video — FUGA

**Duración máxima:** 5:00
**Evento:** Hackatón Código Facilito × Kiro — Reto 3: Agentes especializados
**Proyecto:** FUGA · https://github.com/JuanMCanchala/fuga
**Demo:** https://fuga-two.vercel.app
**App vulnerable de demostración:** https://fuga-two.vercel.app/demo-vulnerable.html
**Animación del loop (Escena 2):** https://fuga-two.vercel.app/loop.html

> El hilo conductor del video es el DIFERENCIADOR: FUGA prueba la **fuga entre
> usuarios** (un usuario lee los datos de otro), el bug que ningún otro escáner
> del mercado detecta. Todo lo demás cuelga de ahí.

---

## ESCENA 1 — Hook: el bug que nadie ve (0:00 – 0:40)

| | |
|---|---|
| **En pantalla** | Abre **/demo-vulnerable.html** (MediCloud, portal de pacientes). Se ve la historia clínica de "Alice" (cédula, diagnóstico, tarjeta). Click en **"Entrar como Mallory (otra cuenta)"** → aparece el banner rojo: Mallory ve el registro de Alice. |
| **Narración** | «Esta es MediCloud, una app de telemedicina hecha rápido con IA. Se ve profesional. Pero mira: entro como Mallory —una cuenta cualquiera, no soy admin— y veo la historia clínica completa de otra paciente: su diagnóstico, su cédula, su tarjeta. La regla exige estar logueado, así que **todos los escáneres del mercado dirían que esta app es segura**. Revisan si la puerta está cerrada, no si tienes permiso de entrar a la habitación. Ese es el bug que nadie prueba… hasta ahora.» |

---

## ESCENA 2 — Qué es FUGA (0:40 – 1:10)

| | |
|---|---|
| **En pantalla** | Abre **/loop.html** (pantalla completa): el loop animado SCAN → PROVE → FIX → VERIFY, los nodos iluminándose en secuencia y el tagline "No advierte. Prueba que un usuario lee los datos de otro." |
| **Narración** | «FUGA es un agente especializado que no advierte sobre fugas: las demuestra, las repara y lo verifica. Y su sello es probar la **fuga entre usuarios**. En vez de atacar como anónimo, ataca con dos identidades: crea a Mallory y demuestra que llega a los datos de Alice. Luego genera el fix acotado al dueño —un LLM propone, un evaluador propio valida— y re-lanza el ataque para confirmar que Mallory ya no entra. Prueba, no opina.» |

---

## ESCENA 3 — DEMO en vivo (1:10 – 3:10)

| | |
|---|---|
| **En pantalla** | En la app MediCloud, click en **"Auditar esta app con FUGA"**. Abre la consola (**/app.html**) con las reglas de MediCloud **ya cargadas**. Click en **"Escanear ahora"**. |

### 3a — SCAN + el diferenciador (1:10 – 2:00)

| | |
|---|---|
| **En pantalla** | El reporte carga: gauge en **100/100, grado F**. Arriba, el callout rojo **"Fuga entre usuarios"** con la historia de Alice vs Mallory, la evidencia (nombre, cédula, diagnóstico, teléfono en rojo) y la regla culpable. Debajo, los hallazgos: FUGA-IDOR-READ, FUGA-IDOR-WRITE, más la fuga pública de pagos. |
| **Narración** | «Un clic y FUGA carga las reglas de MediCloud. Riesgo 100 sobre 100. Y aquí está lo que ningún otro detecta: la fuga entre usuarios. FUGA lo probó con dos cuentas —Mallory leyó el registro de Alice— y te muestra exactamente qué datos quedan expuestos: nombre, cédula, diagnóstico, teléfono. Además cazó la fuga pública de pagos, con tarjeta y CVV. Esto no es un análisis estático: es el ataque, ejecutado.» |

### 3b — FIX con IA validada (2:00 – 2:40)

| | |
|---|---|
| **En pantalla** | Sección "Tu fix": reglas endurecidas. Se resalta que cada colección queda **acotada al dueño** (`request.auth.uid == ...`). Menciona en pantalla: motor **OpenAI (gpt-4o-mini)**, etiqueta **"llm-validado"**. |
| **Narración** | «El fix lo redacta un modelo de OpenAI, pero no confiamos en él a ciegas: el evaluador portátil re-lanza el ataque y solo acepta las reglas si Mallory queda bloqueada. Por eso dice "validado". Las historias clínicas ahora solo las lee su dueño; los pagos exigen autenticación y propiedad. LLM propone, evaluador dispone.» |

### 3c — VERIFY: loop cerrado de verdad (2:40 – 3:10)

| | |
|---|---|
| **En pantalla** | Banner verde: "Verificado: el atacante anónimo Y cualquier otro usuario ajeno quedan bloqueados." |
| **Narración** | «Y verify cierra el loop. Re-lanzamos los dos ataques contra las reglas nuevas: el anónimo y el de entre usuarios. Ambos, denegados. La fuga que Mallory explotaba ya no existe. No lo creemos: lo probamos.» |

---

## ESCENA 4 — Por dentro + MCP en el editor (3:10 – 4:05)

| | |
|---|---|
| **En pantalla** | Diagrama de arquitectura. Luego, un **editor con MCP** (Cursor/Kiro): el agente llama a **`fuga_audit`** sobre unas reglas y devuelve el resumen: "FUGA ENTRE USUARIOS: 1 de lectura, 1 de escritura… atacantes BLOQUEADOS". |
| **Narración** | «Por dentro, cuatro piezas. Un evaluador de reglas propio en TypeScript: decide ALLOW o DENY sin Java ni emulador, así que corre en CI y en el navegador —y es lo que nos permite simular a dos usuarios y probar la fuga entre ellos. Un RAG que lee tu código y sabe que "pacientes" guarda diagnósticos. Soporte multi-backend: Firestore, Realtime Database y Supabase. Y un servidor MCP: aquí, dentro del editor, el agente llama a `fuga_audit` mientras programas, ve la fuga entre usuarios y aplica el fix. FUGA no es una web donde pegas una URL: vive donde se escribe el bug.» |

---

## ESCENA 5 — IA (OpenAI/Bedrock) + Kiro (4:05 – 4:40)

| | |
|---|---|
| **En pantalla** | `FUGA_LLM=openai` en producción. Menciona alternativas: Bedrock (AWS), Ollama local, plantilla determinista. Luego la carpeta **`.kiro/`**: specs, steering, agente `fuga-auditor`, hooks. |
| **Narración** | «El motor de IA es intercambiable: en producción usamos OpenAI, pero puedes correr Amazon Bedrock en la nube, Ollama en local para no enviar tu esquema a nadie, o la plantilla determinista sin ninguna clave. FUGA funciona igual sin IA. Y todo se construyó con el flujo spec-driven de Kiro: requirements, design, tasks, steering, hooks y un agente `fuga-auditor` que auditó FUGA de punta a punta —y encontró bugs reales que corregimos.» |

---

## ESCENA 6 — Cierre (4:40 – 5:00)

| | |
|---|---|
| **En pantalla** | Split: izquierda "atacantes bloqueados ✔", derecha el repo de GitHub. URLs grandes: fuga-two.vercel.app · github.com/JuanMCanchala/fuga |
| **Narración** | «El mercado está lleno de escáneres que detectan la puerta abierta. FUGA es el único que prueba que un usuario puede leer los datos de otro —y escribe el fix que lo cierra. De "no sabía que Mallory veía a mis pacientes" a "probado, reparado y verificado" en dos minutos. Demo en vivo, código abierto. Pruébalo. Gracias.» |

---

## Checklist de grabación

- [ ] Abrir **/demo-vulnerable.html** para el hook (probar el botón "Entrar como Mallory").
- [ ] Abrir **/loop.html** para la Escena 2 (pantalla completa F11, cursor fuera de cuadro; el ciclo dura 8s — deja que dé al menos una vuelta).
- [ ] Confirmar que **"Auditar esta app con FUGA"** carga la consola con las reglas de MediCloud ya puestas (un clic → "Escanear ahora").
- [ ] Producción con **`FUGA_LLM=openai`** activo (el fix debe salir "llm-validado"). Probar un scan antes de grabar.
- [ ] Editor con el **MCP** conectado (config en `.kiro/settings/mcp.json`); tener a mano una llamada a `fuga_audit`.
- [ ] Repo abierto en github.com/JuanMCanchala/fuga y carpeta `.kiro/` a la vista.
- [ ] 1080p mínimo, fuente ≥14px, notificaciones del SO silenciadas, micrófono limpio.
- [ ] Datos del demo son ficticios (banner visible en MediCloud).
- [ ] Cronómetro visible para respetar el límite de 5:00.

---

## Frases clave (memorables)

1. **«Revisan si la puerta está cerrada, no si tienes permiso de entrar.»**
2. **«El único que prueba que un usuario lee los datos de otro.»**
3. **«No advierte. Prueba.»**
4. **«El LLM propone, el evaluador dispone.»**
5. **«No lo creemos: lo probamos. Loop cerrado.»**
6. **«FUGA vive donde se escribe el bug.»**
7. **«De "no sabía que Mallory veía a mis pacientes" a probado, reparado y verificado.»**
