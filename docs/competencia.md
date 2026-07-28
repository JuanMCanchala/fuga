# Análisis de competencia — qué tienen otros que FUGA no

Investigación de julio 2026 sobre el mercado de "scanners de seguridad para apps
vibe-coded". El objetivo no es copiar: es saber dónde estamos por delante y dónde
tenemos un hueco real de producto.

## El mapa

| Herramienta | Qué hace | Modelo |
|---|---|---|
| [Vibe App Scanner](https://vibeappscanner.com/) | Escanea la app **desplegada por URL**: keys expuestas en el bundle JS, RLS faltante en Supabase, reglas de Firebase mal puestas, headers de seguridad. Re-escaneo semanal con alertas en el plan Pro. | Open source + nube desde $9 hasta $99/mes |
| [VibeDoctor](https://vibedoctor.io/pricing) | Escaneo **automático en cada push a GitHub**, con historial de salud del código. Secretos filtrados, CVEs de dependencias y bugs de lógica de negocio (webhooks de Stripe rotos, falta de rate limiting). | Planes Watch / Guard / Shield |
| [SecuriSky](https://securisky.dev/lp/firebase-security-audit) | Firebase **desde afuera y sin acceso a la consola**: reglas abiertas de Firestore, buckets de Storage públicos, config expuesta, falta de auth. Entrega "AI fix prompts". | Landing de auditoría |
| [ScanVibe](https://scanvibe.dev/en) | 8 analizadores: SSL/TLS, headers, keys y secretos, librerías JS vulnerables, **archivos expuestos (.env, .git)**, RLS de Supabase, reglas de Firebase y auth de endpoints. | Freemium |
| [VibeEval](https://vibe-eval.com/firebase-scanner/) | Scanners gratuitos por categoría (Firebase, [RLS de Supabase](https://vibe-eval.com/supabase-rls-checker/), GitHub Copilot). | Gratis, capta leads |
| [AuditYour.app](https://www.audityour.app/checklists/firebase-security) | Scanner de Supabase + Firebase con checklists guiados. | Freemium |
| [CheckVibe](https://checkvibe.dev/vibe-coding-security-scanner) | Seguridad + **SEO + AEO** (100+ checks) con fix copiable para cada uno. | Freemium |
| [CloudThinker](https://www.cloudthinker.io/blogs/automate-firebase-security-audit-ai-agent) | Agente IA de escaneo **continuo** de Firestore/Storage/RTDB, vigila deriva de App Check y de la config de Auth. | Enterprise |
| Supabase Security Advisor | Linter **nativo y gratis** dentro del dashboard: RLS desactivado, RLS sin políticas, security definer views, `search_path` mutable, columnas sensibles expuestas por la API. | Incluido |

Contexto del problema, según su propio material: el 60 % de las apps vibe-coded
sale con API keys expuestas, ~70 % de las apps con Supabase no tienen RLS, y ~90 %
no tiene headers de seguridad.

## Lo que ellos tienen y nosotros no

Ordenado por impacto para nuestro usuario objetivo.

1. **Escaneo por URL.** Es el hueco más grande, y es de UX pura. Todos los
   competidores piden una sola cosa: la URL de tu app desplegada. Extraen
   `firebaseConfig` / `SUPABASE_URL` del bundle de JavaScript y prueban desde
   afuera. FUGA hoy exige pegar las reglas — pero un vibe coder normalmente **no
   sabe dónde están sus reglas**. Le estamos pidiendo justo lo que no tiene.
2. **Secretos expuestos en el bundle.** `service_role` key, `sk_live_` de Stripe,
   claves de OpenAI. Es la vulnerabilidad más común del segmento y no la miramos.
   Una `service_role` filtrada salta por encima de todo el RLS: hace irrelevante
   cualquier política que auditemos.
3. **Headers de seguridad** (CSP, HSTS, X-Frame-Options). Barato de comprobar,
   presente en todos ellos.
4. **Storage.** Reglas de Firebase Storage y buckets públicos de Supabase. Solo
   miramos la base de datos; las fotos de perfil y los PDFs quedan fuera.
5. **Monitoreo continuo y alertas.** Re-escaneo periódico y aviso cuando algo
   cambia. Nosotros somos de un solo disparo.
6. **Integración con GitHub / CI.** Escaneo en cada push con historial.
7. **Archivos expuestos**: `.env`, `.git`, source maps.
8. **CVEs de dependencias.**
9. **Configuración de Auth**, no solo reglas: signups abiertos, confirmación de
   correo desactivada, política de contraseñas débil, App Check ausente.
   *(Comprobado en la práctica: al conectar el login de la consola descubrimos que
   el proyecto Supabase de destino tenía `mailer_autoconfirm: true` y
   `disable_signup: false` — exactamente esta clase de hallazgo, y ninguna
   herramienta de reglas lo ve.)*
10. **Reporte compartible / PDF / badge público.**
11. **Planes de pago y onboarding comercial** ya montados.

## El diferenciador que elegimos: fuga ENTRE USUARIOS (IDOR)

El mercado está plagado de escáneres, sí — pero **todos hacen lo mismo**:
detectan la puerta abierta (regla pública, RLS apagado). Ninguno prueba el bug
difícil: reglas que **exigen login pero no comprueban el dueño**, dejando que
cualquier usuario con cuenta lea o edite los datos de los demás. Es la clase de
fallo del CVE-2025-48757 (exposición masiva de apps Supabase) y no se detecta con
coincidencia de patrones: hay que **ejecutar el ataque con dos identidades**.

FUGA crea a "Mallory" (una cuenta cualquiera) y demuestra que accede al registro
de "Alice", genera el fix acotado al dueño y re-lanza el ataque para confirmar el
cierre. Un atacante anónimo obtiene DENY, así que los 8 competidores dicen
"seguro" y siguen de largo. **Esto es lo que nos saca de la categoría "scanner
#9".** Implementado y probado para Firestore y Supabase (RTDB en camino); 23
tests en verde. Bonus: el propio generador de fix de FUGA tenía este mismo bug
en su plantilla de perfiles — el verificador cross-tenant lo cazó.

## Lo que nosotros tenemos y ninguno tiene

Esto es el foso, y conviene decirlo así de directo en la presentación:

1. **Prueba de fuga ENTRE USUARIOS (IDOR).** Ver arriba: el bug que ninguno de
   los 8 detecta. Nuestro sello.
2. **Prueba real de explotación con datos exfiltrados.** Todos concluyen "te falta
   RLS" o "tus reglas están abiertas". **FUGA ejecuta el ataque y te muestra los
   registros que se llevaría.** Ninguno enseña el botín. Es la diferencia entre un
   linter y una demostración.
2. **El fix se verifica.** Los demás entregan texto o un "prompt de arreglo" para
   que se lo pegues a tu IA. FUGA genera reglas endurecidas y **vuelve a lanzar el
   mismo atacante** para confirmar que ahora queda denegado. El bucle se cierra.
3. **Servidor MCP.** Vive dentro de Cursor, Kiro o Claude *mientras programas*.
   Todos los competidores son una web donde pegas una URL y esperas. Nosotros
   estamos en el sitio donde el bug se está escribiendo.
4. **Evaluador de reglas propio.** Oráculo portátil en TypeScript (subconjunto de
   CEL + reglas JSON de RTDB + políticas SQL de Postgres): decide ALLOW/DENY sin
   Java, sin emulador y sin credenciales. Corre en el navegador y en CI. Los demás
   hacen coincidencia de patrones o sondean el endpoint en vivo.
5. **Tres backends con el mismo motor** y con su semántica real: la cascada de
   Realtime Database, las políticas de Postgres, el comodín recursivo de Firestore.
6. **RAG sobre el código cliente.** Sabemos qué campos vive en cada colección, así
   que priorizamos `/pagos` sobre `/logs` y nombramos el PII concreto que se filtra.

## Qué construir después, por prioridad

- **P0 — Escaneo por URL.** Pegas la URL, sacamos la config del bundle y probamos
  desde afuera. Cierra el mayor hueco de UX y es precisamente donde ganamos:
  nosotros, además de detectar, demostramos la fuga.
- **P1 — Secretos en el bundle** (una `service_role` filtrada invalida toda la
  auditoría de reglas) **y headers de seguridad.**
- **P2 — Chequeo de la configuración de Auth** (autoconfirm, signups abiertos,
  política de contraseñas). Barato y nadie del segmento lo cubre bien.
- **P3 — Monitoreo continuo:** GitHub Action + re-escaneo programado con alertas.
