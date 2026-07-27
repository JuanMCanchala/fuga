# Producto — FUGA

## Qué es
FUGA es un agente especializado en seguridad de reglas de acceso de bases de
datos BaaS (Backend-as-a-Service), empezando por Cloud Firestore. No es un linter
que "opina": **demuestra** cada fuga ejecutando el ataque de un intruso anónimo y
mostrando los datos que se filtrarían, luego repara las reglas y **re-verifica**
que la fuga desapareció.

## Problema real que ataca
El antipatrón `allow read, write: if true` (y variantes permisivas) es una de las
causas más frecuentes de exposición de datos personales en apps con Firebase.
Miles de proyectos —incluyendo prototipos que llegan a producción— dejan la base
de datos abierta al mundo. Las herramientas actuales solo advierten; el
desarrollador no ve el impacto y lo ignora.

## Propuesta de valor (por qué es distinto)
- **Prueba, no advierte.** Un oráculo (evaluador propio + emulador oficial)
  ejecuta el acceso anónimo real y captura el JSON exfiltrable.
- **Loop cerrado.** exploit → fix → verify. El fix no se acepta hasta que el
  atacante queda denegado.
- **Contexto de dominio con RAG.** Lee el código cliente para saber qué datos
  hay detrás de cada colección: una fuga en `/pagos` no es igual a una en `/logs`.
- **Sin fricción.** El evaluador portátil corre sin Java ni emulador, en CI y en
  el navegador.

## Usuarios
Desarrolladores y equipos que usan Firebase/Firestore; auditores de seguridad;
docentes de desarrollo web seguro.

## Éxito
El usuario pasa de "no sabía que mi base estaba abierta" a "vi mis datos filtrarse,
apliqué el fix generado y verifiqué que ya no ocurre" en menos de dos minutos.
