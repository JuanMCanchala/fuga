# Orquestación: Kiro prueba FUGA y genera reporte

En este repositorio (FUGA), ejecuta la batería de pruebas del proyecto y
documenta los resultados en `docs/kiro-test-report.md`. NO modifiques código
fuente; solo ejecuta comandos y escribe el reporte.

## Pasos

1. Tests unitarios: ejecuta `npm run test -w @fuga/core` y captura cuántos pasan.

2. Flujo CLI de FUGA sobre el ejemplo vulnerable
   (`examples/vulnerable-firestore/`):
   - `node packages/cli/dist/index.js scan --rules examples/vulnerable-firestore/firestore.rules --code examples/vulnerable-firestore --json`
   - `node packages/cli/dist/index.js prove --rules examples/vulnerable-firestore/firestore.rules --seed examples/vulnerable-firestore/fuga.seed.json --json`
   - `node packages/cli/dist/index.js fix --rules examples/vulnerable-firestore/firestore.rules --code examples/vulnerable-firestore`
   - `node packages/cli/dist/index.js verify --rules examples/vulnerable-firestore/firestore.rules.fuga --seed examples/vulnerable-firestore/fuga.seed.json`

3. Escribe `docs/kiro-test-report.md` (en español). El documento debe:
   - Encabezarse indicando que fue **generado por Kiro CLI ejecutando FUGA**, con
     la fecha.
   - Incluir el resumen de tests unitarios (X/Y pasan).
   - Listar los hallazgos del `scan` (código, severidad, título) y el riesgo.
   - Reportar las fugas probadas por `prove`: cuántas, cuántos documentos
     exfiltrables, y un ejemplo del JSON exfiltrado (sin inventar datos: usa lo
     que devolvió el comando).
   - Confirmar que `verify` quedó limpio tras el `fix`.
   - Terminar con una tabla resumen y una conclusión de una o dos frases.
