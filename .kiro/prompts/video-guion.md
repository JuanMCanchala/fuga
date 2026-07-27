# Orquestación: guion del video de FUGA (ejecutado por Kiro)

Escribe `docs/video-guion.md`: un guion completo para un video de presentación de
**máximo 5 minutos** del proyecto FUGA para el hackatón Código Facilito × Kiro
(Reto 3: Agentes especializados). El video debe mostrar objetivos, componentes
principales y una demo funcional.

## Datos del proyecto (úsalos, no inventes)
- FUGA: agente que NO advierte sobre fugas de datos en reglas de Firestore, las
  DEMUESTRA (atacante anónimo) → repara (mínimo privilegio, LLM propone +
  evaluador valida) → verifica (re-ataca hasta DENY). Loop scan→prove→fix→verify.
- Demo en vivo: https://fuga-two.vercel.app (tiene un command center con el preset
  "Clínica MediCloud").
- Repo: https://github.com/JuanMCanchala/fuga
- Caso de uso del demo: app de telemedicina "MediCloud" (examples/clinica-vulnerable)
  con reglas vulnerables: lectura pública de historias clínicas, pagos públicos
  (tarjeta+CVV), list público de la agenda, create anónimo por type-check, y una
  colección segura de control. FUGA exfiltra en vivo la historia clínica de un
  paciente (cédula, diagnóstico) y la tarjeta de crédito, en rojo.
- Componentes: evaluador de reglas propio en TypeScript (oráculo portátil sin
  Java), RAG sobre el código cliente (infiere esquema y PII por colección),
  LLM pluggable (Amazon Bedrock en la nube / Ollama local / plantilla), servidor
  MCP (fuga_scan/fuga_prove/fuga_fix), y un agente Kiro `fuga-auditor`.
- AWS: Amazon Bedrock como motor LLM. Kiro: construido con su flujo spec-driven
  (specs/steering/hooks/agents en .kiro/), y Kiro auditó y probó FUGA
  (docs/kiro-review.md, docs/kiro-test-report.md).

## Formato del guion
Una tabla o secciones por ESCENA con: rango de tiempo (que sume ≤5:00), "En
pantalla" (qué mostrar/qué click), y "Narración" (el texto exacto a decir, en
español, tono claro y con gancho). Estructura sugerida:
0:00–0:30 Hook + el problema (el antipatrón `allow read, write: if true`).
0:30–1:10 Qué es FUGA y su diferencia (prueba, no advierte).
1:10–3:00 DEMO en vivo en el command center con el preset "Clínica MediCloud":
  mostrar SCAN (riesgo 100), PROVE (historia clínica + tarjeta exfiltradas en
  rojo), FIX (reglas endurecidas) y VERIFY (fuga eliminada). Es el corazón.
3:00–4:00 Cómo funciona por dentro (evaluador propio, RAG por colección, MCP).
4:00–4:40 AWS (Bedrock) + Kiro (spec-driven, agente fuga-auditor, auditoría).
4:40–5:00 Cierre: impacto, repo y demo, llamada a la acción.

Al final agrega una sección "Checklist de grabación" (qué tener abierto, resolución
1080p, no mostrar datos sensibles reales, mostrar el repo y el demo) y una lista de
"Frases clave" memorables.

Escribe SOLO `docs/video-guion.md`.
