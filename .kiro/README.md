# FUGA construido con Kiro

Este directorio contiene los artefactos de [Kiro](https://kiro.dev) que guiaron
el desarrollo de FUGA. El proyecto usó el flujo **spec-driven** de Kiro (specs →
steering → hooks) y la propia CLI de Kiro para generar, probar y auditar el
código.

## Estructura

```
.kiro/
├─ specs/fuga-agent/       Flujo spec-driven: requirements → design → tasks
│  ├─ requirements.md      Historias de usuario + criterios (formato EARS)
│  ├─ design.md            Arquitectura y decisiones
│  └─ tasks.md             Plan de implementación (con estado)
├─ steering/               Contexto persistente inyectado en cada sesión de Kiro
│  ├─ product.md           (inclusion: always) qué es y por qué
│  ├─ tech.md              (inclusion: always) stack y decisiones
│  ├─ structure.md         (inclusion: always) organización del repo
│  └─ firestore-rules.md   (inclusion: fileMatch **/*.rules) guía dirigida
├─ agents/
│  └─ fuga-auditor.json    Agente Kiro CLI que audita reglas usando el MCP de FUGA
├─ hooks/
│  └─ fuga-scan-on-rules-save.kiro.hook  Corre FUGA al guardar un .rules
├─ settings/
│  └─ mcp.json             Registra el servidor MCP de FUGA en Kiro
└─ prompts/                Prompts de orquestación ejecutados con `kiro-cli chat`
   ├─ logo.md, site.md, presentacion.md
   ├─ test-fuga.md         Kiro corrió los tests + CLI de FUGA
   └─ review-fuga.md       Kiro auditó FUGA (ver docs/kiro-review.md)
```

## Qué hizo Kiro en este proyecto

- **Spec-driven**: los specs de `specs/fuga-agent/` definieron requisitos, diseño
  y tareas antes de codificar.
- **Generación con `kiro-cli chat`** (headless): Kiro construyó el logo SVG, el
  sitio web con hero animado y el command center, y la página de presentación.
  Los prompts exactos están en `prompts/`.
- **Pruebas**: Kiro ejecutó `npm test` y el flujo `scan/prove/fix/verify` de la
  CLI de FUGA (ver `docs/kiro-test-report.md`).
- **Auditoría**: Kiro revisó el código y estresó el oráculo, encontrando bugs
  reales (ver `docs/kiro-review.md`); sus hallazgos se remediaron.
- **Integración MCP**: FUGA se expone como servidor MCP y el agente
  `fuga-auditor` lo consume desde Kiro.

## Reutilizar el agente

```bash
# Desde la raíz del repo, con el MCP de FUGA construido (npm run build):
kiro-cli chat --agent fuga-auditor
```
