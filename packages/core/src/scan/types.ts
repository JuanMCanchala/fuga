import { Method } from '../rules/ast';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export interface Finding {
  /** Código estable, ej "FUGA001". */
  code: string;
  title: string;
  severity: Severity;
  /** Path del bloque match afectado. */
  matchPath: string;
  line: number;
  methods: Method[];
  /** Texto original de la condición. */
  condition: string;
  /** Por qué es un problema. */
  rationale: string;
  /** Cómo arreglarlo (guía corta; el fix real lo genera `harden`). */
  recommendation: string;
  /** true si el evaluador confirmó explotación por un atacante anónimo. */
  proven: boolean;
  /** Colección inferida por el RAG, si aplica. */
  collection?: string;
  /** Campos PII expuestos, inferidos por el RAG. */
  piiFields?: string[];
}

export interface ScanReport {
  service: string;
  version: string | null;
  findings: Finding[];
  /** Resumen por severidad. */
  summary: Record<Severity, number>;
  /** Puntaje de riesgo 0-100 (100 = crítico y probado). */
  riskScore: number;
}
