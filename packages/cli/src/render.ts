/** Utilidades de salida en terminal: color ANSI y formato. */

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

function wrap(code: number, s: string): string {
  return useColor ? `\x1b[${code}m${s}\x1b[0m` : s;
}

export const c = {
  red: (s: string) => wrap(31, s),
  green: (s: string) => wrap(32, s),
  yellow: (s: string) => wrap(33, s),
  blue: (s: string) => wrap(34, s),
  magenta: (s: string) => wrap(35, s),
  cyan: (s: string) => wrap(36, s),
  gray: (s: string) => wrap(90, s),
  bold: (s: string) => wrap(1, s),
  dim: (s: string) => wrap(2, s),
};

export function severityTag(sev: string): string {
  switch (sev) {
    case 'critical':
      return c.bold(c.red('CRÍTICO'));
    case 'high':
      return c.red('ALTO');
    case 'medium':
      return c.yellow('MEDIO');
    case 'low':
      return c.blue('BAJO');
    default:
      return c.gray('INFO');
  }
}

export function banner(): string {
  return c.bold(c.magenta('  FUGA')) + c.dim('  ·  detecta y prueba fugas de datos en reglas Firestore');
}

export function riskBar(score: number): string {
  const filled = Math.round((score / 100) * 20);
  const bar = '█'.repeat(filled) + '░'.repeat(20 - filled);
  const color = score >= 70 ? c.red : score >= 40 ? c.yellow : c.green;
  return `${color(bar)} ${color(String(score))}/100`;
}

export function rule(): string {
  return c.gray('─'.repeat(64));
}
