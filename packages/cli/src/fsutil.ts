import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import type { IndexInput } from '@fuga/core';

const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', '.firebase']);

/** Localiza el archivo de reglas: --rules explícito, o firestore.rules por convención. */
export function findRulesFile(explicit: string | undefined, cwd: string): string | null {
  if (explicit) return existsSync(explicit) ? explicit : null;
  const candidates = ['firestore.rules', 'firebase/firestore.rules'];
  for (const cand of candidates) {
    const p = join(cwd, cand);
    if (existsSync(p)) return p;
  }
  return null;
}

export function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

/** Recolecta el código cliente para el RAG (limitado para no explotar en repos grandes). */
export function collectClientCode(root: string, maxFiles = 400): IndexInput[] {
  const out: IndexInput[] = [];
  const walk = (dir: string) => {
    if (out.length >= maxFiles) return;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (out.length >= maxFiles) return;
      if (SKIP_DIRS.has(name)) continue;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(full);
      } else if (CODE_EXT.has(extname(name))) {
        try {
          const content = readFileSync(full, 'utf8');
          if (content.includes('fire') || /collection|addDoc|setDoc|doc\(/.test(content)) {
            out.push({ file: relative(root, full), content });
          }
        } catch {
          // ignora archivos ilegibles
        }
      }
    }
  };
  walk(root);
  return out;
}
