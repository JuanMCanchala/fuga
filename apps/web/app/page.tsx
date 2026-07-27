'use client';

import React, { useState } from 'react';
import { Shield, Bug, Wrench, Check, Alert, Play, Spinner, Search, Github } from './icons';

const EXAMPLE_VULN = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`;

const EXAMPLE_SAFE = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
    match /pagos/{id} {
      allow read, write: if request.auth != null
        && request.auth.uid == resource.data.ownerId;
    }
  }
}`;

const EXAMPLE_CODE = `import { collection, addDoc } from 'firebase/firestore';
const pagos = collection(db, 'pagos');
const usuarios = collection(db, 'usuarios');
await addDoc(pagos, { ownerId: uid, monto, numeroTarjeta, cvv });
await addDoc(usuarios, { nombre, email, telefono });`;

interface Finding {
  code: string;
  title: string;
  severity: string;
  matchPath: string;
  line: number;
  condition: string;
  rationale: string;
  recommendation: string;
  proven: boolean;
  piiFields?: string[];
}
interface Leak {
  collection: string;
  path: string;
  method: string;
  verdict: string;
  proven: boolean;
  exfiltrated?: Record<string, unknown>[];
  piiFields?: string[];
}
interface Result {
  llm: string;
  scan: { riskScore: number; summary: Record<string, number>; findings: Finding[] };
  exploit: { leaks: Leak[]; totalDocsExposed: number; clean: boolean };
  fix: { rules: string; source: string; validated: boolean };
  verify: { clean: boolean; remaining: number };
  error?: string;
  detail?: string;
}

function riskColor(score: number): string {
  if (score >= 70) return 'var(--danger)';
  if (score >= 40) return 'var(--warn)';
  return 'var(--ok)';
}

export default function Home() {
  const [rules, setRules] = useState(EXAMPLE_VULN);
  const [code, setCode] = useState(EXAMPLE_CODE);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rules, code }),
      });
      const data = (await res.json()) as Result;
      if (!res.ok || data.error) {
        setError(data.detail || data.error || 'Error desconocido');
      } else {
        setResult(data);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="wrap">
      <header className="top">
        <Shield size={30} />
        <span className="logo">FUGA</span>
      </header>
      <p className="tagline">
        Las reglas de Firestore mal configuradas (<code>allow read, write: if true</code>) son una de las causas
        más comunes de fuga de datos. FUGA no solo advierte: <strong>lanza un atacante anónimo</strong> contra tus
        reglas, te muestra los datos que se filtrarían, y genera un fix de mínimo privilegio que{' '}
        <strong>vuelve a verificar</strong>.
      </p>

      <div className="grid">
        <div className="card">
          <h2>
            <Shield size={14} /> Reglas de Firestore
          </h2>
          <textarea className="rules" value={rules} onChange={(e) => setRules(e.target.value)} spellCheck={false} />
          <div className="examples">
            <button className="btn ghost" onClick={() => setRules(EXAMPLE_VULN)}>
              Ejemplo vulnerable
            </button>
            <button className="btn ghost" onClick={() => setRules(EXAMPLE_SAFE)}>
              Ejemplo seguro
            </button>
          </div>
        </div>

        <div className="card">
          <h2>
            <Search size={14} /> Código cliente (opcional · RAG de esquema y PII)
          </h2>
          <textarea className="code" value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
          <p className="meta">
            FUGA lee tu código para inferir qué colecciones existen y qué campos son sensibles. Así distingue una
            fuga en <code>/logs</code> de una en <code>/pagos</code>.
          </p>
          <button className="btn" onClick={run} disabled={loading}>
            {loading ? <Spinner size={18} className="spin" /> : <Play size={18} />}
            {loading ? 'Atacando…' : 'Probar la fuga'}
          </button>
        </div>
      </div>

      {error && (
        <div className="stages">
          <div className="card">
            <p className="err">Error: {error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="stages">
          {/* 1. SCAN */}
          <div className="stage">
            <div className="stage-head">
              <span className="stage-num">1</span>
              <Search size={18} />
              <span className="stage-title">Análisis estático</span>
              <span style={{ marginLeft: 'auto', color: 'var(--muted)', fontSize: 13 }}>
                motor LLM: {result.llm}
              </span>
            </div>
            <div className="stage-body">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <div className="riskbar" style={{ flex: 1 }}>
                  <span
                    style={{
                      width: `${result.scan.riskScore}%`,
                      background: riskColor(result.scan.riskScore),
                    }}
                  />
                </div>
                <strong style={{ color: riskColor(result.scan.riskScore) }}>{result.scan.riskScore}/100</strong>
              </div>
              {result.scan.findings.length === 0 && (
                <p className="verify-ok">
                  <Check size={18} /> Sin hallazgos: no hay acceso anónimo.
                </p>
              )}
              {result.scan.findings.map((f, i) => (
                <div className="finding" key={i}>
                  <div>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                    {f.proven && <span className="badge proven">probado</span>}
                    {f.piiFields && f.piiFields.length > 0 && (
                      <span className="badge pii">PII: {f.piiFields.join(', ')}</span>
                    )}
                    <strong style={{ marginLeft: 8 }}>
                      {f.code} · {f.title}
                    </strong>
                  </div>
                  <p className="meta">
                    <code>{f.matchPath}</code> (línea {f.line}) · condición <code>{f.condition}</code>
                  </p>
                  <p style={{ margin: '6px 0 0', fontSize: 14 }}>{f.rationale}</p>
                </div>
              ))}
            </div>
          </div>

          {/* 2. PROVE */}
          <div className="stage">
            <div className="stage-head">
              <span className="stage-num">2</span>
              <Bug size={18} />
              <span className="stage-title">Ataque anónimo — datos exfiltrables</span>
            </div>
            <div className="stage-body">
              {result.exploit.clean ? (
                <p className="verify-ok">
                  <Check size={18} /> El atacante anónimo quedó denegado. Nada que filtrar.
                </p>
              ) : (
                <>
                  <p style={{ color: 'var(--danger)', fontWeight: 700, marginTop: 0 }}>
                    <Alert size={16} /> {result.exploit.leaks.length} fugas probadas ·{' '}
                    {result.exploit.totalDocsExposed} documentos exfiltrables
                  </p>
                  {result.exploit.leaks.map((l, i) => (
                    <div className="leak" key={i}>
                      <div>
                        <span className="path">
                          {l.method === 'read' ? 'LEER' : 'ESCRIBIR'} {l.path}
                        </span>
                        {l.piiFields && l.piiFields.length > 0 && (
                          <span className="badge pii">PII: {l.piiFields.join(', ')}</span>
                        )}
                      </div>
                      {l.exfiltrated && (
                        <pre className="exfil">{JSON.stringify(l.exfiltrated, null, 2)}</pre>
                      )}
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>

          {/* 3. FIX */}
          <div className="stage">
            <div className="stage-head">
              <span className="stage-num">3</span>
              <Wrench size={18} />
              <span className="stage-title">Reglas endurecidas ({result.fix.source})</span>
            </div>
            <div className="stage-body">
              <pre className="rules">{result.fix.rules}</pre>
            </div>
          </div>

          {/* 4. VERIFY */}
          <div className="stage">
            <div className="stage-head">
              <span className="stage-num">4</span>
              <Check size={18} />
              <span className="stage-title">Verificación (loop cerrado)</span>
            </div>
            <div className="stage-body">
              {result.verify.clean ? (
                <p className="verify-ok">
                  <Check size={20} /> El mismo atacante ahora queda DENEGADO en todas las colecciones. Fuga
                  eliminada y verificada.
                </p>
              ) : (
                <p className="verify-bad">
                  <Alert size={18} /> Todavía quedan {result.verify.remaining} fugas. El fix no está completo.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="footer">
        <span className="pill">
          <Shield size={13} /> RAG + evaluador de reglas en TS
        </span>
        <span className="pill">MCP server</span>
        <span className="pill">Amazon Bedrock</span>
        <a
          href="https://github.com/JuanMCanchala/fuga"
          target="_blank"
          rel="noreferrer"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 10 }}
        >
          <Github size={15} /> github.com/JuanMCanchala/fuga
        </a>
      </div>
    </div>
  );
}
