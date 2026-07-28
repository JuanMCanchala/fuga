/**
 * @fuga/core — motor de FUGA.
 *
 * API pública usada por el CLI, el servidor MCP y el playground web.
 */

export * from './rules/ast';
export { parseRules, ParseError } from './rules/parser';
export {
  evaluate,
  probeAllow,
  listRules,
  samplePath,
  UNKNOWN,
} from './rules/evaluator';
export type {
  AccessRequest,
  AuthState,
  Decision,
  RuleMatch,
  Verdict,
  FlatAllow,
} from './rules/evaluator';

export { analyze } from './scan/analyzer';
export type { Finding, ScanReport, Severity } from './scan/types';
export { SEVERITY_ORDER } from './scan/types';

export {
  sensitivityOf,
  classifyFieldByLexicon,
  collectionSensitivity,
} from './rag/schema';
export type {
  SchemaModel,
  CollectionInfo,
  FieldInfo,
  PiiCategory,
  Sensitivity,
} from './rag/schema';
export { indexClientCode } from './rag/indexer';
export type { IndexInput } from './rag/indexer';
export { classifyFields } from './rag/pii';

export { prove } from './prove/attacker';
export type { ExploitReport, ExploitAttempt, SeededDb, ProveOptions } from './prove/attacker';
export { synthSeed, sampleValueFor } from './prove/seed';
export { emulatorTestSpec, emulatorFirebaseJson } from './prove/emulator';

export { harden, templateRules, templateTests } from './fix/harden';
export type { HardenInput, HardenResult } from './fix/harden';

export { selectProvider } from './llm/provider';
export type { LlmProvider, LlmMessage } from './llm/provider';

// Motor RTDB (Firebase Realtime Database)
export {
  parseRtdbRules,
  analyzeRtdb,
  proveRtdb,
  evaluateRtdb,
  hardenRtdb,
} from './rtdb/engine';
export type { RtdbRules } from './rtdb/engine';

// Motor Supabase (Postgres RLS)
export {
  parseSupabase,
  analyzeSupabase,
  proveSupabase,
  evaluateSupabase,
  hardenSupabase,
} from './supabase/engine';
export type { SupabaseSchema, TableModel, Policy } from './supabase/engine';
export { rtdbCollections } from './rtdb/engine';
export { synthSeedFor } from './prove/seed';

// Fuga entre usuarios (IDOR / cross-tenant) — el diferenciador
export {
  proveCrossTenantFirestore,
  proveCrossTenantSupabase,
  crossTenantFindings,
  VICTIM_UID,
  ATTACKER_UID,
} from './prove/multitenant';
export type { TenantLeak, TenantReport } from './prove/multitenant';

// Dispatcher multi-backend
export { runFuga, detectBackend } from './backends';
export type { Backend, RunResult, RunOptions } from './backends';
