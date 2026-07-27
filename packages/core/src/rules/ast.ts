/**
 * AST de reglas de seguridad de Firestore (rules_version = '2').
 *
 * No es una gramática CEL completa: cubre el subconjunto que aparece en reglas
 * reales de producción (allow con condiciones booleanas, comparaciones, acceso a
 * miembros, get()/exists(), funciones auxiliares y variables de path). Lo que no
 * se reconoce se preserva como `Raw` para que el análisis estático nunca pierda
 * información aunque el evaluador no pueda resolver la expresión.
 */

export type Method =
  | 'read'
  | 'write'
  | 'get'
  | 'list'
  | 'create'
  | 'update'
  | 'delete';

export interface Position {
  line: number;
  column: number;
}

/** Segmento de un path dentro de `match`: literal, captura simple o recursiva. */
export interface PathSegment {
  /** Texto tal cual aparece: "users", "{uid}", "{document=**}". */
  raw: string;
  /** Nombre de la variable capturada, si es `{var}` o `{var=**}`. */
  variable?: string;
  /** true si es un comodín recursivo `{x=**}` que matchea cero o más segmentos. */
  recursive: boolean;
  /** true si es un literal fijo (no captura). */
  literal: boolean;
}

export interface AllowRule {
  kind: 'allow';
  methods: Method[];
  condition: Expr;
  position: Position;
  /** Texto original de la condición, para reportes legibles. */
  conditionSource: string;
}

export interface FunctionDef {
  kind: 'function';
  name: string;
  params: string[];
  /** Cuerpo simplificado: la expresión devuelta por el `return`. */
  body: Expr;
  position: Position;
}

export interface MatchNode {
  kind: 'match';
  path: PathSegment[];
  /** Path original completo, ej "/users/{uid}". */
  pathSource: string;
  allows: AllowRule[];
  functions: FunctionDef[];
  children: MatchNode[];
  position: Position;
}

export interface ServiceNode {
  kind: 'service';
  /** "cloud.firestore" o "firebase.storage". */
  name: string;
  match: MatchNode | null;
  functions: FunctionDef[];
  position: Position;
}

export interface RulesFile {
  kind: 'rules';
  version: string | null;
  services: ServiceNode[];
}

// ---------------------------------------------------------------------------
// Expresiones
// ---------------------------------------------------------------------------

export type Expr =
  | BoolLiteral
  | NumberLiteral
  | StringLiteral
  | NullLiteral
  | ListLiteral
  | Identifier
  | MemberAccess
  | IndexAccess
  | CallExpr
  | UnaryExpr
  | BinaryExpr
  | PathExpr
  | Raw;

export interface BoolLiteral {
  type: 'bool';
  value: boolean;
}
export interface NumberLiteral {
  type: 'number';
  value: number;
}
export interface StringLiteral {
  type: 'string';
  value: string;
}
export interface NullLiteral {
  type: 'null';
}
export interface ListLiteral {
  type: 'list';
  elements: Expr[];
}
export interface Identifier {
  type: 'ident';
  name: string;
}
export interface MemberAccess {
  type: 'member';
  object: Expr;
  property: string;
}
export interface IndexAccess {
  type: 'index';
  object: Expr;
  index: Expr;
}
export interface CallExpr {
  type: 'call';
  callee: Expr;
  args: Expr[];
}
export interface UnaryExpr {
  type: 'unary';
  op: '!' | '-';
  operand: Expr;
}
export interface BinaryExpr {
  type: 'binary';
  op: string; // && || == != < <= > >= in + - * /
  left: Expr;
  right: Expr;
}
/** Path literal usado en get()/exists(): /databases/$(x)/documents/... */
export interface PathExpr {
  type: 'path';
  source: string;
}
/** Expresión no reconocida; se conserva su texto. */
export interface Raw {
  type: 'raw';
  source: string;
}
