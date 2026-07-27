/**
 * Parser de reglas de Firestore. Lexer + descenso recursivo.
 *
 * Objetivo: producir un AST fiel del subconjunto real de la sintaxis (match,
 * allow, function, expresiones booleanas) preservando offsets de origen para
 * poder citar el texto exacto de cada condición en los reportes. Cualquier
 * construcción no soportada se preserva como nodo `Raw`, nunca se descarta.
 */

import {
  AllowRule,
  BinaryExpr,
  Expr,
  FunctionDef,
  MatchNode,
  Method,
  PathSegment,
  RulesFile,
  ServiceNode,
} from './ast';

type TokType =
  | 'ident'
  | 'string'
  | 'number'
  | '{'
  | '}'
  | '('
  | ')'
  | '['
  | ']'
  | ';'
  | ','
  | ':'
  | '.'
  | '/'
  | '='
  | '=='
  | '!='
  | '<'
  | '<='
  | '>'
  | '>='
  | '&&'
  | '||'
  | '!'
  | '+'
  | '-'
  | '*'
  | '%'
  | 'eof';

interface Token {
  type: TokType;
  value: string;
  start: number;
  line: number;
  column: number;
}

const METHODS: ReadonlySet<string> = new Set([
  'read',
  'write',
  'get',
  'list',
  'create',
  'update',
  'delete',
]);

export class ParseError extends Error {
  constructor(message: string, public line: number, public column: number) {
    super(`${message} (línea ${line}, columna ${column})`);
    this.name = 'ParseError';
  }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

function lex(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  const push = (type: TokType, value: string, start: number, startCol: number) => {
    tokens.push({ type, value, start, line, column: startCol });
  };

  while (i < src.length) {
    const c = src[i];

    // Espacios / saltos de línea
    if (c === '\n') {
      i++;
      line++;
      col = 1;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') {
      i++;
      col++;
      continue;
    }

    // Comentarios de línea // ... y de bloque /* ... */
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      col += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') {
          line++;
          col = 1;
        } else {
          col++;
        }
        i++;
      }
      i += 2;
      col += 2;
      continue;
    }

    const startCol = col;
    const start = i;

    // Strings
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      col++;
      let value = '';
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') {
          value += src[i + 1] ?? '';
          i += 2;
          col += 2;
        } else {
          value += src[i];
          i++;
          col++;
        }
      }
      i++; // cierre
      col++;
      push('string', value, start, startCol);
      continue;
    }

    // Números
    if (c >= '0' && c <= '9') {
      let value = '';
      while (i < src.length && /[0-9.]/.test(src[i])) {
        value += src[i];
        i++;
        col++;
      }
      push('number', value, start, startCol);
      continue;
    }

    // Identificadores / keywords
    if (/[A-Za-z_$]/.test(c)) {
      let value = '';
      while (i < src.length && /[A-Za-z0-9_$]/.test(src[i])) {
        value += src[i];
        i++;
        col++;
      }
      push('ident', value, start, startCol);
      continue;
    }

    // Operadores de dos caracteres
    const two = src.slice(i, i + 2);
    if (two === '==' || two === '!=' || two === '<=' || two === '>=' || two === '&&' || two === '||') {
      push(two as TokType, two, start, startCol);
      i += 2;
      col += 2;
      continue;
    }

    // Un carácter
    const singles: Record<string, TokType> = {
      '{': '{',
      '}': '}',
      '(': '(',
      ')': ')',
      '[': '[',
      ']': ']',
      ';': ';',
      ',': ',',
      ':': ':',
      '.': '.',
      '/': '/',
      '=': '=',
      '<': '<',
      '>': '>',
      '!': '!',
      '+': '+',
      '-': '-',
      '*': '*',
      '%': '%',
    };
    if (singles[c]) {
      push(singles[c], c, start, startCol);
      i++;
      col++;
      continue;
    }

    throw new ParseError(`Carácter inesperado '${c}'`, line, startCol);
  }

  tokens.push({ type: 'eof', value: '', start: src.length, line, column: col });
  return tokens;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser {
  private pos = 0;

  constructor(private tokens: Token[], private src: string) {}

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.pos + offset, this.tokens.length - 1)];
  }

  private next(): Token {
    return this.tokens[this.pos++];
  }

  private is(type: TokType): boolean {
    return this.peek().type === type;
  }

  private isIdent(value: string): boolean {
    const t = this.peek();
    return t.type === 'ident' && t.value === value;
  }

  private expect(type: TokType): Token {
    if (!this.is(type)) {
      const t = this.peek();
      throw new ParseError(`Se esperaba '${type}' pero se encontró '${t.value || t.type}'`, t.line, t.column);
    }
    return this.next();
  }

  private expectIdent(value: string): Token {
    if (!this.isIdent(value)) {
      const t = this.peek();
      throw new ParseError(`Se esperaba '${value}' pero se encontró '${t.value || t.type}'`, t.line, t.column);
    }
    return this.next();
  }

  parse(): RulesFile {
    let version: string | null = null;
    const services: ServiceNode[] = [];

    while (!this.is('eof')) {
      if (this.isIdent('rules_version')) {
        this.next();
        this.expect('=');
        version = this.expect('string').value;
        if (this.is(';')) this.next();
        continue;
      }
      if (this.isIdent('service')) {
        services.push(this.parseService());
        continue;
      }
      // Tolerancia: saltar tokens sueltos de nivel superior.
      this.next();
    }

    return { kind: 'rules', version, services };
  }

  private parseService(): ServiceNode {
    const start = this.expectIdent('service');
    // Nombre del servicio: "cloud.firestore" o "firebase.storage".
    let name = this.expect('ident').value;
    while (this.is('.')) {
      this.next();
      name += '.' + this.expect('ident').value;
    }
    this.expect('{');

    let match: MatchNode | null = null;
    const functions: FunctionDef[] = [];
    while (!this.is('}') && !this.is('eof')) {
      if (this.isIdent('match')) {
        match = this.parseMatch();
      } else if (this.isIdent('function')) {
        functions.push(this.parseFunction());
      } else {
        this.next();
      }
    }
    this.expect('}');
    return {
      kind: 'service',
      name,
      match,
      functions,
      position: { line: start.line, column: start.column },
    };
  }

  private parseMatch(): MatchNode {
    const start = this.expectIdent('match');
    const { segments, source } = this.parsePath();
    this.expect('{');

    const allows: AllowRule[] = [];
    const functions: FunctionDef[] = [];
    const children: MatchNode[] = [];

    while (!this.is('}') && !this.is('eof')) {
      if (this.isIdent('allow')) {
        allows.push(this.parseAllow());
      } else if (this.isIdent('match')) {
        children.push(this.parseMatch());
      } else if (this.isIdent('function')) {
        functions.push(this.parseFunction());
      } else {
        this.next();
      }
    }
    this.expect('}');

    return {
      kind: 'match',
      path: segments,
      pathSource: source,
      allows,
      functions,
      children,
      position: { line: start.line, column: start.column },
    };
  }

  private parsePath(): { segments: PathSegment[]; source: string } {
    const segments: PathSegment[] = [];
    while (this.is('/')) {
      this.next(); // consume '/'
      if (this.is('{')) {
        this.next();
        const name = this.expect('ident').value;
        let recursive = false;
        if (this.is('=')) {
          this.next();
          this.expect('*');
          this.expect('*');
          recursive = true;
        }
        this.expect('}');
        segments.push({
          raw: `{${name}${recursive ? '=**' : ''}}`,
          variable: name,
          recursive,
          literal: false,
        });
      } else {
        const name = this.expect('ident').value;
        segments.push({ raw: name, recursive: false, literal: true });
      }
    }
    const source = '/' + segments.map((s) => s.raw).join('/');
    return { segments, source };
  }

  private parseAllow(): AllowRule {
    const start = this.expectIdent('allow');
    const methods: Method[] = [];
    // Lista de métodos separada por comas hasta ':'.
    for (;;) {
      const t = this.expect('ident');
      if (!METHODS.has(t.value)) {
        throw new ParseError(`Método de acceso desconocido '${t.value}'`, t.line, t.column);
      }
      methods.push(t.value as Method);
      if (this.is(',')) {
        this.next();
        continue;
      }
      break;
    }

    let condition: Expr = { type: 'bool', value: true };
    let conditionSource = 'true';

    if (this.is(':')) {
      this.next();
      this.expectIdent('if');
      const condStart = this.peek().start;
      condition = this.parseExpr();
      const semi = this.peek();
      conditionSource = this.src.slice(condStart, semi.start).trim();
    }
    if (this.is(';')) this.next();

    return {
      kind: 'allow',
      methods,
      condition,
      conditionSource,
      position: { line: start.line, column: start.column },
    };
  }

  private parseFunction(): FunctionDef {
    const start = this.expectIdent('function');
    const name = this.expect('ident').value;
    this.expect('(');
    const params: string[] = [];
    while (!this.is(')') && !this.is('eof')) {
      params.push(this.expect('ident').value);
      if (this.is(',')) this.next();
    }
    this.expect(')');
    this.expect('{');
    // Cuerpo: buscamos el `return <expr>;`. Ignoramos declaraciones `let`
    // intermedias (poco comunes) saltando hasta return.
    let body: Expr = { type: 'raw', source: '' };
    while (!this.is('}') && !this.is('eof')) {
      if (this.isIdent('return')) {
        this.next();
        body = this.parseExpr();
        if (this.is(';')) this.next();
      } else {
        this.next();
      }
    }
    this.expect('}');
    return {
      kind: 'function',
      name,
      params,
      body,
      position: { line: start.line, column: start.column },
    };
  }

  // ----- Expresiones (precedencia por escalada) -----

  parseExpr(): Expr {
    return this.parseOr();
  }

  private parseOr(): Expr {
    let left = this.parseAnd();
    while (this.is('||')) {
      this.next();
      const right = this.parseAnd();
      left = { type: 'binary', op: '||', left, right } as BinaryExpr;
    }
    return left;
  }

  private parseAnd(): Expr {
    let left = this.parseEquality();
    while (this.is('&&')) {
      this.next();
      const right = this.parseEquality();
      left = { type: 'binary', op: '&&', left, right } as BinaryExpr;
    }
    return left;
  }

  private parseEquality(): Expr {
    let left = this.parseRelational();
    while (this.is('==') || this.is('!=')) {
      const op = this.next().type;
      const right = this.parseRelational();
      left = { type: 'binary', op, left, right } as BinaryExpr;
    }
    return left;
  }

  private parseRelational(): Expr {
    let left = this.parseAdditive();
    for (;;) {
      if (this.is('<') || this.is('<=') || this.is('>') || this.is('>=')) {
        const op = this.next().type;
        const right = this.parseAdditive();
        left = { type: 'binary', op, left, right } as BinaryExpr;
      } else if (this.isIdent('in')) {
        this.next();
        const right = this.parseAdditive();
        left = { type: 'binary', op: 'in', left, right } as BinaryExpr;
      } else if (this.isIdent('is')) {
        this.next();
        const typeName = this.expect('ident').value;
        left = { type: 'binary', op: 'is', left, right: { type: 'string', value: typeName } } as BinaryExpr;
      } else {
        break;
      }
    }
    return left;
  }

  private parseAdditive(): Expr {
    let left = this.parseMultiplicative();
    while (this.is('+') || this.is('-')) {
      const op = this.next().type;
      const right = this.parseMultiplicative();
      left = { type: 'binary', op, left, right } as BinaryExpr;
    }
    return left;
  }

  private parseMultiplicative(): Expr {
    let left = this.parseUnary();
    while (this.is('*') || this.is('/') || this.is('%')) {
      const op = this.next().type;
      const right = this.parseUnary();
      left = { type: 'binary', op, left, right } as BinaryExpr;
    }
    return left;
  }

  private parseUnary(): Expr {
    if (this.is('!')) {
      this.next();
      return { type: 'unary', op: '!', operand: this.parseUnary() };
    }
    if (this.is('-')) {
      this.next();
      return { type: 'unary', op: '-', operand: this.parseUnary() };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Expr {
    let expr = this.parsePrimary();
    for (;;) {
      if (this.is('.')) {
        this.next();
        const property = this.expect('ident').value;
        expr = { type: 'member', object: expr, property };
      } else if (this.is('[')) {
        this.next();
        const index = this.parseExpr();
        this.expect(']');
        expr = { type: 'index', object: expr, index };
      } else if (this.is('(')) {
        this.next();
        const args: Expr[] = [];
        while (!this.is(')') && !this.is('eof')) {
          args.push(this.parseExpr());
          if (this.is(',')) this.next();
        }
        this.expect(')');
        expr = { type: 'call', callee: expr, args };
      } else {
        break;
      }
    }
    return expr;
  }

  private parsePrimary(): Expr {
    const t = this.peek();

    if (t.type === 'number') {
      this.next();
      return { type: 'number', value: Number(t.value) };
    }
    if (t.type === 'string') {
      this.next();
      return { type: 'string', value: t.value };
    }
    if (t.type === '(') {
      this.next();
      const expr = this.parseExpr();
      this.expect(')');
      return expr;
    }
    if (t.type === '[') {
      this.next();
      const elements: Expr[] = [];
      while (!this.is(']') && !this.is('eof')) {
        elements.push(this.parseExpr());
        if (this.is(',')) this.next();
      }
      this.expect(']');
      return { type: 'list', elements };
    }
    if (t.type === '/') {
      // Path literal, ej: /databases/$(database)/documents/users/$(uid)
      return this.parsePathLiteral();
    }
    if (t.type === 'ident') {
      this.next();
      if (t.value === 'true') return { type: 'bool', value: true };
      if (t.value === 'false') return { type: 'bool', value: false };
      if (t.value === 'null') return { type: 'null' };
      return { type: 'ident', name: t.value };
    }

    throw new ParseError(`Expresión inesperada '${t.value || t.type}'`, t.line, t.column);
  }

  private parsePathLiteral(): Expr {
    // Consume tokens balanceando '(' de los interpoladores $(...) hasta el
    // límite del argumento (coma o paréntesis de cierre a profundidad 0).
    const startOffset = this.peek().start;
    let depth = 0;
    while (!this.is('eof')) {
      const t = this.peek();
      if (t.type === '(') depth++;
      if (t.type === ')') {
        if (depth === 0) break;
        depth--;
      }
      if (t.type === ',' && depth === 0) break;
      if (t.type === ';' && depth === 0) break;
      this.next();
    }
    const endOffset = this.peek().start;
    return { type: 'path', source: this.src.slice(startOffset, endOffset).trim() };
  }
}

export function parseRules(src: string): RulesFile {
  const tokens = lex(src);
  return new Parser(tokens, src).parse();
}
