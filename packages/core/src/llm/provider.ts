/**
 * Capa LLM pluggable. FUGA usa el LLM para PROPONER (reglas endurecidas,
 * explicaciones), nunca como única fuente de verdad: toda regla que sugiere un
 * LLM se re-verifica con el evaluador (proponer/disponer). Por eso el sistema
 * funciona igual sin ningún LLM, con un fallback determinista.
 *
 * Orden de resolución (configurable con FUGA_LLM):
 *   bedrock  -> Amazon Bedrock (AWS, nube)      [import dinámico del SDK]
 *   ollama   -> modelo local (privacidad)        [HTTP localhost:11434]
 *   anthropic-> Claude vía API                    [HTTP api.anthropic.com]
 *   none     -> sin LLM (plantillas deterministas)
 */

export interface LlmMessage {
  role: 'system' | 'user';
  content: string;
}

export interface LlmProvider {
  name: string;
  available(): Promise<boolean>;
  complete(messages: LlmMessage[], opts?: { maxTokens?: number; temperature?: number }): Promise<string>;
}

// --- Bedrock (AWS) -----------------------------------------------------------

class BedrockProvider implements LlmProvider {
  name = 'bedrock';
  // Bedrock exige normalmente un *inference profile* (prefijo us./eu./apac.) en
  // vez del model id on-demand. Por defecto usamos el perfil de Claude Haiku en
  // US; sobreescribe con FUGA_BEDROCK_MODEL.
  private modelId = process.env.FUGA_BEDROCK_MODEL ?? 'us.anthropic.claude-3-haiku-20240307-v1:0';
  // Si no hay AWS_REGION, dejamos que el SDK la resuelva de la config compartida
  // (aws configure / perfil), en vez de forzar una región equivocada.
  private region = process.env.AWS_REGION;

  // Especificador computado: el SDK es una dependencia OPCIONAL, no debe exigirse
  // en tiempo de compilación ni si el usuario no usa Bedrock.
  private sdkModule = '@aws-sdk/client-bedrock-runtime';

  async available(): Promise<boolean> {
    if (process.env.FUGA_LLM && process.env.FUGA_LLM !== 'bedrock') return false;
    // Explícito (FUGA_LLM=bedrock) => confiamos en la cadena de credenciales del
    // SDK (env, config compartida, SSO, IMDS). En auto-detección exigimos señal.
    const explicit = process.env.FUGA_LLM === 'bedrock';
    const hasCreds = Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_PROFILE);
    if (!explicit && !hasCreds) return false;
    try {
      await import(this.sdkModule);
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: LlmMessage[], opts?: { maxTokens?: number; temperature?: number }): Promise<string> {
    const { BedrockRuntimeClient, InvokeModelCommand } = await import(this.sdkModule);
    const client = new BedrockRuntimeClient(this.region ? { region: this.region } : {});
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const user = messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n');
    const body = {
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: opts?.maxTokens ?? 1500,
      temperature: opts?.temperature ?? 0,
      system,
      messages: [{ role: 'user', content: user }],
    };
    const res = await client.send(
      new InvokeModelCommand({
        modelId: this.modelId,
        contentType: 'application/json',
        accept: 'application/json',
        body: JSON.stringify(body),
      }),
    );
    const decoded = JSON.parse(new TextDecoder().decode(res.body));
    return decoded.content?.[0]?.text ?? '';
  }
}

// --- Ollama (local) ----------------------------------------------------------

class OllamaProvider implements LlmProvider {
  name = 'ollama';
  private model = process.env.FUGA_OLLAMA_MODEL ?? 'llama3.1';
  private host = process.env.OLLAMA_HOST ?? 'http://localhost:11434';

  async available(): Promise<boolean> {
    if (process.env.FUGA_LLM && process.env.FUGA_LLM !== 'ollama') return false;
    try {
      const res = await fetch(`${this.host}/api/tags`, { signal: AbortSignal.timeout(1500) });
      return res.ok;
    } catch {
      return false;
    }
  }

  async complete(messages: LlmMessage[], opts?: { temperature?: number }): Promise<string> {
    const prompt = messages.map((m) => (m.role === 'system' ? `[sistema]\n${m.content}` : m.content)).join('\n\n');
    const res = await fetch(`${this.host}/api/generate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        prompt,
        stream: false,
        options: { temperature: opts?.temperature ?? 0 },
      }),
    });
    const data = (await res.json()) as { response?: string };
    return data.response ?? '';
  }
}

// --- Anthropic (API) ---------------------------------------------------------

class AnthropicProvider implements LlmProvider {
  name = 'anthropic';
  private model = process.env.FUGA_ANTHROPIC_MODEL ?? 'claude-3-5-sonnet-latest';

  async available(): Promise<boolean> {
    if (process.env.FUGA_LLM && process.env.FUGA_LLM !== 'anthropic') return false;
    return Boolean(process.env.ANTHROPIC_API_KEY);
  }

  async complete(messages: LlmMessage[], opts?: { maxTokens?: number; temperature?: number }): Promise<string> {
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const user = messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n');
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY!,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: opts?.maxTokens ?? 1500,
        temperature: opts?.temperature ?? 0,
        system,
        messages: [{ role: 'user', content: user }],
      }),
    });
    const data = (await res.json()) as { content?: Array<{ text?: string }> };
    return data.content?.[0]?.text ?? '';
  }
}

// --- Kiro (CLI headless) -----------------------------------------------------

/**
 * Usa el CLI de Kiro en modo headless como motor LLM. Consume los créditos de
 * Kiro del usuario. Solo funciona donde `kiro-cli` está instalado y logueado
 * (uso local / CLI), NO en despliegues serverless. Se activa con FUGA_LLM=kiro.
 */
class KiroProvider implements LlmProvider {
  name = 'kiro';
  private bin = process.env.FUGA_KIRO_BIN ?? 'kiro-cli';

  async available(): Promise<boolean> {
    return process.env.FUGA_LLM === 'kiro';
  }

  async complete(messages: LlmMessage[]): Promise<string> {
    const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n');
    const user = messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n');
    const prompt = (system ? `[contexto]\n${system}\n\n` : '') + user;
    try {
      const { spawn } = await import('node:child_process');
      return await new Promise<string>((resolve) => {
        // --trust-tools= (vacío) => chat puro, sin acceso a herramientas.
        const child = spawn(this.bin, ['chat', '--no-interactive', '--trust-tools=', prompt], {
          env: process.env,
        });
        let out = '';
        child.stdout?.on('data', (d) => (out += d.toString()));
        child.on('error', () => resolve(''));
        child.on('close', () => resolve(stripAnsi(out)));
        setTimeout(() => {
          try {
            child.kill();
          } catch {
            /* noop */
          }
          resolve(stripAnsi(out));
        }, 120_000);
      });
    } catch {
      return '';
    }
  }
}

function stripAnsi(s: string): string {
  // Quita secuencias de escape ANSI (colores, cursor, spinners) del CLI.
  return s.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').replace(/\r/g, '');
}

// --- Null (sin LLM) ----------------------------------------------------------

class NullProvider implements LlmProvider {
  name = 'none';
  async available(): Promise<boolean> {
    return true;
  }
  async complete(): Promise<string> {
    return '';
  }
}

const PROVIDERS: LlmProvider[] = [
  new KiroProvider(),
  new BedrockProvider(),
  new OllamaProvider(),
  new AnthropicProvider(),
];

/** Selecciona el primer proveedor disponible según env; nunca lanza. */
export async function selectProvider(): Promise<LlmProvider> {
  if (process.env.FUGA_LLM === 'none') return new NullProvider();
  for (const p of PROVIDERS) {
    try {
      if (await p.available()) return p;
    } catch {
      // ignora y prueba el siguiente
    }
  }
  return new NullProvider();
}
