/**
 * Modelo de esquema inferido y juicio de sensibilidad.
 *
 * La severidad de una fuga depende de QUÉ se filtra: `if true` sobre `/logs` es
 * ruido; sobre `/pagos` es una brecha notificable. Este módulo aporta el
 * conocimiento de dominio (léxico ES/EN de colecciones y campos sensibles) que
 * enriquece el análisis estático. Funciona sin ningún LLM; el RAG y Ollama solo
 * lo afinan.
 */

export type PiiCategory =
  | 'identidad'
  | 'contacto'
  | 'financiero'
  | 'credencial'
  | 'salud'
  | 'ubicacion'
  | 'menor'
  | 'ninguno';

export interface FieldInfo {
  name: string;
  pii: boolean;
  category: PiiCategory;
  /** De dónde salió la inferencia: 'lexico' | 'llm' | 'declarado'. */
  source?: string;
}

export interface CollectionInfo {
  name: string;
  fields: FieldInfo[];
  /** true si el nombre de la colección ya implica datos sensibles. */
  sensitiveByName: boolean;
}

export interface SchemaModel {
  collections: Record<string, CollectionInfo>;
}

export interface Sensitivity {
  sensitive: boolean;
  piiFields: string[];
  categories: PiiCategory[];
}

// Colecciones cuyo nombre ya implica datos regulados / sensibles.
const SENSITIVE_COLLECTIONS: Record<string, PiiCategory> = {
  users: 'identidad',
  usuarios: 'identidad',
  profiles: 'identidad',
  perfiles: 'identidad',
  members: 'identidad',
  miembros: 'identidad',
  socios: 'identidad',
  clientes: 'identidad',
  customers: 'identidad',
  pagos: 'financiero',
  payments: 'financiero',
  invoices: 'financiero',
  facturas: 'financiero',
  transactions: 'financiero',
  transacciones: 'financiero',
  orders: 'financiero',
  pedidos: 'financiero',
  cards: 'financiero',
  tarjetas: 'financiero',
  wallets: 'financiero',
  billing: 'financiero',
  subscriptions: 'financiero',
  suscripciones: 'financiero',
  messages: 'contacto',
  mensajes: 'contacto',
  chats: 'contacto',
  conversations: 'contacto',
  tokens: 'credencial',
  secrets: 'credencial',
  apikeys: 'credencial',
  credentials: 'credencial',
  credenciales: 'credencial',
  sessions: 'credencial',
  sesiones: 'credencial',
  medical: 'salud',
  medico: 'salud',
  health: 'salud',
  salud: 'salud',
  historias: 'salud',
  minors: 'menor',
  menores: 'menor',
  estudiantes: 'menor',
  students: 'menor',
  ninos: 'menor',
};

// Nombres de campo que casi siempre son PII. Claves normalizadas (sin _, minúsculas).
const PII_FIELDS: Record<string, PiiCategory> = {
  email: 'contacto',
  correo: 'contacto',
  mail: 'contacto',
  phone: 'contacto',
  telefono: 'contacto',
  celular: 'contacto',
  movil: 'contacto',
  whatsapp: 'contacto',
  address: 'contacto',
  direccion: 'contacto',
  name: 'identidad',
  nombre: 'identidad',
  apellido: 'identidad',
  fullname: 'identidad',
  firstname: 'identidad',
  lastname: 'identidad',
  dni: 'identidad',
  cedula: 'identidad',
  documento: 'identidad',
  passport: 'identidad',
  pasaporte: 'identidad',
  ssn: 'identidad',
  rut: 'identidad',
  curp: 'identidad',
  birthdate: 'identidad',
  fechanacimiento: 'identidad',
  nacimiento: 'identidad',
  cardnumber: 'financiero',
  numerotarjeta: 'financiero',
  cvv: 'financiero',
  iban: 'financiero',
  cuenta: 'financiero',
  account: 'financiero',
  clabe: 'financiero',
  balance: 'financiero',
  saldo: 'financiero',
  salary: 'financiero',
  salario: 'financiero',
  sueldo: 'financiero',
  income: 'financiero',
  password: 'credencial',
  passwd: 'credencial',
  contrasena: 'credencial',
  clave: 'credencial',
  token: 'credencial',
  apikey: 'credencial',
  secret: 'credencial',
  pin: 'credencial',
  otp: 'credencial',
  location: 'ubicacion',
  ubicacion: 'ubicacion',
  latitude: 'ubicacion',
  latitud: 'ubicacion',
  longitude: 'ubicacion',
  longitud: 'ubicacion',
  geo: 'ubicacion',
  gps: 'ubicacion',
  diagnosis: 'salud',
  diagnostico: 'salud',
  bloodtype: 'salud',
  medication: 'salud',
  medicamento: 'salud',
};

function normalize(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '') // quita tildes
    .replace(/[_\-\s]/g, '');
}

/** Clasifica un nombre de campo por léxico. Devuelve 'ninguno' si no es PII. */
export function classifyFieldByLexicon(field: string): PiiCategory {
  const n = normalize(field);
  if (PII_FIELDS[n]) return PII_FIELDS[n];
  // Coincidencia por subcadena para variantes (userEmail, phoneNumber...).
  for (const key of Object.keys(PII_FIELDS)) {
    if (n.includes(key)) return PII_FIELDS[key];
  }
  return 'ninguno';
}

/** ¿El nombre de una colección implica datos sensibles por sí mismo? */
export function collectionSensitivity(name: string): PiiCategory {
  const n = normalize(name);
  if (SENSITIVE_COLLECTIONS[n]) return SENSITIVE_COLLECTIONS[n];
  // Plural/singular tolerante: quita 's' final.
  const singular = n.replace(/s$/, '');
  for (const key of Object.keys(SENSITIVE_COLLECTIONS)) {
    if (key === singular || key.replace(/s$/, '') === singular) {
      return SENSITIVE_COLLECTIONS[key];
    }
  }
  return 'ninguno';
}

/**
 * Juicio de sensibilidad para una colección, combinando el esquema inferido (si
 * lo hay) con el léxico de dominio. Nunca falla: si no hay esquema, decide por
 * el nombre de la colección.
 */
export function sensitivityOf(collection: string, schema?: SchemaModel): Sensitivity {
  const categories = new Set<PiiCategory>();
  const piiFields: string[] = [];

  const byName = collectionSensitivity(collection);
  if (byName !== 'ninguno') categories.add(byName);

  const info = schema?.collections[collection] ?? schema?.collections[normalize(collection)];
  if (info) {
    for (const f of info.fields) {
      if (f.pii) {
        piiFields.push(f.name);
        categories.add(f.category);
      }
    }
  }

  const sensitive = categories.size > 0 || piiFields.length > 0;
  return { sensitive, piiFields, categories: [...categories] };
}
