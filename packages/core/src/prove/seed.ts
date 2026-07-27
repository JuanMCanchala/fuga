/**
 * Generación de datos sembrados verosímiles para las demostraciones. La parte
 * más contundente de FUGA es mostrar QUÉ datos se filtran; que se vean como
 * datos reales (una tarjeta con formato de tarjeta, un teléfono con formato de
 * teléfono) hace la fuga tangible. Son datos ficticios, nunca reales.
 */

import { PiiCategory, SchemaModel } from '../rag/schema';
import { SeededDb } from './attacker';

function norm(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[_\-\s]/g, '');
}

// Valores por nombre de campo (subcadena). Se evalúan en orden.
const BY_NAME: Array<[string, unknown]> = [
  ['email', 'alice@correo.com'],
  ['correo', 'alice@correo.com'],
  ['mail', 'alice@correo.com'],
  ['telefono', '+57 300 123 4567'],
  ['celular', '+57 300 123 4567'],
  ['movil', '+57 300 123 4567'],
  ['phone', '+57 300 123 4567'],
  ['whatsapp', '+57 300 123 4567'],
  ['apellido', 'Pérez'],
  ['lastname', 'Pérez'],
  ['nombre', 'Alice Pérez'],
  ['name', 'Alice Pérez'],
  ['cedula', '1.032.456.789'],
  ['dni', '1.032.456.789'],
  ['documento', '1.032.456.789'],
  ['curp', 'PERA930721HDF'],
  ['rut', '12.345.678-9'],
  ['passport', 'AB123456'],
  ['pasaporte', 'AB123456'],
  ['ssn', '123-45-6789'],
  ['nacimiento', '1993-07-21'],
  ['birthdate', '1993-07-21'],
  ['numerotarjeta', '4111 1111 1111 1111'],
  ['cardnumber', '4111 1111 1111 1111'],
  ['tarjeta', '4111 1111 1111 1111'],
  ['cvv', '321'],
  ['clabe', '0021 3456 7890 1234 56'],
  ['iban', 'ES91 2100 0418 4502 0005 1332'],
  ['cuenta', '0021-3456-7890'],
  ['account', '0021-3456-7890'],
  ['saldo', 1250000],
  ['balance', 1250000],
  ['salario', 4200000],
  ['sueldo', 4200000],
  ['salary', 4200000],
  ['income', 4200000],
  ['monto', 1250000],
  ['amount', 1250000],
  ['password', 'P@ssw0rd!'],
  ['passwd', 'P@ssw0rd!'],
  ['contrasena', 'P@ssw0rd!'],
  ['clave', 'P@ssw0rd!'],
  ['apikey', 'sk_live_51H8xSECRETabcd'],
  ['token', 'tok_live_51H8xSECRETabcd'],
  ['secret', 'sk_live_51H8xSECRETabcd'],
  ['pin', '4821'],
  ['otp', '820193'],
  ['latitud', 4.6097],
  ['latitude', 4.6097],
  ['longitud', -74.0817],
  ['longitude', -74.0817],
  ['ubicacion', '4.6097,-74.0817'],
  ['location', '4.6097,-74.0817'],
  ['diagnostico', 'Hipertensión arterial'],
  ['diagnosis', 'Hipertensión arterial'],
  ['medicamento', 'Losartán 50mg'],
  ['medication', 'Losartán 50mg'],
  ['bloodtype', 'O+'],
];

const BY_CATEGORY: Record<PiiCategory, unknown> = {
  identidad: 'Alice Pérez',
  contacto: 'alice@correo.com',
  financiero: '4111 1111 1111 1111',
  credencial: 'sk_live_SECRET',
  salud: 'Tipo O+, hipertensión',
  ubicacion: '4.6097,-74.0817',
  menor: '2015-04-12',
  ninguno: 'valor',
};

export function sampleValueFor(field: string, category: PiiCategory): unknown {
  const n = norm(field);
  for (const [key, val] of BY_NAME) {
    if (n.includes(key)) return val;
  }
  return BY_CATEGORY[category] ?? 'valor';
}

/**
 * Sintetiza un almacén sembrado a partir del esquema inferido: un documento por
 * colección, con valores verosímiles en los campos sensibles y un ownerId para
 * que las reglas endurecidas tengan contra qué validar.
 */
export function synthSeed(schema: SchemaModel, fallbackCollections: string[] = ['pagos', 'usuarios']): SeededDb {
  const collections = Object.keys(schema.collections);
  const targets = collections.length ? collections : fallbackCollections;
  const db: SeededDb = {};
  for (const coll of targets) {
    const info = schema.collections[coll];
    const doc: Record<string, unknown> = { ownerId: 'alice' };
    for (const f of info?.fields ?? []) {
      if (f.pii) doc[f.name] = sampleValueFor(f.name, f.category);
    }
    if (Object.keys(doc).length === 1) doc.dato = 'valor de ejemplo';
    db[`/${coll}/ejemplo1`] = doc;
  }
  return db;
}
