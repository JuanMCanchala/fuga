// Código cliente de ejemplo. FUGA lo lee (RAG) para inferir qué colecciones
// existen y qué campos son sensibles, y así ponderar la severidad de la fuga.
import { collection, addDoc, doc, setDoc, query, where } from 'firebase/firestore';

const pagos = collection(db, 'pagos');
const usuarios = collection(db, 'usuarios');
const mensajes = collection(db, 'mensajes');

export async function registrarUsuario(uid, datos) {
  await setDoc(doc(db, 'usuarios', uid), {
    nombre: datos.nombre,
    email: datos.email,
    telefono: datos.telefono,
    cedula: datos.cedula,
  });
}

export async function cobrar(uid, datos) {
  await addDoc(pagos, {
    ownerId: uid,
    monto: datos.monto,
    numeroTarjeta: datos.numeroTarjeta,
    cvv: datos.cvv,
  });
}

export function misPagos(uid) {
  return query(pagos, where('ownerId', '==', uid));
}
