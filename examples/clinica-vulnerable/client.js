// client.js — MediCloud: app de telemedicina (React + Firebase)
// Este archivo simula el código cliente real que usa las colecciones de Firestore.

import { initializeApp } from "firebase/app";
import {
  getFirestore,
  collection,
  doc,
  addDoc,
  setDoc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  limit,
} from "firebase/firestore";
import { getAuth } from "firebase/auth";

const app = initializeApp({
  apiKey: "AIza...",
  projectId: "medicloud-demo",
});

const db = getFirestore(app);
const auth = getAuth(app);

// ─── Pacientes (historias clínicas) ─────────────────────────────────────────

/**
 * Registra un paciente con su historia clínica completa.
 * Campos sensibles: cédula, diagnóstico, tipo de sangre, teléfono.
 */
export async function registrarPaciente(uid, datos) {
  const ref = doc(collection(db, "pacientes"));
  await setDoc(ref, {
    nombre: datos.nombre,
    cedula: datos.cedula,
    email: datos.email,
    telefono: datos.telefono,
    diagnostico: datos.diagnostico,
    tipoSangre: datos.tipoSangre,
    ownerId: uid,
    creadoEn: new Date().toISOString(),
  });
  return ref.id;
}

/** Obtiene los pacientes del médico autenticado. */
export async function obtenerMisPacientes(uid) {
  const q = query(
    collection(db, "pacientes"),
    where("ownerId", "==", uid),
    orderBy("creadoEn", "desc"),
    limit(50)
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

// ─── Pagos ──────────────────────────────────────────────────────────────────

/**
 * Cobra una consulta médica almacenando datos de tarjeta.
 * Anti-patrón real: guardar PAN y CVV en Firestore.
 */
export async function cobrarConsulta(uid, datosPago) {
  await addDoc(collection(db, "pagos"), {
    ownerId: uid,
    monto: datosPago.monto,
    numeroTarjeta: datosPago.numeroTarjeta,
    cvv: datosPago.cvv,
    fecha: new Date().toISOString(),
  });
}

/** Historial de pagos del usuario. */
export async function obtenerMisPagos(uid) {
  const q = query(
    collection(db, "pagos"),
    where("ownerId", "==", uid),
    orderBy("fecha", "desc")
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

// ─── Citas ──────────────────────────────────────────────────────────────────

/** Agenda una cita médica. */
export async function agendarCita(uid, datosCita) {
  await addDoc(collection(db, "citas"), {
    pacienteId: datosCita.pacienteId,
    fecha: datosCita.fecha,
    motivo: datosCita.motivo,
    creadoPor: uid,
    estado: "pendiente",
  });
}

/** Lista las citas futuras (usa list → público por las reglas vulnerables). */
export async function listarCitasDelDia(fecha) {
  const q = query(
    collection(db, "citas"),
    where("fecha", ">=", fecha),
    orderBy("fecha"),
    limit(20)
  );
  const snap = await getDocs(q);
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

// ─── Reseñas ────────────────────────────────────────────────────────────────

/** Deja una reseña pública (anónima permitida por las reglas). */
export async function dejarResena(texto, autor) {
  await addDoc(collection(db, "resenas"), {
    texto,
    autor: autor || "Anónimo",
    fecha: new Date().toISOString(),
  });
}

/** Lee todas las reseñas. */
export async function obtenerResenas() {
  const snap = await getDocs(collection(db, "resenas"));
  return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
}

// ─── Usuarios (perfil) ─────────────────────────────────────────────────────

/** Crea o actualiza el perfil del usuario autenticado. */
export async function guardarPerfil(uid, datos) {
  await setDoc(doc(db, "usuarios", uid), {
    nombre: datos.nombre,
    email: datos.email,
    actualizadoEn: new Date().toISOString(),
  });
}

/** Lee el perfil del usuario autenticado. */
export async function obtenerPerfil(uid) {
  const snap = await getDoc(doc(db, "usuarios", uid));
  return snap.exists() ? snap.data() : null;
}
