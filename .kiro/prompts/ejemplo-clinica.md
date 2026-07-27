# Orquestación: ejemplo "Clínica vulnerable" para el video (ejecutado por Kiro)

Construye un caso de uso realista para demostrar FUGA: una mini-app de
telemedicina ("MediCloud") con reglas de Firestore vulnerables. Crea la carpeta
`examples/clinica-vulnerable/` con estos archivos:

## 1. `firestore.rules` — usa EXACTAMENTE estas reglas (son el corazón del demo)

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Historias clínicas: LECTURA PÚBLICA (fuga de datos de salud). Catastrófico.
    match /pacientes/{pacienteId} {
      allow read: if true;
      allow write: if request.auth != null;
    }

    // Pagos: ACCESO PÚBLICO TOTAL (tarjetas expuestas).
    match /pagos/{pagoId} {
      allow read, write: if true;
    }

    // Citas: LIST público permite enumerar toda la agenda; get requiere auth.
    match /citas/{citaId} {
      allow get: if request.auth != null;
      allow list: if true;
    }

    // Reseñas: CREATE anónimo con solo validación de tipo (spam/inyección).
    match /resenas/{resenaId} {
      allow read: if true;
      allow create: if request.resource.data.texto is string;
    }

    // Perfil de usuario: SEGURO por dueño (FUGA NO debe reportar fuga aquí).
    match /usuarios/{userId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

## 2. `client.js` — código cliente React realista que consulta esas colecciones
Debe usar `collection(db, '...')`, `addDoc`/`setDoc` con objetos que incluyan los
campos de PII para que el RAG de FUGA infiera el esquema y la sensibilidad. Cubre:
- `pacientes`: { nombre, cedula, email, telefono, diagnostico, tipoSangre, ownerId }
- `pagos`: { ownerId, monto, numeroTarjeta, cvv }
- `citas`: { pacienteId, fecha, motivo }
- `resenas`: { texto, autor }
- `usuarios`: { nombre, email }
Incluye funciones verosímiles (registrarPaciente, cobrarConsulta, agendarCita,
dejarResena) y algún `where('ownerId','==',uid)`.

## 3. `fuga.seed.json` — datos sembrados realistas (ficticios) para el ataque
Un documento por colección con datos que se vean reales:
- `/pacientes/p_ana`: nombre "Ana Ríos", cedula, email, telefono, diagnostico
  "Diabetes tipo 2", tipoSangre "O+", ownerId "ana".
- `/pagos/pg_1`: ownerId "ana", monto 480000, numeroTarjeta "4111 1111 1111 1111", cvv "321".
- `/citas/c_1`: pacienteId "p_ana", fecha, motivo "Control".
- `/resenas/r_1`: texto, autor.
- `/usuarios/ana`: nombre, email.

## 4. `README.md` — describe el escenario "MediCloud" y los comandos para probarlo
Explica cada vulnerabilidad en una tabla (colección → problema → impacto) y muestra:
```
fuga scan   --code .
fuga prove  --seed fuga.seed.json
fuga fix
fuga verify --rules firestore.rules.fuga --seed fuga.seed.json
```

No modifiques nada fuera de `examples/clinica-vulnerable/`.
