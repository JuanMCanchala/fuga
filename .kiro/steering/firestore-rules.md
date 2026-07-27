---
inclusion: fileMatch
fileMatchPattern: "**/*.rules"
---

# Guía para reglas de Firestore/Storage

Este steering se inyecta solo al editar archivos `.rules`. Reglas de oro que FUGA
verifica y que el agente debe respetar al escribir o revisar reglas:

- **Denegar por defecto.** Empezar con `match /{document=**} { allow read, write: if false; }`
  y abrir explícitamente por colección.
- **Nunca** `allow read, write: if true;` (acceso público total: la fuga #1).
- Exigir autenticación: `request.auth != null` en toda regla no pública.
- Autorizar por propiedad: `request.auth.uid == resource.data.ownerId` (o el path
  variable en colecciones tipo `users/{uid}`).
- Distinguir `get` de `list`: una `list` pública permite enumerar toda la colección.
- Validar datos entrantes en `create`/`update` (`request.resource.data`), pero la
  validación de tipo NO sustituye la verificación de auth.
- Los `get()`/`exists()` para roles cuentan como verificación de auth indirecta.

Ante cualquier cambio en reglas, correr `fuga scan` y `fuga prove` antes de commitear.
