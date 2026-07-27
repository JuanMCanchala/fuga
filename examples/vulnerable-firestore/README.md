# Ejemplo: app Firestore vulnerable

Un proyecto mínimo con el antipatrón más común: `allow read, write: if true`.
Úsalo para probar FUGA en segundos.

```bash
cd examples/vulnerable-firestore

# 1. Ver qué reglas exponen acceso anónimo
fuga scan

# 2. DEMOSTRAR la fuga: lanza un atacante anónimo y captura los datos
fuga prove --seed fuga.seed.json

# 3. Generar reglas endurecidas + tests
fuga fix

# 4. Verificar que la fuga desapareció
fuga verify --rules firestore.rules.fuga --seed fuga.seed.json
```

Con `fuga prove` verás salir por pantalla el número de tarjeta, la cédula y los
mensajes privados — exactamente lo que un atacante extraería de tu base de datos
si publicaras estas reglas.
