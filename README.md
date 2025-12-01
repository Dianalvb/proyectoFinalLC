# proyectoFinalLC
## Tecnologías utilizadas
- Python 3.10+
- FastAPI
- Cryptography
- Uvicorn

## Estructura del proyrcto
<img width="363" height="452" alt="Captura de pantalla 2025-12-01 112943" src="https://github.com/user-attachments/assets/26c42766-b3a2-45b2-b5e7-97efabef6c9e" />


## como ejecutar el proyecto:
1. Crea un entorno virtual:
   ```bash
   python -m venv venv
2. actívalo
   ```bash
   venv\Scripts\activate
3. Instalar dependencias
   ```bash
   pip install -r requirements.txt
4. Ejecutar servidor:
   ```bash
   uvicorn app.main:app --reload
5. Y abre en el navegador lo siguiente:
   http://127.0.0.1:8000/docs


## Pruebas realizadas:

[FastAPI - Swagger UI.pdf](https://github.com/user-attachments/files/23860827/FastAPI.-.Swagger.UI.pdf)

## ¿Porque AES sobre DES?

El Estandar de Cifrado Avanzado (AES) se elige sobre el Estándar de Cifrado de Datos (DES) por su seguridad superior, mayor eficiencia y un diseño mas moderno, robusto y con llaves más grandes. El DES es considerado obsoleto y vulnerable para las aplicaciones actuales.

### Razones clave para la superioridad de aes:
<img width="902" height="579" alt="Captura de pantalla 2025-12-01 114552" src="https://github.com/user-attachments/assets/ae5b7a17-44e5-4d33-bb31-3fe55031f7d2" />

## ¿Porque Argon 2 sobre SHA-256 para contraseñas?
SHA-256 es una función de hash criptográfico rápida. Es ideal para integridad de datos, blockchain, firmas, etc.
No fue diseñada para proteger contraseñas, al ser muy rápida, es vulnerable a ataques de:
- fuerza bruta (probará distintas variaciones hasta encontrarla)
- diccionario (contraseñas comunes)
- GPU/ASIC (el atacante usa hardware especiaalizado)
- rainbow tables (tablas gigantes que ya contienen millones de contraseñas comunes y sus hashes precalculados)

Argon2 (Ganador del Password Hashing Competition 2015) fue diseñado específicamente para proteger contraseñas. Es un hash lento, configurable y resistente.
Utiliza:

- memoria controlada (difícil para GPUs o ASICs)
- parámetros de tiempo
- salts automáticos (valores aleatorios agregado a la contraseña antes de hashearla)
- protección contra ataques paralelos

Argon2 es mucho más seguro para contraseñas porque “castiga” a los atacantes consumiendo memoria y tiempo. SHA-256 es demasiado rápido y permite millones de intentos por segundo.

## ¿Que es CHaCha20 y porque es seguro?
ChaCha20 es un algoritmo de cifrado simétrico moderno creado por Daniel Bernstein.
Es una alternativa más segura y rápida que AES, especialmente en dispositivos móviles.

ChaCha20 pertenece a la familia de cifrados tipo stream cipher:
genera una secuencia de bytes pseudoaleatorios (keystream) que se combina con el mensaje mediante XOR para cifrarlo.
### Ventajas: 
1. Muy rápido incluso en dispositivos sin aceleración de hardware
AES es rápido en CPUs modernas porque tiene instrucciones especiales (AES-NI).
Pero en celulares, routers u otros dispositivos sin ese hardware, AES puede ser lento.
ChaCha20 fue diseñado para ser rápido en cualquier procesador, incluso pequeños.
2. Altamente resistente a ataques side-channel
Muchos ataques utilizan:
tiempo que tarda en ejecutarse, consumo eléctrico, diferencias en caché.
ChaCha20 opera siempre de manera constante, reduciendo ataques de canal lateral.
3. Diseño moderno y más simple
AES usa estructuras complejas (S-boxes).
ChaCha20 usa operaciones básicas:
- sumas
- rotaciones
- XOR
Esto reduce errores de implementación.
4. Usado por Google, IETF, Cloudflare, WireGuard, TLS 1.3
Es uno de los algoritmos favoritos en Internet moderno.

### Desventajas:
1. Necesita un nonce único para cada mensaje (si se repite → inseguro).
2. Es un algoritmo de cifrado, no firma ni verifica.

## ¿Qué es RSA y para qué sirve?
es un algoritmo de criptografía asimétrica, es decir:
- Tiene clave pública para cifrar.
- Tiene clave privada para descifrar.
- Fue inventado en 1977 por Rivest, Shamir y Adleman (RSA).
RSA se basa en la dificultad de factorizar números enormes (multiplicar es fácil, dividir entre factores primos gigantes es muy difícil).
### ¿Para qué se usa?
1. Intercambio seguro de claves
Ejemplo:
Un servidor usa RSA para enviar una clave AES segura al cliente.
Después usan AES para seguir hablando.
2. Firmas digitales

La clave privada firma → la pública verifica.
Se usa en:
- certificados HTTPS
- actualizaciones oficiales
- Git commits firmados
- autenticación de servidores
3. Cifrado de datos pequeños
Aunque no se usa para cifrar archivos grandes, sí cifra:
- contraseñas
- claves
- tokens
### Ventajas:
1. Basado en matemáticas muy estudiadas
Lleva 40+ años siendo analizado.
2. Modelo asimétrico seguro
La clave pública puede compartirse libremente sin comprometer la seguridad.
3. Ampliamente implementado y compatible
Funciona en casi todos los sistemas cryptográficos del mundo.
### Desventajas:
1. Lento comparado con AES o ChaCha20
Por eso nunca se usa para cifrar mucha información, solo llaves.
2. Tamaño grande de claves
- RSA 2048 bits = seguridad media
- RSA 4096 bits = seguridad fuerte pero más lento
Las claves son enormes comparadas con Ed25519 o ECC moderna.
3. Vulnerable si se implementa mal
- relleno incorrecto (PKCS1 v1.5) → ataques padding oracle
- claves pequeñas → rotas fácilmente
- números primos débiles → colapsa la seguridad
