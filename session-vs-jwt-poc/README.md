# Session-Based vs JWT Authentication POC

POC académico desarrollado en Go para comparar autenticación y autorización mediante sesiones stateful y JSON Web Tokens stateless

El proyecto busca demostrar mediante código y escenarios reproducibles las ventajas, limitaciones y compromisos de cada método, sin convertir el ejercicio en una plataforma de autenticación de producción

## Objetivos

El POC aborda:

- Stateful frente a stateless
- HTTP y el problema de conservar estado
- Seguridad, experiencia de usuario y rendimiento
- Riesgos específicos de sesiones
- Riesgos específicos de JWT
- Escalabilidad horizontal
- Revocación después de cambio de contraseña
- Bloqueo administrativo
- Logout manual
- Logout o rechazo por timeout
- Páginas públicas y protegidas
- Autenticación y autorización
- Experiencia de usuario en ambos métodos

## Estrategia de comparación

Las variantes comparten:

- usuarios
- reglas de autorización
- páginas
- handlers funcionales
- persistencia de usuarios
- interfaz visual
- mensajes
- escenarios de demostración

Solo cambia el mecanismo utilizado para emitir, transportar, validar y revocar la credencial de autenticación

HTTP procesa solicitudes independientes y no conserva por sí solo la identidad entre una y otra. Session resuelve ese problema mediante una referencia a estado server-side; JWT puro transporta identidad autocontenida y firmada; JWT controlado agrega comprobaciones stateful al token

```text
Sesiones
Cookie con ID opaco
→ consulta del estado en el servidor
→ recuperación de identidad

JWT
Cookie con token firmado
→ validación de firma y claims
→ recuperación de identidad
```

Session es stateful: la cookie transporta un ID opaco y el servidor recupera el estado autenticado. JWT puro es stateless durante la validación: la cookie transporta identidad firmada y cada instancia comprueba firma y claims. JWT controlado conserva el token, pero agrega estado para revocación y para comprobar al usuario actual

## Comparación implementada

| Aspecto | Session | JWT Pure | JWT Controlled |
|---|---|---|---|
| Estado de autenticación | servidor | token | token + estado adicional |
| Store requerido para validar | sí | no | según el control configurado |
| Logout / credencial actual | mediante el store | sin revocación server-side | mediante denylist |
| Expiración | idle + absoluta | fija | fija |
| Horizontal scaling | requiere store compartido | validación local | revocación compartida si se requiere |
| Claims desactualizados | menor problema: consulta usuario | posible hasta `exp` | comprobados contra estado actual |
| Dependencia Redis | opcional | no | opcional |
| Costo por request | lookup de sesión + usuario | criptografía | criptografía + lookups |

La tabla no declara un ganador. Session y JWT desplazan dónde vive el estado, qué se consulta en cada request y qué complejidad aparece cuando se exige revocación, seguridad o escalabilidad

### Seguridad y revocación

| Modo | Qué valida por request | Logout / credencial actual | Cambio de contraseña, bloqueo o desbloqueo |
|---|---|---|---|
| Session memory | sesión local, expiraciones, usuario, `Active`, `AuthVersion` y actividad | sesión local al proceso | `Active` y `AuthVersion` en SQLite invalidan entre instancias; la limpieza directa alcanza el store local |
| Session Redis | sesión compartida, expiraciones, usuario, `Active`, `AuthVersion` y actividad | sesión compartida mediante Redis | `Active` y `AuthVersion` invalidan entre instancias y la limpieza usa el store compartido |
| JWT pure | firma HS256 y claims | no existe revocación server-side; una copia vive hasta `exp` | no consulta los cambios; el JWT previo vive hasta `exp` |
| JWT controlled memory | firma, claims, denylist local, `Active` y `AuthVersion` | `jti` local al proceso | `Active` y `AuthVersion` se consultan en SQLite e invalidan entre instancias |
| JWT controlled Redis | firma, claims, denylist Redis, `Active` y `AuthVersion` | `jti` compartido mediante Redis | `Active` y `AuthVersion` se consultan en SQLite e invalidan entre instancias |

Los TTL cortos reducen la ventana de abuso, mientras que `Active`, `AuthVersion` y la denylist permiten controles inmediatos a costa de nuevas consultas. La metadata de observabilidad no incorpora cookies, tokens, `jti` completos, IDs de sesión completos, hashes, secretos ni CSRF

### Escalabilidad horizontal

| Demostración | Resultado esperado |
|---|---|
| Session memory: A hace login, B recibe la cookie | B no conoce la sesión |
| Session Redis: A hace login, B recibe la cookie | B conoce la sesión compartida |
| JWT pure: A emite, B valida con el mismo secreto, issuer y audience | B valida localmente |
| JWT controlled memory: A revoca, B recibe una copia | B no conoce la denylist de A |
| JWT controlled Redis: A revoca, B recibe una copia | B conoce la revocación compartida |

### Disponibilidad

| Modo | Dependencias de una validación autenticada |
|---|---|
| Session memory | proceso local y SQLite; reiniciar pierde las sesiones |
| Session Redis | Redis y SQLite; Redis es requerido |
| JWT pure | claves y parámetros compatibles; no Redis ni consulta de usuario |
| JWT controlled memory | SQLite para estado actual y denylist del proceso |
| JWT controlled Redis | SQLite + Redis |

La afirmación de independencia de JWT puro aplica a la validación del access token. Login y mutaciones de usuarios continúan dependiendo de SQLite

## Compromisos entre seguridad, experiencia y performance

Este trilema no es una ley matemática, sino una forma práctica de razonar sobre compromisos del diseño:

### Seguridad

TTL corto, revocación, `Active` y `AuthVersion` reducen ventanas de abuso, pero pueden agregar estado y dependencias

### Experiencia

Un JWT expirado requiere otro login; una Session extiende el timeout idle con actividad; cambiar la contraseña fuerza reautenticación

### Performance

Session consulta su store y SQLite; JWT realiza trabajo criptográfico; Redis agrega I/O de red; JWT controlado vuelve a introducir Redis o memoria y SQLite

La interfaz diferencia los mensajes de sesión inactiva, expiración absoluta, JWT expirado, cuenta bloqueada, credencial revocada y reautenticación después de cambiar contraseña. No agrega refresh tokens ni flujos nuevos

## Interpretación de las mediciones

El dashboard mide únicamente el tiempo empleado por la validación de autenticación de la solicitud actual. No incluye transporte de la cookie, CSRF, handler, renderizado HTML, CPU total, memoria, red completa ni throughput. `/api/me` presenta el mismo dato como `validation_duration_us`, junto con modo, store y consultas de estado

Una medición individual tiene ruido. Memory suele evitar una llamada de red; Redis agrega I/O; JWT puro evita el lookup de sesión y realiza validación criptográfica; JWT controlado suma consultas de denylist y usuario. Los resultados locales no prueban que una estrategia sea universalmente más rápida

Con una cookie válida, estas solicitudes permiten observar la variación sin instalar una herramienta de carga:

```bash
for i in {1..10}; do
  curl -s -b /tmp/session-cookie.txt http://localhost:8081/api/me
done

for i in {1..10}; do
  curl -s -b /tmp/jwt-cookie.txt http://localhost:8082/api/me
done
```

Los comandos usan los archivos de cookies creados en los escenarios Session y JWT descritos más adelante

## Stack

- Go
- `net/http`
- `html/template`
- HTML semántico
- CSS local
- SQLite
- bcrypt
- JWT
- Redis en las fases distribuidas
- Docker Compose opcional para iniciar Redis

No se utilizará un framework frontend ni un framework HTTP

## Aplicaciones

```text
Session application
http://localhost:8081

JWT application
http://localhost:8082
```

Los puertos podrán cambiarse mediante variables de entorno para ejecutar varias instancias al mismo tiempo

## Rutas principales

| Ruta | Acceso | Propósito |
|---|---|---|
| `/` | Público | Presentación del método y navegación |
| `/login` | Público | Inicio de sesión |
| `/dashboard` | Autenticado | Información del usuario y de la credencial |
| `/account/password` | Autenticado | Cambio de contraseña |
| `/admin/users` | Administrador | Listado y bloqueo de usuarios |
| `/logout` | Autenticado | Cierre manual de sesión |
| `/api/me` | Autenticado | Recurso JSON para pruebas con curl |
| `/health` | Público | Estado básico de la instancia |

## Estructura

La estructura principal es:

```text
.
├── AGENTS.md
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
├── go.mod
├── go.sum
├── cmd/
│   ├── sessionapp/
│   └── jwtapp/
├── data/
├── docs/
│   └── PROJECT_CONTEXT.md
├── internal/
│   ├── auth/
│   │   ├── session/
│   │   └── jwt/
│   ├── config/
│   ├── security/
│   ├── storage/
│   │   ├── memory/
│   │   ├── redis/
│   │   └── sqlite/
│   ├── user/
│   └── web/
└── web/
    ├── static/
    └── templates/
```

La estructura puede ajustarse cuando exista una razón concreta, pero no debe crecer por anticipación

## Persistencia

### SQLite

SQLite conservará:

- usuarios
- hash de contraseña
- rol
- estado activo o bloqueado
- versión de autenticación
- fechas relevantes

SQLite permite que varias instancias locales observen el mismo estado de usuario sin introducir un servidor de base de datos adicional

### Memoria

La memoria se utilizará para demostrar:

- sesiones locales
- revocaciones locales
- pérdida de estado al reiniciar
- inconsistencias entre instancias

### Redis

Redis se utiliza para demostrar:

- sesiones compartidas entre instancias
- revocaciones de sesión compartidas
- expiración mediante TTL
- dependencia de disponibilidad del store

## Variables de entorno

La lista definitiva se mantendrá en `.env.example`

Las aplicaciones utilizan, según el modo configurado:

```text
APP_PORT
APP_INSTANCE
DATABASE_PATH
COOKIE_SECURE
SESSION_IDLE_TIMEOUT
SESSION_ABSOLUTE_TIMEOUT
SESSION_STORE
REDIS_ADDR
REDIS_PASSWORD
REDIS_DB
JWT_SECRET
JWT_ISSUER
JWT_AUDIENCE
JWT_TTL
JWT_SECURITY_MODE
JWT_REVOCATION_STORE
```

`DATABASE_PATH` usa `data/poc.db` de forma predeterminada. El directorio y la base se crean automáticamente al iniciar cualquiera de las aplicaciones

`sessionapp` utiliza estos valores predeterminados:

```text
COOKIE_SECURE=false
SESSION_IDLE_TIMEOUT=2m
SESSION_ABSOLUTE_TIMEOUT=10m
```

`COOKIE_SECURE=false` permite la demostración mediante HTTP local. En HTTPS debe configurarse como `true`

`jwtapp` requiere `JWT_SECRET` con al menos 32 caracteres. Los demás valores JWT usan estos predeterminados:

```text
JWT_ISSUER=session-vs-jwt-poc
JWT_AUDIENCE=session-vs-jwt-web
JWT_TTL=2m
JWT_SECURITY_MODE=pure
JWT_REVOCATION_STORE=memory
```

`JWT_SECURITY_MODE` acepta `pure` o `controlled`. El modo puro ignora `JWT_REVOCATION_STORE` y no conecta Redis. El modo controlado acepta `memory` o `redis`; Redis reutiliza `REDIS_ADDR`, `REDIS_PASSWORD` y `REDIS_DB`

Los secretos reales deben permanecer en `.env`, que no se versiona

## Instalación de Codex CLI en macOS

La instalación actual puede realizarse con:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

Después:

```bash
codex
```

Codex debe ejecutarse desde la raíz del repositorio para que cargue `AGENTS.md`

## Estado de desarrollo

El proyecto se implementó por fases

| Fase | Descripción | Estado |
|---:|---|---|
| 0 | Bootstrap del repositorio | Completada |
| 1 | Aplicación común y usuarios | Completada |
| 2 | Sesiones locales | Completada |
| 3 | Sesiones distribuidas con Redis | Completada |
| 4 | JWT puro | Completada |
| 5 | JWT con revocación | Completada |
| 6 | Comparación y observabilidad | Completada |
| 7 | Revisión y preparación de demostración | Completada |

Cada fase mantuvo estos criterios:

1. mantener el repositorio compilable
2. implementar únicamente su alcance
3. finalizar con una prueba manual
4. actualizar este estado cuando corresponda
5. conservar los escenarios construidos anteriormente

## Comandos generales

Desde la raíz del módulo Go:

```bash
gofmt -w .
go mod tidy
go vet ./...
go test ./...
go build ./...
go test -race ./...
```

Los ejecutables se inician desde la raíz del proyecto:

```bash
go run ./cmd/sessionapp
go run ./cmd/jwtapp
```

La aplicación de sesiones usa el puerto `8081` y la aplicación JWT el puerto `8082` de forma predeterminada. Ambas comparten `data/poc.db`. Cada proceso permite sobrescribir su puerto, identificador y base de datos:

```bash
APP_PORT=8091 APP_INSTANCE=session-demo DATABASE_PATH=data/poc.db go run ./cmd/sessionapp
APP_PORT=8092 APP_INSTANCE=jwt-demo DATABASE_PATH=data/poc.db \
JWT_SECRET='local-poc-secret-change-me-32-bytes' go run ./cmd/jwtapp
```

### Credenciales de demostración

```text
Administrador
Correo: admin@poc.local
Contraseña: Admin123!

Usuario
Correo: user@poc.local
Contraseña: User123!
```

Estas credenciales se usan únicamente para el POC local. SQLite almacena hashes bcrypt, no las contraseñas

En `sessionapp`, `POST /login` crea una sesión stateful en el store configurado y emite una cookie `session_id` opaca. En `jwtapp`, emite un JWT HS256 autocontenido en la cookie `access_token`

### Flujo de sesiones stateful

```text
Login válido
→ ID impredecible creado con crypto/rand
→ sesión guardada en MemorySessionStore o RedisSessionStore
→ cookie HttpOnly y SameSite=Lax
→ middleware consulta el store y SQLite
→ identidad común disponible en context.Context
```

La sesión aplica un timeout deslizante por inactividad y una expiración absoluta que nunca se extiende. El logout, cambio de contraseña y bloqueo eliminan las sesiones correspondientes

### Prueba con curl

Iniciar `sessionapp`:

```bash
APP_PORT=8081 APP_INSTANCE=session-a DATABASE_PATH=data/poc.db \
SESSION_STORE=memory \
COOKIE_SECURE=false SESSION_IDLE_TIMEOUT=2m SESSION_ABSOLUTE_TIMEOUT=10m \
go run ./cmd/sessionapp
```

Iniciar sesión y conservar la cookie:

```bash
curl -i -c /tmp/session-cookie.txt \
  -d "email=user@poc.local&password=User123!" \
  http://localhost:8081/login
```

Consultar la identidad segura:

```bash
curl -i -b /tmp/session-cookie.txt http://localhost:8081/api/me
```

Para cerrar sesión mediante curl, obtener el token CSRF del formulario renderizado y enviarlo junto con la cookie:

```bash
curl -s -b /tmp/session-cookie.txt \
  http://localhost:8081/account/password > /tmp/session-page.html

CSRF_TOKEN=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' \
  /tmp/session-page.html | head -n 1)

curl -i -b /tmp/session-cookie.txt \
  -d "csrf_token=${CSRF_TOKEN}" \
  http://localhost:8081/logout
```

Reutilizar una copia anterior de `session_id` después del logout debe producir `401` en `/api/me`

### Dos instancias con memoria local

Ejecutar una segunda instancia contra la misma base:

```bash
APP_PORT=8083 APP_INSTANCE=session-b DATABASE_PATH=data/poc.db \
SESSION_STORE=memory \
COOKIE_SECURE=false SESSION_IDLE_TIMEOUT=2m SESSION_ABSOLUTE_TIMEOUT=10m \
go run ./cmd/sessionapp
```

La cookie obtenida en `session-a` funciona en el puerto `8081`, pero produce `401` al enviarse a `session-b`:

```bash
curl -i -b /tmp/session-cookie.txt http://localhost:8081/api/me
curl -i -b /tmp/session-cookie.txt http://localhost:8083/api/me
```

Ambos procesos comparten usuarios en SQLite, pero cada uno tiene un `MemorySessionStore` independiente. Este aislamiento es deliberado

### Sesiones distribuidas con Redis

`SESSION_STORE` acepta `memory` (valor predeterminado) o `redis`. El segundo modo usa estas variables:

| Variable | Predeterminado | Propósito |
|---|---|---|
| `REDIS_ADDR` | `localhost:6379` | Dirección del servidor Redis |
| `REDIS_PASSWORD` | vacío | Contraseña opcional |
| `REDIS_DB` | `0` | Base lógica Redis |

`sessionapp` carga estas variables cuando `SESSION_STORE=redis`. `jwtapp` solo conecta a Redis cuando usa `JWT_SECURITY_MODE=controlled` y `JWT_REVOCATION_STORE=redis`

Iniciar únicamente Redis con Docker Compose:

```bash
docker compose up -d redis
```

Ejecutar dos instancias que comparten Redis y SQLite:

```bash
APP_PORT=8081 APP_INSTANCE=session-redis-a DATABASE_PATH=data/poc.db \
SESSION_STORE=redis REDIS_ADDR=localhost:6379 \
COOKIE_SECURE=false SESSION_IDLE_TIMEOUT=2m SESSION_ABSOLUTE_TIMEOUT=10m \
go run ./cmd/sessionapp
```

```bash
APP_PORT=8083 APP_INSTANCE=session-redis-b DATABASE_PATH=data/poc.db \
SESSION_STORE=redis REDIS_ADDR=localhost:6379 \
COOKIE_SECURE=false SESSION_IDLE_TIMEOUT=2m SESSION_ABSOLUTE_TIMEOUT=10m \
go run ./cmd/sessionapp
```

Realizar el login en `8081` con el comando de curl anterior. La misma cookie debe devolver `200` tanto en `8081` como en `8083`:

```bash
curl -i -b /tmp/session-cookie.txt http://localhost:8081/api/me
curl -i -b /tmp/session-cookie.txt http://localhost:8083/api/me
```

Para demostrar revocación cruzada, obtener el CSRF desde cualquiera de las instancias, hacer `POST /logout` en `8083` y volver a consultar `8081`:

```bash
curl -s -b /tmp/session-cookie.txt \
  http://localhost:8083/account/password > /tmp/session-page.html

CSRF_TOKEN=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' \
  /tmp/session-page.html | head -n 1)

curl -i -b /tmp/session-cookie.txt \
  -d "csrf_token=${CSRF_TOKEN}" \
  http://localhost:8083/logout

curl -i -b /tmp/session-cookie.txt http://localhost:8081/api/me
```

La última solicitud debe producir `401`, porque ambas instancias consultan la misma revocación en Redis

Para demostrar la dependencia de disponibilidad, crear otra sesión válida, detener Redis y consultar una ruta protegida:

```bash
docker compose stop redis
curl -i -b /tmp/session-cookie.txt http://localhost:8081/api/me
```

La aplicación falla de forma cerrada: devuelve un error controlado y no concede acceso ni cambia automáticamente a memoria. Al arrancar con `SESSION_STORE=redis`, también termina con un error claro si Redis no está disponible. Reiniciar o retirar el servicio con:

```bash
docker compose start redis
docker compose down
```

Redis permite compartir el estado de autenticación de Session entre instancias; no vuelve escalable por sí solo a toda la aplicación. A cambio, Redis se convierte en una dependencia de disponibilidad para autenticar solicitudes. El POC demuestra este compromiso sin agregar alta disponibilidad, reintentos ni componentes de infraestructura adicionales

### JWT puro stateless

`jwtapp` valida localmente la firma HS256 y los claims `sub`, `jti`, `iat`, `exp`, `iss`, `aud`, `role` y `auth_version`. Nombre y correo también viajan firmados para construir la identidad común sin consultar SQLite durante una solicitud autenticada. No existe SessionStore, denylist ni registro server-side del token

```text
Login válido
→ UserService consulta SQLite y verifica bcrypt
→ JWT firmado con expiración fija
→ cookie access_token HttpOnly y SameSite=Lax
→ middleware valida firma y claims localmente
→ auth.Identity disponible en context.Context
```

Las operaciones POST usan una cookie `jwt_csrf` separada y firmada. El formulario recibe el mismo valor desde el servidor y se compara de forma segura; no se guarda estado CSRF en memoria, Redis o SQLite. En sesiones, en cambio, el CSRF continúa asociado al estado server-side de cada sesión

Iniciar dos instancias con el mismo material criptográfico:

```bash
APP_PORT=8082 APP_INSTANCE=jwt-a DATABASE_PATH=data/poc.db \
COOKIE_SECURE=false JWT_SECRET='local-poc-secret-change-me-32-bytes' \
JWT_ISSUER=session-vs-jwt-poc JWT_AUDIENCE=session-vs-jwt-web JWT_TTL=2m \
JWT_SECURITY_MODE=pure \
go run ./cmd/jwtapp
```

```bash
APP_PORT=8084 APP_INSTANCE=jwt-b DATABASE_PATH=data/poc.db \
COOKIE_SECURE=false JWT_SECRET='local-poc-secret-change-me-32-bytes' \
JWT_ISSUER=session-vs-jwt-poc JWT_AUDIENCE=session-vs-jwt-web JWT_TTL=2m \
JWT_SECURITY_MODE=pure \
go run ./cmd/jwtapp
```

Hacer login en A y reutilizar la misma cookie en ambas instancias:

```bash
curl -i -c /tmp/jwt-cookie.txt \
  -d "email=user@poc.local&password=User123!" \
  http://localhost:8082/login

curl -i -b /tmp/jwt-cookie.txt http://localhost:8082/api/me
curl -i -b /tmp/jwt-cookie.txt http://localhost:8084/api/me
```

La segunda respuesta identifica `jwt-b`, `authentication_method: jwt`, `store: none` y ausencia de consultas de estado. Las instancias no comparten sesiones: comparten el secreto, issuer y audience necesarios para verificar el token. Con un secreto, issuer o audience diferente, la validación falla

JWT usa `exp` fijo y no tiene timeout por inactividad. La actividad no renueva el token; después de `JWT_TTL`, las rutas HTML vuelven al login y `/api/me` responde `401`

El logout borra `access_token` y `jwt_csrf` únicamente del navegador. Si se conserva una copia anterior de `access_token`, esa copia continúa siendo válida hasta `exp`; no se crea una denylist. De igual forma, cambiar la contraseña cierra el navegador actual e incrementa `AuthVersion`, pero un JWT copiado antes sigue siendo criptográficamente válido. Bloquear un usuario impide nuevos logins, aunque un JWT emitido antes del bloqueo continúa funcionando hasta expirar. Estas limitaciones son deliberadas en JWT puro

Redis puede permanecer detenido: `jwtapp` no carga su cliente ni lo consulta para login o validación. SQLite sigue siendo necesaria para login y para operaciones que modifican usuarios; la propiedad stateless se refiere específicamente a la validación del access token

### JWT controlado y revocación

El modo controlado conserva primero toda la validación criptográfica del modo puro y después agrega dos consultas stateful:

```text
firma y claims
→ denylist por jti
→ usuario actual en SQLite
→ Active y AuthVersion
→ identidad autorizada
```

La denylist guarda únicamente `jti → exp`. En memoria usa un mapa concurrente con limpieza lazy; en Redis usa claves `poc:jwt-revoked:<jti>` cuyo TTL termina con el `exp` original. No existe índice por usuario: cambiar contraseña, bloquear y desbloquear incrementan `AuthVersion`, que invalida globalmente los JWT anteriores

Para revocación local, iniciar dos instancias con el mismo secreto y `JWT_REVOCATION_STORE=memory`:

```bash
APP_PORT=8082 APP_INSTANCE=jwt-memory-a DATABASE_PATH=data/poc.db \
COOKIE_SECURE=false JWT_SECRET='local-poc-secret-change-me-32-bytes' \
JWT_ISSUER=session-vs-jwt-poc JWT_AUDIENCE=session-vs-jwt-web JWT_TTL=2m \
JWT_SECURITY_MODE=controlled JWT_REVOCATION_STORE=memory \
go run ./cmd/jwtapp
```

```bash
APP_PORT=8084 APP_INSTANCE=jwt-memory-b DATABASE_PATH=data/poc.db \
COOKIE_SECURE=false JWT_SECRET='local-poc-secret-change-me-32-bytes' \
JWT_ISSUER=session-vs-jwt-poc JWT_AUDIENCE=session-vs-jwt-web JWT_TTL=2m \
JWT_SECURITY_MODE=controlled JWT_REVOCATION_STORE=memory \
go run ./cmd/jwtapp
```

Un token emitido en A funciona inicialmente en ambas instancias. Después de logout en A, la copia devuelve `401` en A pero continúa en `200` en B porque cada proceso tiene su propia denylist

Para revocación distribuida, iniciar Redis y sustituir el store en ambas instancias:

```bash
docker compose up -d redis
JWT_SECURITY_MODE=controlled JWT_REVOCATION_STORE=redis REDIS_ADDR=localhost:6379 \
APP_PORT=8082 APP_INSTANCE=jwt-redis-a \
DATABASE_PATH=data/poc.db COOKIE_SECURE=false \
JWT_SECRET='local-poc-secret-change-me-32-bytes' \
go run ./cmd/jwtapp
```

Ejecutar la segunda instancia en `8084` con otro `APP_INSTANCE` y los mismos valores. Después de logout en A, la copia se rechaza en A y B porque ambos consultan Redis

El estado actual del usuario siempre proviene de SQLite en modo controlado. Un cambio de contraseña invalida JWT anteriores por `AuthVersion`; bloquear invalida por `Active`, y desbloquear vuelve a incrementar la versión para impedir que un token histórico recupere validez. Esto funciona entre instancias incluso con denylist local

Disponibilidad por modo:

- `pure`: firma y claims; no depende de Redis ni consulta usuario durante validación
- `controlled + memory`: firma, denylist local y SQLite; no depende de Redis
- `controlled + redis`: firma, Redis y SQLite; Redis pasa a ser dependencia de validación

Si Redis o SQLite falla en modo controlado, una ruta protegida falla cerrada con respuesta controlada. La cookie no se elimina por un error de infraestructura y puede volver a funcionar cuando la dependencia se recupera. No existe fallback a memoria, reintento ni circuit breaker

### Reiniciar la base local

Detener ambos ejecutables y eliminar únicamente los archivos de la base del POC:

```bash
rm -f data/poc.db data/poc.db-shm data/poc.db-wal
```

El siguiente inicio recreará el esquema y los dos usuarios de demostración. El POC está finalizado y listo para preparar su explicación y demostración

## Principios de desarrollo

- KISS
- DRY
- separación de responsabilidades
- bajo acoplamiento
- nombres claros
- dependencias explícitas
- patrones solamente cuando resuelvan una variación real
- seguridad implementada en backend
- comentarios útiles para comprender decisiones
- código proporcional al objetivo académico

## Fuera de alcance

- OAuth
- OpenID Connect
- SSO
- MFA
- refresh tokens
- login social
- recuperación de contraseña
- microservicios
- Kubernetes
- despliegue cloud
- frontend SPA
- suite extensa de pruebas
- monitoreo de producción

## Documentación

La especificación completa se encuentra en:

```text
docs/PROJECT_CONTEXT.md
```

Las reglas permanentes para Codex se encuentran en:

```text
AGENTS.md
```
