# Session-Based vs JWT Authentication POC

POC académico de Software Avanzado desarrollado en Go para comparar autenticación y autorización mediante sesiones stateful y JSON Web Tokens stateless

El proyecto busca demostrar mediante código y escenarios reproducibles las ventajas, limitaciones y compromisos de cada método, sin convertir el ejercicio en una plataforma de autenticación de producción

## Objetivos

El POC aborda:

* Stateful frente a stateless
* HTTP y el problema de conservar estado
* Seguridad, experiencia de usuario y rendimiento
* Riesgos específicos de sesiones
* Riesgos específicos de JWT
* Escalabilidad horizontal
* Revocación después de cambio de contraseña
* Bloqueo administrativo
* Logout manual
* Logout o rechazo por timeout
* Páginas públicas y protegidas
* Autenticación y autorización
* Experiencia de usuario en ambos métodos

## Estrategia de comparación

Las dos variantes comparten:

* usuarios
* reglas de autorización
* páginas
* handlers funcionales
* persistencia de usuarios
* interfaz visual
* mensajes
* escenarios de demostración

Solo cambia el mecanismo utilizado para emitir, transportar, validar y revocar la credencial de autenticación

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

## Stack

* Go
* `net/http`
* `html/template`
* HTML semántico
* CSS local
* SQLite
* bcrypt
* JWT
* Redis en las fases distribuidas
* Docker Compose opcional para iniciar Redis

No se utilizó un framework frontend ni un framework HTTP

## Aplicaciones previstas

```text
Session application
http://localhost:8081

JWT application
http://localhost:8082
```

Los puertos podrán cambiarse mediante variables de entorno para ejecutar varias instancias al mismo tiempo

## Páginas

| Ruta                | Acceso        | Propósito                                  |
| ------------------- | ------------- | ------------------------------------------ |
| `/`                 | Público       | Presentación del método y navegación       |
| `/login`            | Público       | Inicio de sesión                           |
| `/dashboard`        | Autenticado   | Información del usuario y de la credencial |
| `/account/password` | Autenticado   | Cambio de contraseña                       |
| `/admin/users`      | Administrador | Listado y bloqueo de usuarios              |
| `/logout`           | Autenticado   | Cierre manual de sesión                    |
| `/api/me`           | Autenticado   | Recurso JSON para pruebas con curl         |
| `/health`           | Público       | Estado básico de la instancia              |

## Estructura objetivo

```text
.
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

SQLite conserva:

* usuarios
* hash de contraseña
* rol
* estado activo o bloqueado
* versión de autenticación
* fechas relevantes

SQLite permite que varias instancias locales observen el mismo estado de usuario sin introducir un servidor de base de datos adicional

### Memoria

La memoria se utiliza para demostrar:

* sesiones locales
* revocaciones locales
* pérdida de estado al reiniciar
* inconsistencias entre instancias

### Redis

Redis se utilizó para demostrar:

* sesiones compartidas entre instancias
* revocación JWT compartida
* expiración mediante TTL
* dependencia de disponibilidad del store

## Variables previstas

La lista se mantiene en `.env.example`

```text
APP_PORT
APP_INSTANCE
DATABASE_PATH
COOKIE_SECURE
SESSION_STORE
SESSION_IDLE_TIMEOUT
SESSION_ABSOLUTE_TIMEOUT
JWT_SECRET
JWT_ISSUER
JWT_AUDIENCE
JWT_TTL
JWT_SECURITY_MODE
JWT_REVOCATION_STORE
REDIS_ADDR
REDIS_PASSWORD
REDIS_DB
```

Los secretos reales permanecen en `.env` (NO SE VERSIONA EN GIT)


## Flujo de desarrollo

El proyecto se implementa por fases

| Fase | Descripción                            | Estado    |
| ---: | -------------------------------------- | --------- |
|    0 | Bootstrap del repositorio              | Pendiente |
|    1 | Aplicación común y usuarios            | Pendiente |
|    2 | Sesiones locales                       | Pendiente |
|    3 | Sesiones distribuidas con Redis        | Pendiente |
|    4 | JWT puro                               | Pendiente |
|    5 | JWT con revocación                     | Pendiente |
|    6 | Comparación y observabilidad           | Pendiente |
|    7 | Revisión y preparación de demostración | Pendiente |

Cada fase:

1. mantener el repositorio compilable
2. implementar únicamente su alcance
3. finalizar con una prueba manual
4. actualizar este estado cuando corresponda
5. conservar los escenarios construidos anteriormente

## Comandos generales

Cuando exista el módulo Go:

```bash
gofmt -w .
go mod tidy
go vet ./...
go test ./...
go build ./...
```

Los comandos específicos de ejecución se agregarán cuando se creen los ejecutables

## Principios de desarrollo

* SOLID
* KISS
* DRY
* separación de responsabilidades
* bajo acoplamiento
* nombres claros
* dependencias explícitas
* patrones solamente cuando resuelvan una variación real
* seguridad implementada en backend
* comentarios útiles para comprender decisiones
* código proporcional al objetivo académico

## Fuera de alcance

* OAuth
* OpenID Connect
* SSO
* MFA
* refresh tokens
* login social
* recuperación de contraseña
* microservicios
* Kubernetes
* despliegue cloud
* frontend SPA
* suite de pruebas unitarias
* monitoreo de producción
