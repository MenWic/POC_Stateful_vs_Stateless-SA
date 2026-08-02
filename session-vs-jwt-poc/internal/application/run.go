package application

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"session-vs-jwt-poc/internal/auth"
	jwtmanager "session-vs-jwt-poc/internal/auth/jwt"
	"session-vs-jwt-poc/internal/auth/session"
	"session-vs-jwt-poc/internal/config"
	"session-vs-jwt-poc/internal/storage/memory"
	redisstore "session-vs-jwt-poc/internal/storage/redis"
	"session-vs-jwt-poc/internal/storage/sqlite"
	"session-vs-jwt-poc/internal/user"
	webui "session-vs-jwt-poc/web"
)

const shutdownTimeout = 5 * time.Second

type Options struct {
	Method            string
	DefaultPort       string
	DefaultInstanceID string
	SessionsEnabled   bool
	JWTEnabled        bool
}

func Run(options Options) (runErr error) {
	logger := log.New(os.Stdout, "", log.LstdFlags)

	appConfig, err := config.Load(options.DefaultPort, options.DefaultInstanceID)
	if err != nil {
		return fmt.Errorf("cargar configuración: %w", err)
	}

	database, err := sqlite.Open(context.Background(), appConfig.DatabasePath)
	if err != nil {
		return fmt.Errorf("inicializar SQLite: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			closeErr := fmt.Errorf("cerrar base de datos: %w", err)
			if runErr == nil {
				runErr = closeErr
				return
			}
			logger.Printf("error adicional durante el apagado: %v", closeErr)
		}
	}()

	if err := sqlite.Initialize(context.Background(), database); err != nil {
		return fmt.Errorf("crear esquema SQLite: %w", err)
	}
	if err := sqlite.SeedUsers(context.Background(), database); err != nil {
		return fmt.Errorf("crear usuarios de demostración: %w", err)
	}

	userRepository := sqlite.NewUserRepository(database)
	userService := user.NewService(userRepository)

	var webAuthentication *webui.Authentication
	if options.SessionsEnabled && options.JWTEnabled {
		return fmt.Errorf("la aplicación no puede habilitar sesiones y JWT simultáneamente")
	}
	if options.SessionsEnabled {
		sessionConfig, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("cargar configuración de sesiones: %w", err)
		}

		var sessionStore session.Store
		switch sessionConfig.Store {
		case config.SessionStoreMemory:
			sessionStore = memory.NewSessionStore()
		case config.SessionStoreRedis:
			redisClient, err := connectRedis(sessionConfig.Redis)
			if err != nil {
				return err
			}
			defer closeRedisClient(redisClient, logger, &runErr)
			sessionStore = redisstore.NewSessionStore(redisClient)
		default:
			return fmt.Errorf("store de sesiones no soportado: %q", sessionConfig.Store)
		}

		sessionManager := session.NewManager(
			sessionStore,
			userService,
			sessionConfig.IdleTimeout,
			sessionConfig.AbsoluteTimeout,
			appConfig.InstanceID,
		)
		webAuthentication = &webui.Authentication{
			Issuer:       sessionManager,
			Validator:    sessionManager,
			Revoker:      sessionManager,
			Transport:    session.NewCookieTransport(sessionConfig.CookieSecure),
			SecurityMode: "session",
			Validation: auth.ValidationMetadata{
				StoreName:          string(sessionConfig.Store),
				ServerStateChecked: true,
				CurrentUserChecked: true,
				Description:        sessionValidationDescription(sessionConfig.Store),
			},
			UsesIdleExpiration: true,
		}
	}
	if options.JWTEnabled {
		jwtConfig, err := config.LoadJWT()
		if err != nil {
			return fmt.Errorf("cargar configuración JWT: %w", err)
		}
		jwtManager := jwtmanager.NewManager(
			[]byte(jwtConfig.Secret),
			jwtConfig.Issuer,
			jwtConfig.Audience,
			jwtConfig.TTL,
			appConfig.InstanceID,
		)
		validator := auth.CredentialValidator(jwtManager)
		var revoker auth.CredentialRevoker
		storeName := "none"
		serverStateChecked := false
		currentUserChecked := false
		if jwtConfig.SecurityMode == config.JWTSecurityModeControlled {
			var revocationStore jwtmanager.RevocationStore
			switch jwtConfig.RevocationStore {
			case config.JWTRevocationStoreMemory:
				revocationStore = memory.NewJWTRevocationStore()
			case config.JWTRevocationStoreRedis:
				redisClient, err := connectRedis(jwtConfig.Redis)
				if err != nil {
					return err
				}
				defer closeRedisClient(redisClient, logger, &runErr)
				revocationStore = redisstore.NewJWTRevocationStore(redisClient)
			default:
				return fmt.Errorf("store de revocación JWT no soportado: %q", jwtConfig.RevocationStore)
			}
			controlledAuthenticator := jwtmanager.NewControlledAuthenticator(jwtManager, revocationStore, userService)
			validator = controlledAuthenticator
			revoker = controlledAuthenticator
			storeName = string(jwtConfig.RevocationStore)
			serverStateChecked = true
			currentUserChecked = true
		}
		webAuthentication = &webui.Authentication{
			Issuer:        jwtManager,
			Validator:     validator,
			Revoker:       revoker,
			Transport:     jwtmanager.NewCookieTransport(jwtConfig.CookieSecure),
			CSRFTransport: jwtmanager.NewCSRFTokenTransport([]byte(jwtConfig.Secret), jwtConfig.CookieSecure),
			SecurityMode:  string(jwtConfig.SecurityMode),
			Validation: auth.ValidationMetadata{
				StoreName:          storeName,
				ServerStateChecked: serverStateChecked,
				CurrentUserChecked: currentUserChecked,
				Description:        jwtValidationDescription(jwtConfig.SecurityMode, jwtConfig.RevocationStore),
			},
		}
	}

	handler, err := webui.NewHandler(webui.AppInfo{
		Method:     options.Method,
		InstanceID: appConfig.InstanceID,
	}, userService, logger, webAuthentication)
	if err != nil {
		return fmt.Errorf("crear servidor web: %w", err)
	}

	server := &http.Server{
		Addr:              appConfig.Address(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("escuchar en %s: %w", server.Addr, err)
	}

	logger.Printf("aplicación %s iniciada en http://localhost:%s (instancia %s)", options.Method, appConfig.Port, appConfig.InstanceID)

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("servir HTTP: %w", err)
	case <-signalContext.Done():
		logger.Printf("apagando aplicación %s", options.Method)
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("apagar servidor HTTP: %w", err)
	}

	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("finalizar servidor HTTP: %w", err)
	}

	return nil
}

func sessionValidationDescription(store config.SessionStore) string {
	if store == config.SessionStoreRedis {
		return "sesión en Redis + usuario actual + actualización de actividad"
	}
	return "sesión en memoria + usuario actual + actualización de actividad"
}

func jwtValidationDescription(mode config.JWTSecurityMode, store config.JWTRevocationStore) string {
	if mode == config.JWTSecurityModePure {
		return "firma HS256 + claims"
	}
	if store == config.JWTRevocationStoreRedis {
		return "firma HS256 + claims + denylist Redis + usuario actual"
	}
	return "firma HS256 + claims + denylist local + usuario actual"
}

func connectRedis(redisConfig config.RedisConfig) (*redisclient.Client, error) {
	redisClient := redisclient.NewClient(&redisclient.Options{
		Addr:     redisConfig.Address,
		Password: redisConfig.Password,
		DB:       redisConfig.Database,
	})
	pingContext, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if err := redisClient.Ping(pingContext).Err(); err != nil {
		_ = redisClient.Close()
		return nil, fmt.Errorf("conectar con Redis en %s: %w", redisConfig.Address, err)
	}
	return redisClient, nil
}

func closeRedisClient(redisClient *redisclient.Client, logger *log.Logger, runErr *error) {
	if err := redisClient.Close(); err != nil {
		closeErr := fmt.Errorf("cerrar cliente Redis: %w", err)
		if *runErr == nil {
			*runErr = closeErr
			return
		}
		logger.Printf("error adicional durante el apagado: %v", closeErr)
	}
}
