package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port         string
	InstanceID   string
	DatabasePath string
}

type SessionConfig struct {
	CookieSecure    bool
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Store           SessionStore
	Redis           RedisConfig
}

type JWTConfig struct {
	Secret          string
	Issuer          string
	Audience        string
	TTL             time.Duration
	CookieSecure    bool
	SecurityMode    JWTSecurityMode
	RevocationStore JWTRevocationStore
	Redis           RedisConfig
}

type SessionStore string

const (
	SessionStoreMemory SessionStore = "memory"
	SessionStoreRedis  SessionStore = "redis"
)

type JWTSecurityMode string

const (
	JWTSecurityModePure       JWTSecurityMode = "pure"
	JWTSecurityModeControlled JWTSecurityMode = "controlled"
)

type JWTRevocationStore string

const (
	JWTRevocationStoreMemory JWTRevocationStore = "memory"
	JWTRevocationStoreRedis  JWTRevocationStore = "redis"
)

type RedisConfig struct {
	Address  string
	Password string
	Database int
}

func Load(defaultPort, defaultInstanceID string) (Config, error) {
	port := environmentValue("APP_PORT", defaultPort)
	if err := validatePort(port); err != nil {
		return Config{}, err
	}

	instanceID := environmentValue("APP_INSTANCE", defaultInstanceID)
	if instanceID == "" {
		return Config{}, fmt.Errorf("APP_INSTANCE no puede estar vacío")
	}

	databasePath := environmentValue("DATABASE_PATH", "data/poc.db")
	if databasePath == "" {
		return Config{}, fmt.Errorf("DATABASE_PATH no puede estar vacío")
	}

	return Config{
		Port:         port,
		InstanceID:   instanceID,
		DatabasePath: databasePath,
	}, nil
}

func (config Config) Address() string {
	return net.JoinHostPort("", config.Port)
}

func LoadSession() (SessionConfig, error) {
	store := SessionStore(environmentValue("SESSION_STORE", string(SessionStoreMemory)))
	if store != SessionStoreMemory && store != SessionStoreRedis {
		return SessionConfig{}, fmt.Errorf("SESSION_STORE debe ser memory o redis")
	}

	cookieSecure, err := loadCookieSecure()
	if err != nil {
		return SessionConfig{}, err
	}

	idleTimeout, err := time.ParseDuration(environmentValue("SESSION_IDLE_TIMEOUT", "2m"))
	if err != nil {
		return SessionConfig{}, fmt.Errorf("SESSION_IDLE_TIMEOUT no es una duración válida: %w", err)
	}
	absoluteTimeout, err := time.ParseDuration(environmentValue("SESSION_ABSOLUTE_TIMEOUT", "10m"))
	if err != nil {
		return SessionConfig{}, fmt.Errorf("SESSION_ABSOLUTE_TIMEOUT no es una duración válida: %w", err)
	}

	if idleTimeout <= 0 {
		return SessionConfig{}, fmt.Errorf("SESSION_IDLE_TIMEOUT debe ser mayor que cero")
	}
	if absoluteTimeout <= 0 {
		return SessionConfig{}, fmt.Errorf("SESSION_ABSOLUTE_TIMEOUT debe ser mayor que cero")
	}
	if idleTimeout >= absoluteTimeout {
		return SessionConfig{}, fmt.Errorf("SESSION_IDLE_TIMEOUT debe ser menor que SESSION_ABSOLUTE_TIMEOUT")
	}

	loadedConfig := SessionConfig{
		CookieSecure:    cookieSecure,
		IdleTimeout:     idleTimeout,
		AbsoluteTimeout: absoluteTimeout,
		Store:           store,
	}
	if store == SessionStoreMemory {
		return loadedConfig, nil
	}

	loadedConfig.Redis, err = loadRedisConfig("SESSION_STORE=redis")
	if err != nil {
		return SessionConfig{}, err
	}

	return loadedConfig, nil
}

func LoadJWT() (JWTConfig, error) {
	secret := environmentValue("JWT_SECRET", "")
	if secret == "" {
		return JWTConfig{}, fmt.Errorf("JWT_SECRET no puede estar vacío")
	}
	if len(secret) < 32 {
		return JWTConfig{}, fmt.Errorf("JWT_SECRET debe tener al menos 32 caracteres")
	}

	issuer := environmentValue("JWT_ISSUER", "session-vs-jwt-poc")
	if issuer == "" {
		return JWTConfig{}, fmt.Errorf("JWT_ISSUER no puede estar vacío")
	}
	audience := environmentValue("JWT_AUDIENCE", "session-vs-jwt-web")
	if audience == "" {
		return JWTConfig{}, fmt.Errorf("JWT_AUDIENCE no puede estar vacío")
	}
	ttl, err := time.ParseDuration(environmentValue("JWT_TTL", "2m"))
	if err != nil {
		return JWTConfig{}, fmt.Errorf("JWT_TTL no es una duración válida: %w", err)
	}
	if ttl <= 0 {
		return JWTConfig{}, fmt.Errorf("JWT_TTL debe ser mayor que cero")
	}
	cookieSecure, err := loadCookieSecure()
	if err != nil {
		return JWTConfig{}, err
	}

	securityMode := JWTSecurityMode(environmentValue("JWT_SECURITY_MODE", string(JWTSecurityModePure)))
	if securityMode != JWTSecurityModePure && securityMode != JWTSecurityModeControlled {
		return JWTConfig{}, fmt.Errorf("JWT_SECURITY_MODE debe ser pure o controlled")
	}

	loadedConfig := JWTConfig{
		Secret:          secret,
		Issuer:          issuer,
		Audience:        audience,
		TTL:             ttl,
		CookieSecure:    cookieSecure,
		SecurityMode:    securityMode,
		RevocationStore: JWTRevocationStoreMemory,
	}
	if securityMode == JWTSecurityModePure {
		return loadedConfig, nil
	}

	revocationStore := JWTRevocationStore(environmentValue("JWT_REVOCATION_STORE", string(JWTRevocationStoreMemory)))
	if revocationStore != JWTRevocationStoreMemory && revocationStore != JWTRevocationStoreRedis {
		return JWTConfig{}, fmt.Errorf("JWT_REVOCATION_STORE debe ser memory o redis")
	}
	loadedConfig.RevocationStore = revocationStore
	if revocationStore == JWTRevocationStoreMemory {
		return loadedConfig, nil
	}

	loadedConfig.Redis, err = loadRedisConfig("JWT_SECURITY_MODE=controlled y JWT_REVOCATION_STORE=redis")
	if err != nil {
		return JWTConfig{}, err
	}
	return loadedConfig, nil
}

func loadCookieSecure() (bool, error) {
	cookieSecure, err := strconv.ParseBool(environmentValue("COOKIE_SECURE", "false"))
	if err != nil {
		return false, fmt.Errorf("COOKIE_SECURE debe ser true o false: %w", err)
	}

	return cookieSecure, nil
}

func loadRedisConfig(requiredBy string) (RedisConfig, error) {
	redisAddress := environmentValue("REDIS_ADDR", "localhost:6379")
	if redisAddress == "" {
		return RedisConfig{}, fmt.Errorf("REDIS_ADDR no puede estar vacío cuando %s", requiredBy)
	}
	redisDatabase, err := strconv.Atoi(environmentValue("REDIS_DB", "0"))
	if err != nil || redisDatabase < 0 {
		return RedisConfig{}, fmt.Errorf("REDIS_DB debe ser un entero mayor o igual que cero")
	}
	return RedisConfig{
		Address:  redisAddress,
		Password: environmentValue("REDIS_PASSWORD", ""),
		Database: redisDatabase,
	}, nil
}

func environmentValue(name, fallback string) string {
	value, exists := os.LookupEnv(name)
	if !exists {
		return fallback
	}

	return strings.TrimSpace(value)
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("APP_PORT debe ser un número entre 1 y 65535")
	}

	return nil
}
