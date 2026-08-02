package config

import (
	"testing"
	"time"
)

func TestLoadSession(t *testing.T) {
	t.Setenv("SESSION_STORE", "memory")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("SESSION_IDLE_TIMEOUT", "30s")
	t.Setenv("SESSION_ABSOLUTE_TIMEOUT", "2m")

	loadedConfig, err := LoadSession()
	if err != nil {
		t.Fatalf("LoadSession() error = %v", err)
	}
	if !loadedConfig.CookieSecure || loadedConfig.IdleTimeout != 30*time.Second || loadedConfig.AbsoluteTimeout != 2*time.Minute || loadedConfig.Store != SessionStoreMemory {
		t.Fatalf("LoadSession() = %#v", loadedConfig)
	}
}

func TestLoadSessionRedis(t *testing.T) {
	t.Setenv("SESSION_STORE", "redis")
	t.Setenv("REDIS_ADDR", "redis.internal:6380")
	t.Setenv("REDIS_PASSWORD", "demo-secret")
	t.Setenv("REDIS_DB", "4")

	loadedConfig, err := LoadSession()
	if err != nil {
		t.Fatalf("LoadSession() error = %v", err)
	}
	if loadedConfig.Store != SessionStoreRedis {
		t.Fatalf("LoadSession().Store = %q, want %q", loadedConfig.Store, SessionStoreRedis)
	}
	if loadedConfig.Redis.Address != "redis.internal:6380" || loadedConfig.Redis.Password != "demo-secret" || loadedConfig.Redis.Database != 4 {
		t.Fatalf("LoadSession().Redis = %#v", loadedConfig.Redis)
	}
}

func TestLoadSessionMemoryIgnoresInvalidRedisConfig(t *testing.T) {
	t.Setenv("SESSION_STORE", "memory")
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("REDIS_DB", "invalid")

	if _, err := LoadSession(); err != nil {
		t.Fatalf("LoadSession() error = %v", err)
	}
}

func TestLoadSessionRejectsInvalidStore(t *testing.T) {
	t.Setenv("SESSION_STORE", "unknown")

	if _, err := LoadSession(); err == nil {
		t.Fatal("LoadSession() error = nil, want invalid store error")
	}
}

func TestLoadSessionRejectsInvalidRedisDatabase(t *testing.T) {
	t.Setenv("SESSION_STORE", "redis")
	t.Setenv("REDIS_DB", "-1")

	if _, err := LoadSession(); err == nil {
		t.Fatal("LoadSession() error = nil, want invalid Redis database error")
	}
}

func TestLoadSessionRejectsInvalidTimeouts(t *testing.T) {
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("SESSION_IDLE_TIMEOUT", "2m")
	t.Setenv("SESSION_ABSOLUTE_TIMEOUT", "2m")

	if _, err := LoadSession(); err == nil {
		t.Fatal("LoadSession() error = nil, want invalid timeout error")
	}
}

func TestLoadJWT(t *testing.T) {
	t.Setenv("JWT_SECRET", "a-local-test-secret-with-32-bytes-minimum")
	t.Setenv("JWT_ISSUER", "test-issuer")
	t.Setenv("JWT_AUDIENCE", "test-audience")
	t.Setenv("JWT_TTL", "90s")
	t.Setenv("COOKIE_SECURE", "true")

	loadedConfig, err := LoadJWT()
	if err != nil {
		t.Fatalf("LoadJWT() error = %v", err)
	}
	if loadedConfig.Secret == "" || loadedConfig.Issuer != "test-issuer" || loadedConfig.Audience != "test-audience" || loadedConfig.TTL != 90*time.Second || !loadedConfig.CookieSecure || loadedConfig.SecurityMode != JWTSecurityModePure {
		t.Fatalf("LoadJWT() = %#v", loadedConfig)
	}
}

func TestLoadJWTPureIgnoresRevocationAndRedisConfig(t *testing.T) {
	t.Setenv("JWT_SECRET", "a-local-test-secret-with-32-bytes-minimum")
	t.Setenv("JWT_SECURITY_MODE", "pure")
	t.Setenv("JWT_REVOCATION_STORE", "invalid")
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("REDIS_DB", "invalid")

	loadedConfig, err := LoadJWT()
	if err != nil {
		t.Fatalf("LoadJWT() error = %v", err)
	}
	if loadedConfig.SecurityMode != JWTSecurityModePure {
		t.Fatalf("LoadJWT().SecurityMode = %q", loadedConfig.SecurityMode)
	}
}

func TestLoadJWTControlledMemoryAndRedis(t *testing.T) {
	t.Setenv("JWT_SECRET", "a-local-test-secret-with-32-bytes-minimum")
	t.Setenv("JWT_SECURITY_MODE", "controlled")
	t.Setenv("JWT_REVOCATION_STORE", "memory")
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("REDIS_DB", "invalid")

	memoryConfig, err := LoadJWT()
	if err != nil {
		t.Fatalf("LoadJWT(memory) error = %v", err)
	}
	if memoryConfig.RevocationStore != JWTRevocationStoreMemory {
		t.Fatalf("LoadJWT(memory).RevocationStore = %q", memoryConfig.RevocationStore)
	}

	t.Setenv("JWT_REVOCATION_STORE", "redis")
	t.Setenv("REDIS_ADDR", "redis.internal:6380")
	t.Setenv("REDIS_DB", "3")
	redisConfig, err := LoadJWT()
	if err != nil {
		t.Fatalf("LoadJWT(redis) error = %v", err)
	}
	if redisConfig.RevocationStore != JWTRevocationStoreRedis || redisConfig.Redis.Address != "redis.internal:6380" || redisConfig.Redis.Database != 3 {
		t.Fatalf("LoadJWT(redis) = %#v", redisConfig)
	}
}

func TestLoadJWTRejectsInvalidSecurityModeAndRevocationStore(t *testing.T) {
	t.Setenv("JWT_SECRET", "a-local-test-secret-with-32-bytes-minimum")
	t.Setenv("JWT_SECURITY_MODE", "unknown")
	if _, err := LoadJWT(); err == nil {
		t.Fatal("LoadJWT() error = nil, want invalid security mode error")
	}

	t.Setenv("JWT_SECURITY_MODE", "controlled")
	t.Setenv("JWT_REVOCATION_STORE", "unknown")
	if _, err := LoadJWT(); err == nil {
		t.Fatal("LoadJWT() error = nil, want invalid revocation store error")
	}
}

func TestLoadJWTRejectsMissingOrShortSecret(t *testing.T) {
	for _, secret := range []string{"", "too-short"} {
		t.Run(secret, func(t *testing.T) {
			t.Setenv("JWT_SECRET", secret)
			if _, err := LoadJWT(); err == nil {
				t.Fatal("LoadJWT() error = nil, want invalid secret error")
			}
		})
	}
}
