package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"session-vs-jwt-poc/internal/security"
	"session-vs-jwt-poc/internal/storage/sqlite"
	"session-vs-jwt-poc/internal/user"
)

func TestSeedUsersIsIdempotentAndPreservesSecurityChanges(t *testing.T) {
	ctx := context.Background()
	database, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "poc.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	if err := sqlite.Initialize(ctx, database); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if err := sqlite.SeedUsers(ctx, database); err != nil {
		t.Fatalf("SeedUsers() first error = %v", err)
	}
	if err := sqlite.SeedUsers(ctx, database); err != nil {
		t.Fatalf("SeedUsers() second error = %v", err)
	}

	repository := sqlite.NewUserRepository(database)
	storedUsers, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(storedUsers) != 2 {
		t.Fatalf("List() count = %d, want 2", len(storedUsers))
	}

	adminUser, err := repository.FindByEmail(ctx, "admin@poc.local")
	if err != nil {
		t.Fatalf("FindByEmail() error = %v", err)
	}
	if adminUser.PasswordHash == "Admin123!" {
		t.Fatal("PasswordHash contains the seed password")
	}
	if !security.PasswordMatches(adminUser.PasswordHash, "Admin123!") {
		t.Fatal("seed password does not match its hash")
	}

	userService := user.NewService(repository)
	updatedAdmin, err := userService.ChangePassword(ctx, adminUser.ID, "Admin123!", "Changed123!", "Changed123!")
	if err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	if updatedAdmin.AuthVersion != 2 {
		t.Fatalf("ChangePassword() AuthVersion = %d, want 2", updatedAdmin.AuthVersion)
	}
	if err := sqlite.SeedUsers(ctx, database); err != nil {
		t.Fatalf("SeedUsers() after update error = %v", err)
	}

	validatedUser, err := userService.Authenticate(ctx, " ADMIN@POC.LOCAL ", "Changed123!")
	if err != nil {
		t.Fatalf("Authenticate() updated credentials error = %v", err)
	}
	if validatedUser.Email != "admin@poc.local" || validatedUser.Role != user.RoleAdmin {
		t.Fatalf("Authenticate() user = %#v", validatedUser)
	}
	if _, err := userService.Authenticate(ctx, "admin@poc.local", "Admin123!"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("Authenticate() old password error = %v", err)
	}

	adminUser, err = repository.FindByEmail(ctx, "admin@poc.local")
	if err != nil {
		t.Fatalf("FindByEmail() after seed error = %v", err)
	}
	if adminUser.AuthVersion != 2 || !security.PasswordMatches(adminUser.PasswordHash, "Changed123!") {
		t.Fatal("seed overwrote existing security data")
	}

	normalUser, err := repository.FindByEmail(ctx, "user@poc.local")
	if err != nil {
		t.Fatalf("FindByEmail() user error = %v", err)
	}
	blockedUser, err := userService.SetActive(ctx, adminUser.ID, normalUser.ID, false)
	if err != nil {
		t.Fatalf("SetActive() block error = %v", err)
	}
	if blockedUser.Active || blockedUser.AuthVersion != 2 {
		t.Fatalf("SetActive() blocked user = %#v", blockedUser)
	}
	if _, err := userService.Authenticate(ctx, "user@poc.local", "User123!"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("Authenticate() blocked user error = %v", err)
	}
	if _, err := userService.SetActive(ctx, adminUser.ID, adminUser.ID, false); !errors.Is(err, user.ErrCannotBlockSelf) {
		t.Fatalf("SetActive() self block error = %v", err)
	}
	unblockedUser, err := userService.SetActive(ctx, adminUser.ID, normalUser.ID, true)
	if err != nil {
		t.Fatalf("SetActive() unblock error = %v", err)
	}
	if !unblockedUser.Active || unblockedUser.AuthVersion != 3 {
		t.Fatalf("SetActive() unblocked user = %#v", unblockedUser)
	}
	if _, err := userService.Authenticate(ctx, "user@poc.local", "User123!"); err != nil {
		t.Fatalf("Authenticate() unblocked user error = %v", err)
	}
	if _, err := userService.Authenticate(ctx, "missing@poc.local", "Changed123!"); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("Authenticate() missing user error = %v", err)
	}
}
