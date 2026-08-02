package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"session-vs-jwt-poc/internal/security"
	"session-vs-jwt-poc/internal/user"
)

type seedUser struct {
	name     string
	email    string
	password string
	role     user.Role
}

func SeedUsers(ctx context.Context, database *sql.DB) (seedErr error) {
	seedUsers := []seedUser{
		{name: "Administrador", email: "admin@poc.local", password: "Admin123!", role: user.RoleAdmin},
		{name: "Usuario", email: "user@poc.local", password: "User123!", role: user.RoleUser},
	}

	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("iniciar seed de usuarios: %w", err)
	}
	transactionCommitted := false
	defer func() {
		if transactionCommitted {
			return
		}
		if err := transaction.Rollback(); err != nil {
			seedErr = errors.Join(seedErr, fmt.Errorf("revertir seed de usuarios: %w", err))
		}
	}()

	now := time.Now().UTC().Unix()
	for _, seed := range seedUsers {
		passwordHash, err := security.HashPassword(seed.password)
		if err != nil {
			return fmt.Errorf("preparar contraseña de seed: %w", err)
		}

		_, err = transaction.ExecContext(
			ctx,
			`INSERT INTO users (name, email, password_hash, role, active, auth_version, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 1, 1, ?, ?)
			 ON CONFLICT(email) DO NOTHING`,
			seed.name,
			seed.email,
			passwordHash,
			seed.role,
			now,
			now,
		)
		if err != nil {
			return fmt.Errorf("insertar usuario de demostración: %w", err)
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("confirmar seed de usuarios: %w", err)
	}
	transactionCommitted = true

	return nil
}
