package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func Open(ctx context.Context, databasePath string) (*sql.DB, error) {
	databaseDirectory := filepath.Dir(databasePath)
	if databaseDirectory != "." {
		if err := os.MkdirAll(databaseDirectory, 0o750); err != nil {
			return nil, fmt.Errorf("crear directorio de base de datos: %w", err)
		}
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, fmt.Errorf("abrir base de datos SQLite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if err := database.PingContext(ctx); err != nil {
		return nil, closeAfterError(database, fmt.Errorf("verificar conexión SQLite: %w", err))
	}

	if _, err := database.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return nil, closeAfterError(database, fmt.Errorf("configurar espera de SQLite: %w", err))
	}
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		return nil, closeAfterError(database, fmt.Errorf("configurar journal de SQLite: %w", err))
	}

	return database, nil
}

func Initialize(ctx context.Context, database *sql.DB) error {
	const schema = `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT NOT NULL COLLATE NOCASE UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
			active INTEGER NOT NULL CHECK (active IN (0, 1)),
			auth_version INTEGER NOT NULL CHECK (auth_version >= 1),
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`

	if _, err := database.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("crear tabla de usuarios: %w", err)
	}

	return nil
}

func closeAfterError(database *sql.DB, operationErr error) error {
	if err := database.Close(); err != nil {
		return errors.Join(operationErr, fmt.Errorf("cerrar base de datos: %w", err))
	}

	return operationErr
}
