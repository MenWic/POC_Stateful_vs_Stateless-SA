package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"session-vs-jwt-poc/internal/user"
)

const userColumns = `id, name, email, password_hash, role, active, auth_version, created_at, updated_at`

type UserRepository struct {
	database *sql.DB
}

type rowScanner interface {
	Scan(destinations ...any) error
}

func NewUserRepository(database *sql.DB) *UserRepository {
	return &UserRepository{database: database}
}

func (repository *UserRepository) FindByEmail(ctx context.Context, email string) (user.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE email = ?`
	storedUser, err := scanUser(repository.database.QueryRowContext(ctx, query, email))
	if errors.Is(err, sql.ErrNoRows) {
		return user.User{}, user.ErrNotFound
	}
	if err != nil {
		return user.User{}, fmt.Errorf("buscar usuario por correo: %w", err)
	}

	return storedUser, nil
}

func (repository *UserRepository) FindByID(ctx context.Context, userID int64) (user.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE id = ?`
	storedUser, err := scanUser(repository.database.QueryRowContext(ctx, query, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return user.User{}, user.ErrNotFound
	}
	if err != nil {
		return user.User{}, fmt.Errorf("buscar usuario por ID: %w", err)
	}

	return storedUser, nil
}

func (repository *UserRepository) List(ctx context.Context) (users []user.User, listErr error) {
	query := `SELECT ` + userColumns + ` FROM users ORDER BY name, id`
	rows, err := repository.database.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("consultar usuarios: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			listErr = errors.Join(listErr, fmt.Errorf("cerrar consulta de usuarios: %w", err))
		}
	}()

	users = make([]user.User, 0)
	for rows.Next() {
		storedUser, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("leer usuario: %w", err)
		}
		users = append(users, storedUser)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recorrer usuarios: %w", err)
	}

	return users, nil
}

func (repository *UserRepository) UpdateSecurity(ctx context.Context, update user.SecurityUpdate) error {
	result, err := repository.database.ExecContext(
		ctx,
		`UPDATE users
		 SET password_hash = ?, active = ?, auth_version = ?, updated_at = ?
		 WHERE id = ?`,
		update.PasswordHash,
		boolAsInteger(update.Active),
		update.AuthVersion,
		update.UpdatedAt.UTC().Unix(),
		update.UserID,
	)
	if err != nil {
		return fmt.Errorf("actualizar seguridad del usuario: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("verificar actualización de seguridad: %w", err)
	}
	if rowsAffected == 0 {
		return user.ErrNotFound
	}

	return nil
}

func scanUser(scanner rowScanner) (user.User, error) {
	var storedUser user.User
	var active int
	var createdAtUnix int64
	var updatedAtUnix int64

	err := scanner.Scan(
		&storedUser.ID,
		&storedUser.Name,
		&storedUser.Email,
		&storedUser.PasswordHash,
		&storedUser.Role,
		&active,
		&storedUser.AuthVersion,
		&createdAtUnix,
		&updatedAtUnix,
	)
	if err != nil {
		return user.User{}, err
	}

	storedUser.Active = active == 1
	storedUser.CreatedAt = time.Unix(createdAtUnix, 0).UTC()
	storedUser.UpdatedAt = time.Unix(updatedAtUnix, 0).UTC()

	return storedUser, nil
}

func boolAsInteger(value bool) int {
	if value {
		return 1
	}

	return 0
}
