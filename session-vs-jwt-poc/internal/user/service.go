package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"session-vs-jwt-poc/internal/security"
)

var (
	ErrInvalidCredentials     = errors.New("credenciales inválidas o usuario no disponible")
	ErrCurrentPasswordInvalid = errors.New("la contraseña actual no es correcta")
	ErrNewPasswordRequired    = errors.New("la contraseña nueva es obligatoria")
	ErrPasswordConfirmation   = errors.New("la confirmación no coincide")
	ErrPasswordUnchanged      = errors.New("la contraseña nueva debe ser diferente")
	ErrUserUnavailable        = errors.New("el usuario no está disponible")
	ErrCannotBlockSelf        = errors.New("el administrador no puede bloquear su propia cuenta")
)

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository}
}

func (service *Service) Authenticate(ctx context.Context, email, password string) (ValidatedCredentials, error) {
	storedUser, err := service.repository.FindByEmail(ctx, NormalizeEmail(email))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ValidatedCredentials{}, ErrInvalidCredentials
		}

		return ValidatedCredentials{}, fmt.Errorf("buscar usuario para validar credenciales: %w", err)
	}

	if !storedUser.Active || !security.PasswordMatches(storedUser.PasswordHash, password) {
		return ValidatedCredentials{}, ErrInvalidCredentials
	}

	return ValidatedCredentials{
		UserID:      storedUser.ID,
		Name:        storedUser.Name,
		Email:       storedUser.Email,
		Role:        storedUser.Role,
		AuthVersion: storedUser.AuthVersion,
	}, nil
}

func (service *Service) ListUsers(ctx context.Context) ([]Summary, error) {
	storedUsers, err := service.repository.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listar usuarios: %w", err)
	}

	summaries := make([]Summary, 0, len(storedUsers))
	for _, storedUser := range storedUsers {
		summaries = append(summaries, summaryFromUser(storedUser))
	}

	return summaries, nil
}

func (service *Service) GetByID(ctx context.Context, userID int64) (Summary, error) {
	storedUser, err := service.repository.FindByID(ctx, userID)
	if err != nil {
		return Summary{}, fmt.Errorf("buscar usuario por ID: %w", err)
	}

	return summaryFromUser(storedUser), nil
}

func (service *Service) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword, confirmation string) (Summary, error) {
	storedUser, err := service.repository.FindByID(ctx, userID)
	if err != nil {
		return Summary{}, fmt.Errorf("buscar usuario para cambiar contraseña: %w", err)
	}
	if !storedUser.Active {
		return Summary{}, ErrUserUnavailable
	}
	if !security.PasswordMatches(storedUser.PasswordHash, currentPassword) {
		return Summary{}, ErrCurrentPasswordInvalid
	}
	if newPassword == "" {
		return Summary{}, ErrNewPasswordRequired
	}
	if newPassword != confirmation {
		return Summary{}, ErrPasswordConfirmation
	}
	if security.PasswordMatches(storedUser.PasswordHash, newPassword) {
		return Summary{}, ErrPasswordUnchanged
	}

	passwordHash, err := security.HashPassword(newPassword)
	if err != nil {
		return Summary{}, fmt.Errorf("proteger contraseña nueva: %w", err)
	}

	storedUser.PasswordHash = passwordHash
	storedUser.AuthVersion++
	storedUser.UpdatedAt = time.Now().UTC()
	if err := service.repository.UpdateSecurity(ctx, SecurityUpdate{
		UserID:       storedUser.ID,
		PasswordHash: storedUser.PasswordHash,
		Active:       storedUser.Active,
		AuthVersion:  storedUser.AuthVersion,
		UpdatedAt:    storedUser.UpdatedAt,
	}); err != nil {
		return Summary{}, fmt.Errorf("guardar contraseña nueva: %w", err)
	}

	return summaryFromUser(storedUser), nil
}

func (service *Service) SetActive(ctx context.Context, actorUserID, targetUserID int64, active bool) (Summary, error) {
	if actorUserID == targetUserID && !active {
		return Summary{}, ErrCannotBlockSelf
	}

	storedUser, err := service.repository.FindByID(ctx, targetUserID)
	if err != nil {
		return Summary{}, fmt.Errorf("buscar usuario para cambiar estado: %w", err)
	}

	storedUser.Active = active
	storedUser.AuthVersion++
	storedUser.UpdatedAt = time.Now().UTC()
	if err := service.repository.UpdateSecurity(ctx, SecurityUpdate{
		UserID:       storedUser.ID,
		PasswordHash: storedUser.PasswordHash,
		Active:       storedUser.Active,
		AuthVersion:  storedUser.AuthVersion,
		UpdatedAt:    storedUser.UpdatedAt,
	}); err != nil {
		return Summary{}, fmt.Errorf("guardar estado del usuario: %w", err)
	}

	return summaryFromUser(storedUser), nil
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func summaryFromUser(storedUser User) Summary {
	return Summary{
		ID:          storedUser.ID,
		Name:        storedUser.Name,
		Email:       storedUser.Email,
		Role:        storedUser.Role,
		Active:      storedUser.Active,
		AuthVersion: storedUser.AuthVersion,
		CreatedAt:   storedUser.CreatedAt,
		UpdatedAt:   storedUser.UpdatedAt,
	}
}
