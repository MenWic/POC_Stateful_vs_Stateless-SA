package user

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("usuario no encontrado")

type Repository interface {
	FindByEmail(ctx context.Context, email string) (User, error)
	FindByID(ctx context.Context, userID int64) (User, error)
	List(ctx context.Context) ([]User, error)
	UpdateSecurity(ctx context.Context, update SecurityUpdate) error
}
