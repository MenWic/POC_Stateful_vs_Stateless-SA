package user

import "time"

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type User struct {
	ID           int64
	Name         string
	Email        string
	PasswordHash string
	Role         Role
	Active       bool
	AuthVersion  int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type SecurityUpdate struct {
	UserID       int64
	PasswordHash string
	Active       bool
	AuthVersion  int64
	UpdatedAt    time.Time
}

type ValidatedCredentials struct {
	UserID      int64
	Name        string
	Email       string
	Role        Role
	AuthVersion int64
}

type Summary struct {
	ID          int64
	Name        string
	Email       string
	Role        Role
	Active      bool
	AuthVersion int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
