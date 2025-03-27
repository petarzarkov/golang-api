package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	Email     string    `json:"email" validate:"required,email"`
	Password  string    `json:"-"`
	Name      string    `json:"name" validate:"required,min=2,max=100"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time	`json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deletedAt"`
}

type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name" validate:"required,min=2,max=100"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserIdPath struct {
	ID string `path:"id" validate:"required" additionalProperties:"false"`
}

type UpdateUserInput struct {
	UserIdPath
	Email string `json:"email" validate:"omitempty,email"`
	Password string `json:"password" validate:"omitempty,min=8"`
	Name     string `json:"name" validate:"omitempty,min=2,max=100"`
}

type ListUsersQuery struct {
	Limit  int `query:"limit" default:"10" validate:"min=1"`
	Offset int `query:"offset" default:"0" validate:"min=0"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// HashPassword creates a bcrypt hash of the password
func (u *User) HashPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hash)
	return nil
}

// CheckPassword compares the password with its hash
func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
} 