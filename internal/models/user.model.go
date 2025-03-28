package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        string         `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id" format:"uuid"`
	Email     string         `gorm:"unique" json:"email" format:"email" required:"true"`
	Password  string         `json:"-" required:"true"`
	Name      string         `json:"name" required:"true" minLength:"2" maxLength:"100"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" type:"string" format:"date-time" nullable:"true" json:"deletedAt"`
}

type LoginRequest struct {
	Email    string `json:"email" format:"email" required:"true" example:"test@test.com"`
	Password string `json:"password" required:"true" minLength:"8" example:"password"`
}

type CreateUserRequest struct {
	Email    string `json:"email" format:"email" example:"test@test.com" required:"true"`
	Password string `json:"password" minLength:"8" example:"password" required:"true"`
	Name     string `json:"name" minLength:"2" maxLength:"100" required:"true"`
}

type UserIdPath struct {
	ID string `path:"id" format:"uuid" example:"13035584-4a80-4811-9f81-a5648564d40b" required:"true" additionalProperties:"false"`
}

type UpdateUserInput struct {
	UserIdPath
	Email    string `json:"email" format:"email" example:"test@test.com"`
	Password string `json:"password" minLength:"8" example:"password"`
	Name     string `json:"name" minLength:"2" maxLength:"100"`
}

type ListUsersQuery struct {
	Limit  int `query:"limit" default:"10" minimum:"1"`
	Offset int `query:"offset" default:"0" minimum:"0"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" required:"true"`
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
