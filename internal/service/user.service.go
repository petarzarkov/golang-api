package service

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/internal/repository"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists        = errors.New("user already exists")
)

type UserService interface {
	Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error)
	GetUser(ctx context.Context, id string) (*models.User, error)
	UpdateUser(ctx context.Context, id string, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error)
}

type userService struct {
	repo      *repository.GormRepository[models.User]
	jwtSecret string
}

func NewUserService(repo *repository.GormRepository[models.User], jwtSecret string) UserService {
	return &userService{
		repo: repo,
		jwtSecret: jwtSecret,
	}
}

func (s *userService) Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	// Check if user exists	
	existingUser, err := s.repo.Exists(map[string]any{"email": req.Email})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Printf("Error checking if user exists: %v", err)
		return nil, err
	}

	if existingUser {
		log.Printf("User already exists %v", req.Name)
		return nil, ErrUserExists
	}

	// Create new user
	user := &models.User{
		Email: req.Email,
		Name:  req.Name,
	}

	// Hash password
	if err := user.HashPassword(req.Password); err != nil {
		return nil, err
	}

	createError := s.repo.Create(user)
	if createError != nil {
		return nil, createError
	}

	return user, nil
}


func (s *userService) Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error) {
	var user *models.User
	user, err := s.repo.Get(map[string]any{"email": req.Email})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := user.CheckPassword(req.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  tokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour in seconds
	}, nil
}

func (s *userService) GetUser(ctx context.Context, id string) (*models.User, error) {
	var user *models.User
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *userService) UpdateUser(ctx context.Context, id string, user *models.User) error {
	user.ID = uuid.MustParse(id) // Ensure the ID matches
	// Hash password
	if err := user.HashPassword(user.Password); err != nil {
		return err
	}
	return s.repo.Update(user)
}

func (s *userService) DeleteUser(ctx context.Context, id string) error {
	return s.repo.Delete(id)
}

func (s *userService) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	users, err := s.repo.GetAll(limit, offset)
	if err != nil {
		return nil, err
	}
	return users, nil
} 
