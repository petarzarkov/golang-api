package service

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/internal/repository"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
)

type UserService interface {
	Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.TokenResponse, error)
	RefreshToken(ctx context.Context, req *models.RefreshTokenRequest) (*models.TokenResponse, error)
	GetUser(ctx context.Context, id string) (*models.User, error)
	UpdateUser(ctx context.Context, id string, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error)
}

type userService struct {
	repo      repository.Repository[models.User]
	JWTConfig config.JWTConfig
}

func NewUserService(repo repository.Repository[models.User], JWTConfig config.JWTConfig) UserService {
	return &userService{
		repo:      repo,
		JWTConfig: JWTConfig,
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

	token, err := GenerateJWT(s.JWTConfig, user)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *userService) RefreshToken(ctx context.Context, req *models.RefreshTokenRequest) (*models.TokenResponse, error) {
	accessTokenUserId, ok := middleware.GetUserID(ctx)
	if !ok {
		return nil, errors.New("Unauthorized")
	}

	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Invalid signing method")
		}
		return []byte(s.JWTConfig.Secret), nil
	})

	if err != nil {
		return nil, errors.New(err.Error())
	}

	if !token.Valid {
		return nil, errors.New("Invalid refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Invalid refresh token claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("Invalid user ID in refresh token")
	}

	// Verify Refresh Token Belongs to User
	if accessTokenUserId != userID {
		return nil, errors.New("Refresh token does not belong to you")
	}

	// Get the user from the database
	user, err := s.repo.GetByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, err
	}

	newToken, err := GenerateJWT(s.JWTConfig, user)
	if err != nil {
		return nil, err
	}

	return newToken, nil
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

func GenerateJWT(JWTConfig config.JWTConfig, user *models.User) (*models.TokenResponse, error) {
	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(JWTConfig.AccessExpiry).Unix(),
	})

	tokenString, err := token.SignedString([]byte(JWTConfig.Secret))
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(JWTConfig.RefreshExpiry).Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(JWTConfig.Secret))
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
