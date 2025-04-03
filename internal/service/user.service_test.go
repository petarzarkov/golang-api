package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// MockRepository is a mock implementation of the repository
type MockRepository struct {
	users map[string]*models.User
	idCounter int
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		users: make(map[string]*models.User),
		idCounter: 0, // <--- Initialize counter
	}
}

func (m *MockRepository) Create(user *models.User) error {
    // If the user doesn't have an ID, generate a simple unique one for the mock
    if user.ID == "" { // Assuming ID is a string and "" is its zero value
        m.idCounter++
        user.ID = fmt.Sprintf("mock-id-%d", m.idCounter)
    }
    // Optional: Check if the ID (generated or pre-existing) already exists
    if _, exists := m.users[user.ID]; exists {
         return fmt.Errorf("mock repo: user with ID %s already exists", user.ID)
    }
    m.users[user.ID] = user
    return nil
}

func (m *MockRepository) GetByID(id string) (*models.User, error) {
	if user, exists := m.users[id]; exists {
		return user, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (m *MockRepository) GetAll(limit, offset int) ([]*models.User, error) {
	var users []*models.User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MockRepository) Update(user *models.User) error {
	if _, exists := m.users[user.ID]; exists {
		m.users[user.ID] = user
		return nil
	}
	return gorm.ErrRecordNotFound
}

func (m *MockRepository) Delete(id string) error {
	if _, exists := m.users[id]; exists {
		delete(m.users, id)
		return nil
	}
	return gorm.ErrRecordNotFound
}

func (m *MockRepository) Get(filter map[string]any) (*models.User, error) {
	email, ok := filter["email"].(string)
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

func (m *MockRepository) Exists(filter map[string]any) (bool, error) {
	_, err := m.Get(filter)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}

func TestUserService_Register(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
		AccessExpiry: 1*time.Hour,
		RefreshExpiry: 1*time.Hour,
	})

	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}

	user, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.Equal(t, req.Name, user.Name)
}

func TestUserService_Login(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
	})

	// Register a user first
	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}
	_, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)

	// Attempt to login
	loginReq := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	token, err := userService.Login(context.Background(), loginReq)
	assert.NoError(t, err)
	assert.NotNil(t, token)
}

func TestUserService_RefreshToken(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
		AccessExpiry: 1*time.Hour,
		RefreshExpiry: 1*time.Hour,
	})

	// Register a user first
	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}
	user, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)

	// Login to get a token
	loginReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}
	token, err := userService.Login(context.Background(), loginReq)
	assert.NoError(t, err)

	ctxWithUser := context.WithValue(context.Background(), middleware.UserIDContextKey, user.ID)
	// Attempt to refresh the token
	refreshReq := &models.RefreshTokenRequest{
		RefreshToken: token.RefreshToken,
	}
	newToken, err := userService.RefreshToken(ctxWithUser, refreshReq)
	assert.NoError(t, err)
	assert.NotNil(t, newToken)
}

func TestUserService_GetUser(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
	})

	// Register a user first
	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}
	user, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)

	// Attempt to get the user
	retrievedUser, err := userService.GetUser(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, user.Email, retrievedUser.Email)
	assert.Equal(t, user.Name, retrievedUser.Name)
}

func TestUserService_UpdateUser(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
	})

	// Register a user first
	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}
	user, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)

	// Update the user
	user.Name = "Updated Name"
	err = userService.UpdateUser(context.Background(), user.ID, user)
	assert.NoError(t, err)

	// Retrieve the updated user
	updatedUser, err := userService.GetUser(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updatedUser.Name)
}

func TestUserService_DeleteUser(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
	})

	// Register a user first
	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "password123",
	}
	user, err := userService.Register(context.Background(), req)
	assert.NoError(t, err)

	// Delete the user
	err = userService.DeleteUser(context.Background(), user.ID)
	assert.NoError(t, err)

	// Attempt to retrieve the deleted user
	_, err = userService.GetUser(context.Background(), user.ID)
	assert.Error(t, err)
}

func TestUserService_ListUsers(t *testing.T) {
	mockRepo := NewMockRepository()
	userService := NewUserService(mockRepo, config.JWTConfig{
		Secret: "test-secret",
	})

	// Register multiple users
	req1 := &models.CreateUserRequest{
		Email:    "test1@example.com",
		Name:     "Test User 1",
		Password: "password123",
	}
	req2 := &models.CreateUserRequest{
		Email:    "test2@example.com",
		Name:     "Test User 2",
		Password: "password123",
	}
	_, err := userService.Register(context.Background(), req1)
	assert.NoError(t, err)
	_, err = userService.Register(context.Background(), req2)
	assert.NoError(t, err)

	// List users
	users, err := userService.ListUsers(context.Background(), 10, 0)
	assert.NoError(t, err)
	assert.Len(t, users, 2)
}
