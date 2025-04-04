package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5" // Import for parsing tokens in tests
	"github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	repo "github.com/petarzarkov/go-learning/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require" // Using require to stop tests on critical setup failures
	"gorm.io/gorm"                        // Import gorm for error checking
)

// Helper function to create a user directly in the mock repo for setup
func registerTestUser(t *testing.T, s UserService, email, name, password string) *models.User {
	t.Helper()
	req := &models.CreateUserRequest{
		Email:    email,
		Name:     name,
		Password: password,
	}
	user, err := s.Register(context.Background(), req)
	// Use require here - if setup fails, subsequent steps in the test are likely invalid
	require.NoError(t, err, "Helper function failed to register user")
	require.NotNil(t, user, "Helper function returned nil user")
	require.NotEmpty(t, user.ID, "Helper function resulted in user with empty ID")
	require.NotEmpty(t, user.Password, "User password hash should not be empty after registration")
	require.NotEqual(t, password, user.Password, "User password should be hashed, not plaintext")
	return user
}

// Helper function to parse JWT and check standard claims
func checkTokenClaims(t *testing.T, cfg config.JWTConfig, tokenString string, expectedUserID, expectedEmail string, isRefreshToken bool) {
	t.Helper()
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		require.IsType(t, &jwt.SigningMethodHMAC{}, token.Method, "Token signing method should be HMAC")
		return []byte(cfg.Secret), nil
	})

	require.NoError(t, err, "Failed to parse token")
	require.True(t, token.Valid, "Token is not valid")

	assert.Equal(t, expectedUserID, claims["user_id"], "Token user_id claim mismatch")
	// Email is usually only in the access token, not refresh token
	if !isRefreshToken {
		assert.Equal(t, expectedEmail, claims["email"], "Token email claim mismatch")
	}

	expClaim, ok := claims["exp"].(float64)
	require.True(t, ok, "Token 'exp' claim is not a number")
	expTime := time.Unix(int64(expClaim), 0)
	assert.True(t, expTime.After(time.Now()), "Token expiry time should be in the future")

	var expectedDuration time.Duration
	if isRefreshToken {
		expectedDuration = cfg.RefreshExpiry
	} else {
		expectedDuration = cfg.AccessExpiry
	}
	// Check if expiry is reasonably close to expected duration (allowing few seconds for execution)
	assert.WithinDuration(t, time.Now().Add(expectedDuration), expTime, 5*time.Second, "Token expiry duration is incorrect")
}

func TestUserService_Register(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Secret:        "test-secret-register",
		AccessExpiry:  1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}

	t.Run("success", func(t *testing.T) {
		mockRepo, err := repo.NewMockRepository[models.User]()
		require.NoError(t, err)
		userService := NewUserService(mockRepo, jwtConfig)

		req := &models.CreateUserRequest{
			Email:    "test.success@example.com",
			Name:     "Test Success User",
			Password: "password123",
		}

		user, err := userService.Register(context.Background(), req)
		assert.NoError(t, err)
		require.NotNil(t, user)
		assert.NotEmpty(t, user.ID, "User ID should be generated")
		assert.Equal(t, req.Email, user.Email)
		assert.Equal(t, req.Name, user.Name)
		assert.NotEmpty(t, user.Password, "Password hash should not be empty")
		assert.NotEqual(t, req.Password, user.Password, "Password should be hashed")

		// Verify user is actually in the repo
		retrievedUser, err := mockRepo.GetByID(user.ID)
		assert.NoError(t, err)
		require.NotNil(t, retrievedUser)
		assert.Equal(t, user.Email, retrievedUser.Email) // Check repo content matches returned user
	})

	t.Run("error_user_exists", func(t *testing.T) {
		mockRepo, err := repo.NewMockRepository[models.User]()
		require.NoError(t, err)
		userService := NewUserService(mockRepo, jwtConfig)
		existingEmail := "existing@example.com"

		// Register initial user
		_ = registerTestUser(t, userService, existingEmail, "Existing User", "password123")

		// Attempt to register again with the same email
		req := &models.CreateUserRequest{
			Email:    existingEmail,
			Name:     "Another User",
			Password: "password456",
		}
		user, err := userService.Register(context.Background(), req)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUserExists, "Expected ErrUserExists")
		assert.Nil(t, user)
	})

	// Add tests for password hashing errors or repo create errors if you enhance the mock repo or models
	// t.Run("error_password_hash_fails", ...)
	// t.Run("error_repo_create_fails", ...)
}

func TestUserService_Login(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Secret:        "test-secret-login",
		AccessExpiry:  1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}
	testEmail := "test.login@example.com"
	testPassword := "password123"

	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register a user first
	registeredUser := registerTestUser(t, userService, testEmail, "Login User", testPassword)

	t.Run("success", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    testEmail,
			Password: testPassword,
		}
		tokenResp, err := userService.Login(context.Background(), loginReq)

		assert.NoError(t, err)
		require.NotNil(t, tokenResp)
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)

		// Verify token claims
		checkTokenClaims(t, jwtConfig, tokenResp.AccessToken, registeredUser.ID, registeredUser.Email, false)
		checkTokenClaims(t, jwtConfig, tokenResp.RefreshToken, registeredUser.ID, registeredUser.Email, true)
	})

	t.Run("error_user_not_found", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    "nonexistent@example.com",
			Password: testPassword,
		}
		tokenResp, err := userService.Login(context.Background(), loginReq)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
		assert.Nil(t, tokenResp)
	})

	t.Run("error_incorrect_password", func(t *testing.T) {
		loginReq := &models.LoginRequest{
			Email:    testEmail,
			Password: "wrongpassword",
		}
		tokenResp, err := userService.Login(context.Background(), loginReq)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredentials)
		assert.Nil(t, tokenResp)
	})

	// Add tests for repo get errors or CheckPassword errors if needed/possible
	// t.Run("error_repo_get_fails", ...)
}

func TestUserService_RefreshToken(t *testing.T) {
	jwtConfig := config.JWTConfig{
		Secret:        "test-secret-refresh",
		AccessExpiry:  5 * time.Minute, // Shorter expiry for testing
		RefreshExpiry: 10 * time.Minute,
	}
	testEmail := "test.refresh@example.com"
	testPassword := "password123"

	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register and login a user
	registeredUser := registerTestUser(t, userService, testEmail, "Refresh User", testPassword)
	loginReq := &models.LoginRequest{Email: testEmail, Password: testPassword}
	initialTokenResp, err := userService.Login(context.Background(), loginReq)
	require.NoError(t, err)
	require.NotNil(t, initialTokenResp)

	t.Run("success", func(t *testing.T) {
		ctxWithUser := context.WithValue(context.Background(), middleware.UserIDContextKey, registeredUser.ID)
		refreshReq := &models.RefreshTokenRequest{RefreshToken: initialTokenResp.RefreshToken}

		// Wait for more than 1 second to ensure the timestamp for JWT expiry changes
		time.Sleep(1100 * time.Millisecond)

		newTokenResp, err := userService.RefreshToken(ctxWithUser, refreshReq)

		assert.NoError(t, err)
		require.NotNil(t, newTokenResp)
		assert.NotEmpty(t, newTokenResp.AccessToken)
		assert.NotEmpty(t, newTokenResp.RefreshToken)

		// These assertions should now pass because the 'exp' claim will be different
		assert.NotEqual(t, initialTokenResp.AccessToken, newTokenResp.AccessToken, "New access token should be different")
		// Note on refresh token rotation: See below
		assert.NotEqual(t, initialTokenResp.RefreshToken, newTokenResp.RefreshToken, "New refresh token should be different (rotation)")

		// Verify claims of the *new* tokens
		checkTokenClaims(t, jwtConfig, newTokenResp.AccessToken, registeredUser.ID, registeredUser.Email, false)
		checkTokenClaims(t, jwtConfig, newTokenResp.RefreshToken, registeredUser.ID, registeredUser.Email, true)
	})

	t.Run("error_no_user_id_in_context", func(t *testing.T) {
		refreshReq := &models.RefreshTokenRequest{RefreshToken: initialTokenResp.RefreshToken}
		newTokenResp, err := userService.RefreshToken(context.Background(), refreshReq) // No UserID in context

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unauthorized", "Expected unauthorized error") // Or specific error type if defined
		assert.Nil(t, newTokenResp)
	})

	t.Run("error_invalid_refresh_token_signature", func(t *testing.T) {
		ctxWithUser := context.WithValue(context.Background(), middleware.UserIDContextKey, registeredUser.ID)
		// Generate a token with a different secret
		invalidToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": registeredUser.ID,
			"exp":     time.Now().Add(jwtConfig.RefreshExpiry).Unix(),
		})
		invalidTokenString, _ := invalidToken.SignedString([]byte("wrong-secret"))

		refreshReq := &models.RefreshTokenRequest{RefreshToken: invalidTokenString}
		newTokenResp, err := userService.RefreshToken(ctxWithUser, refreshReq)

		assert.Error(t, err)
		// Error might be "signature is invalid" or similar depending on jwt library version
		assert.Contains(t, err.Error(), "invalid", "Expected signature validation error")
		assert.Nil(t, newTokenResp)
	})

	t.Run("error_expired_refresh_token", func(t *testing.T) {
		ctxWithUser := context.WithValue(context.Background(), middleware.UserIDContextKey, registeredUser.ID)
		// Generate an expired token
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": registeredUser.ID,
			"exp":     time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		})
		expiredTokenString, _ := expiredToken.SignedString([]byte(jwtConfig.Secret))

		refreshReq := &models.RefreshTokenRequest{RefreshToken: expiredTokenString}
		newTokenResp, err := userService.RefreshToken(ctxWithUser, refreshReq)

		assert.Error(t, err)
		// Error might be "token is expired" or similar
		assert.Contains(t, err.Error(), "token is expired", "Expected token expired error")
		assert.Nil(t, newTokenResp)
	})

	t.Run("error_user_id_mismatch", func(t *testing.T) {
		// Create a second user
		otherUser := registerTestUser(t, userService, "other@example.com", "Other User", "password456")

		// Use context for otherUser, but token for registeredUser
		ctxWithOtherUser := context.WithValue(context.Background(), middleware.UserIDContextKey, otherUser.ID)
		refreshReq := &models.RefreshTokenRequest{RefreshToken: initialTokenResp.RefreshToken} // Token from registeredUser

		newTokenResp, err := userService.RefreshToken(ctxWithOtherUser, refreshReq)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Refresh token does not belong to you", "Expected user ID mismatch error")
		assert.Nil(t, newTokenResp)
	})

	t.Run("error_user_not_found_in_db", func(t *testing.T) {
		// Create user and token
		tempUser := registerTestUser(t, userService, "temp.delete@example.com", "Temp User", "password")
		tempLoginReq := &models.LoginRequest{Email: tempUser.Email, Password: "password"}
		tempTokenResp, err := userService.Login(context.Background(), tempLoginReq)
		require.NoError(t, err)

		// Delete the user from the repo
		err = mockRepo.Delete(tempUser.ID)
		require.NoError(t, err)

		// Attempt refresh
		ctxWithUser := context.WithValue(context.Background(), middleware.UserIDContextKey, tempUser.ID)
		refreshReq := &models.RefreshTokenRequest{RefreshToken: tempTokenResp.RefreshToken}
		newTokenResp, err := userService.RefreshToken(ctxWithUser, refreshReq)

		assert.Error(t, err)
		// The service maps RecordNotFound to ErrInvalidCredentials in this path
		assert.ErrorIs(t, err, ErrInvalidCredentials, "Expected invalid credentials on user not found")
		assert.Nil(t, newTokenResp)
	})
}

func TestUserService_GetUser(t *testing.T) {
	jwtConfig := config.JWTConfig{Secret: "test-secret-get"}
	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register a user
	registeredUser := registerTestUser(t, userService, "test.get@example.com", "Get User", "password123")

	t.Run("success", func(t *testing.T) {
		retrievedUser, err := userService.GetUser(context.Background(), registeredUser.ID)

		assert.NoError(t, err)
		require.NotNil(t, retrievedUser)
		assert.Equal(t, registeredUser.ID, retrievedUser.ID)
		assert.Equal(t, registeredUser.Email, retrievedUser.Email)
		assert.Equal(t, registeredUser.Name, retrievedUser.Name)
		// Password hash should still be there but we don't usually return/compare it in Get requests
		assert.NotEmpty(t, retrievedUser.Password)
	})

	t.Run("error_not_found", func(t *testing.T) {
		nonExistentID := "non-existent-id"
		retrievedUser, err := userService.GetUser(context.Background(), nonExistentID)

		assert.Error(t, err)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "Expected RecordNotFound error")
		assert.Nil(t, retrievedUser)
	})
}

func TestUserService_UpdateUser(t *testing.T) {
	jwtConfig := config.JWTConfig{Secret: "test-secret-update"}
	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register a user
	registeredUser := registerTestUser(t, userService, "test.update@example.com", "Update User", "password123")
	originalPasswordHash := registeredUser.Password // Store original hash for comparison

	t.Run("success_update_name", func(t *testing.T) {
		updatePayload := &models.User{
			ID:       registeredUser.ID,    // ID must match
			Name:     "Updated Name",       // Change name
			Email:    registeredUser.Email, // Keep email same
			Password: "password123",        // Provide password again (service hashes it) - Or handle password update separately
			// If password shouldn't be updated here, the model might need adjustment
			// or the service logic should only hash if a *new* password is provided.
			// Assuming current logic re-hashes whatever is in user.Password field.
		}

		err := userService.UpdateUser(context.Background(), registeredUser.ID, updatePayload)
		assert.NoError(t, err)

		// Verify update in repository
		updatedUser, err := mockRepo.GetByID(registeredUser.ID)
		assert.NoError(t, err)
		require.NotNil(t, updatedUser)
		assert.Equal(t, "Updated Name", updatedUser.Name)
		assert.Equal(t, registeredUser.Email, updatedUser.Email) // Email shouldn't change here
		// Check if password hash changed (it should have if service re-hashed "password123")
		assert.NotEqual(t, originalPasswordHash, updatedUser.Password, "Password hash should change on update")
	})

	t.Run("success_update_password", func(t *testing.T) {
		newPassword := "newSecurePassword"
		updatePayload := &models.User{
			ID:       registeredUser.ID,
			Name:     "Updated Name", // Name is already updated from previous sub-test state
			Email:    registeredUser.Email,
			Password: newPassword, // Set new password
		}
		currentHashBeforeUpdate := ""
		currentUser, err := mockRepo.GetByID(registeredUser.ID)
		if err == nil {
			currentHashBeforeUpdate = currentUser.Password
		}

		err = userService.UpdateUser(context.Background(), registeredUser.ID, updatePayload)
		assert.NoError(t, err)

		// Verify update
		updatedUser, err := mockRepo.GetByID(registeredUser.ID)
		assert.NoError(t, err)
		require.NotNil(t, updatedUser)
		assert.NotEqual(t, currentHashBeforeUpdate, updatedUser.Password, "Password hash should change")

		// Verify old password doesn't work, new one does (requires CheckPassword)
		err = updatedUser.CheckPassword("password123") // Check original password
		assert.Error(t, err, "Original password should not work after update")

		err = updatedUser.CheckPassword(newPassword) // Check new password
		assert.NoError(t, err, "New password should work after update")
	})

	t.Run("error_not_found", func(t *testing.T) {
		nonExistentID := "non-existent-id"
		updatePayload := &models.User{
			ID:   nonExistentID,
			Name: "Doesn't Matter",
		}
		err := userService.UpdateUser(context.Background(), nonExistentID, updatePayload)

		assert.Error(t, err)
		// Update calls repo.Update directly, which returns RecordNotFound
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

func TestUserService_DeleteUser(t *testing.T) {
	jwtConfig := config.JWTConfig{Secret: "test-secret-delete"}
	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register a user
	registeredUser := registerTestUser(t, userService, "test.delete@example.com", "Delete User", "password123")

	t.Run("success", func(t *testing.T) {
		err := userService.DeleteUser(context.Background(), registeredUser.ID)
		assert.NoError(t, err)

		// Verify user is gone from repository
		_, err = mockRepo.GetByID(registeredUser.ID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "Expected RecordNotFound after delete")
	})

	t.Run("error_not_found", func(t *testing.T) {
		nonExistentID := "non-existent-id"
		err := userService.DeleteUser(context.Background(), nonExistentID)

		assert.Error(t, err)
		// Delete calls repo.Delete directly, which returns RecordNotFound
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

func TestUserService_ListUsers(t *testing.T) {
	jwtConfig := config.JWTConfig{Secret: "test-secret-list"}
	mockRepo, err := repo.NewMockRepository[models.User]()
	require.NoError(t, err)
	userService := NewUserService(mockRepo, jwtConfig)

	// Setup: Register multiple users
	user1 := registerTestUser(t, userService, "list1@example.com", "List User 1", "pw1")
	user2 := registerTestUser(t, userService, "list2@example.com", "List User 2", "pw2")
	user3 := registerTestUser(t, userService, "list3@example.com", "List User 3", "pw3")
	// Ensure IDs are different for reliable fetching later, mock repo handles this
	require.NotEqual(t, user1.ID, user2.ID)
	require.NotEqual(t, user2.ID, user3.ID)

	t.Run("success_get_all", func(t *testing.T) {
		users, err := userService.ListUsers(context.Background(), 0, 0) // Limit 0 means no limit usually
		assert.NoError(t, err)
		assert.Len(t, users, 3, "Should retrieve all 3 users")
		// Optional: Check if expected users are present (IDs or Emails)
		foundEmails := make(map[string]bool)
		for _, u := range users {
			foundEmails[u.Email] = true
		}
		assert.True(t, foundEmails[user1.Email])
		assert.True(t, foundEmails[user2.Email])
		assert.True(t, foundEmails[user3.Email])

	})

	t.Run("success_limit", func(t *testing.T) {
		users, err := userService.ListUsers(context.Background(), 2, 0) // Limit 2, Offset 0
		assert.NoError(t, err)
		assert.Len(t, users, 2, "Should retrieve only 2 users due to limit")
	})

	t.Run("success_offset", func(t *testing.T) {
		users, err := userService.ListUsers(context.Background(), 2, 1) // Limit 2, Offset 1
		assert.NoError(t, err)
		assert.Len(t, users, 2, "Should retrieve 2 users starting from offset 1")
		// More specific check depends on the mock repo's ordering (which is likely insertion order or map hash order)
		// If order matters, sort IDs in test setup and verify returned IDs match expected slice.
	})

	t.Run("success_limit_and_offset_exact", func(t *testing.T) {
		users, err := userService.ListUsers(context.Background(), 1, 1) // Limit 1, Offset 1
		assert.NoError(t, err)
		assert.Len(t, users, 1, "Should retrieve 1 user at offset 1")
	})

	t.Run("success_offset_too_high", func(t *testing.T) {
		users, err := userService.ListUsers(context.Background(), 5, 3) // Limit 5, Offset 3 (past the end)
		assert.NoError(t, err)
		assert.Empty(t, users, "Should return empty slice when offset is past the end")
		assert.Len(t, users, 0) // More explicit check for empty
	})

	t.Run("success_empty_repo", func(t *testing.T) {
		emptyRepo, err := repo.NewMockRepository[models.User]()
		require.NoError(t, err)
		emptyUserService := NewUserService(emptyRepo, jwtConfig)
		users, err := emptyUserService.ListUsers(context.Background(), 10, 0)
		assert.NoError(t, err)
		assert.Empty(t, users)
		assert.Len(t, users, 0)
	})
}
