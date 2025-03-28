package handlers

import (
	"context"
	"errors"

	"github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/internal/service"
	"github.com/swaggest/usecase"
	"github.com/swaggest/usecase/status"
)

type UserHandler struct {
	userService service.UserService
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

func (h *UserHandler) Register() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, req models.CreateUserRequest, output *models.User) error {
		user, err := h.userService.Register(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrUserExists) {
				return status.Wrap(errors.New("User already exists"), status.AlreadyExists)
			}

			return status.Wrap(err, status.Internal)
		}
		*output = *user
		return nil
	})
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.AlreadyExists)
	u.SetTitle("Register a new user")
	u.SetDescription("Register a new user with the given email and password")
	return u
}

func (h *UserHandler) Login() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, req models.LoginRequest, output *models.TokenResponse) error {
		token, err := h.userService.Login(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				return status.Wrap(errors.New("Invalid credentials"), status.PermissionDenied)
			}

			return status.Wrap(err, status.Internal)
		}
		*output = *token
		return nil
	})
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.PermissionDenied)
	u.SetTitle("Login to the system")
	u.SetDescription("Login to the system with the given email and password")
	return u
}

func (h *UserHandler) RefreshToken() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, req models.RefreshTokenRequest, output *models.TokenResponse) error {
		token, err := h.userService.RefreshToken(ctx, &req)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				return status.Wrap(errors.New("Invalid refresh token"), status.PermissionDenied)
			}

			return status.Wrap(err, status.Internal)
		}

		*output = *token

		return nil
	})
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.PermissionDenied, status.NotFound)
	u.SetTitle("Refresh access token")
	u.SetDescription("Refresh access token using a refresh token")
	return u
}

func (h *UserHandler) GetUser() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, query models.UserIdPath, output *models.User) error {
		user, err := h.userService.GetUser(ctx, query.ID)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				return status.Wrap(errors.New("User not found"), status.NotFound)
			}
			return status.Wrap(err, status.Internal)
		}

		*output = *user
		return nil
	})
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.NotFound)
	u.SetTitle("Get a user by ID")
	u.SetDescription("Get a user by ID")
	return u
}

func (h *UserHandler) ListUsers() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, query models.ListUsersQuery, output *[]models.User) error {
		usersPtr, err := h.userService.ListUsers(ctx, query.Limit, query.Offset)
		if err != nil {
			return status.Wrap(err, status.Internal)
		}

		users := make([]models.User, len(usersPtr))
		for i, userPtr := range usersPtr {
			users[i] = *userPtr
		}

		*output = users
		return nil
	})
	u.SetExpectedErrors(status.Internal, status.InvalidArgument)
	u.SetTitle("List users")
	u.SetDescription("List users with the given limit and offset")
	return u
}

func (h *UserHandler) UpdateUser() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, input models.UpdateUserInput, output *models.User) error {
		// Ensure the user can only update their own profile
		userID, ok := middleware.GetUserID(ctx)
		if !ok || userID != input.ID {
			return status.Wrap(errors.New("Unauthorized"), status.PermissionDenied)
		}

		existingUser, err := h.userService.GetUser(ctx, input.ID)
		if err != nil {
			return status.Wrap(err, status.Internal)
		}

		updateUser := &models.User{
			ID:       existingUser.ID,
			Email:    existingUser.Email,
			Password: existingUser.Password,
			Name:     existingUser.Name,
		}
		if input.Email != "" {
			updateUser.Email = input.Email
		}
		if input.Password != "" {
			updateUser.Password = input.Password
		}
		if input.Name != "" {
			updateUser.Name = input.Name
		}

		err = h.userService.UpdateUser(ctx, existingUser.ID, updateUser)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				return status.Wrap(errors.New("User not found"), status.NotFound)
			}
			return status.Wrap(err, status.Internal)
		}

		*output = *updateUser
		return nil
	})
	u.SetTitle("Update a user")
	u.SetDescription("Update a user with the given ID")
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.PermissionDenied, status.NotFound)
	return u
}

func (h *UserHandler) DeleteUser() usecase.Interactor {
	u := usecase.NewInteractor(func(ctx context.Context, query models.UserIdPath, output *models.User) error {
		// Ensure the user can only delete their own profile
		userID, ok := middleware.GetUserID(ctx)
		if !ok || userID != query.ID {
			return status.Wrap(errors.New("Unauthorized"), status.PermissionDenied)
		}

		err := h.userService.DeleteUser(ctx, query.ID)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				return status.Wrap(errors.New("User not found"), status.NotFound)
			}

			return status.Wrap(err, status.Internal)
		}

		return nil
	})
	u.SetTitle("Delete a user")
	u.SetDescription("Delete a user with the given ID")
	u.SetExpectedErrors(status.Internal, status.InvalidArgument, status.PermissionDenied, status.NotFound)
	return u
}
