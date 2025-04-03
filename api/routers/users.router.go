package routers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/petarzarkov/go-learning/api/handlers"
	customMiddleware "github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/internal/repository"
	"github.com/petarzarkov/go-learning/internal/service"
	"github.com/swaggest/rest/nethttp"
	"gorm.io/gorm"
)

func UsersRouter(db *gorm.DB, jwtConfig config.JWTConfig) func(r chi.Router) {
	// Initialize services
	userService := service.NewUserService(repository.NewGormRepository[models.User](db), jwtConfig)
	// Create a test user to have something to work with
	userService.Register(context.Background(), &models.CreateUserRequest{Email: "test@test.com", Password: "password", Name: "Test User"})

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)
	return func(r chi.Router) {
		r.Route("/users", func(usersRouter chi.Router) {
			// Public routes
			usersRouter.Group(func(group chi.Router) {
				group.Method(http.MethodPost, "/register", nethttp.NewHandler(userHandler.Register()))
				group.Method(http.MethodPost, "/login", nethttp.NewHandler(userHandler.Login()))
				group.With(
					customMiddleware.Auth(customMiddleware.AuthConfig{
						JWTConfig:               jwtConfig,
						PassthroughExpiredToken: true,
					}),
				).Method(http.MethodPost, "/refreshToken", nethttp.NewHandler(userHandler.RefreshToken()))
			})

			// Protected routes
			usersRouter.Group(func(group chi.Router) {
				group.Use(
					customMiddleware.Auth(customMiddleware.AuthConfig{
						JWTConfig: jwtConfig,
					}),
				)

				group.Method(http.MethodGet, "/{id}", nethttp.NewHandler(userHandler.GetUser()))
				group.Method(http.MethodPut, "/{id}", nethttp.NewHandler(userHandler.UpdateUser()))
				group.Method(http.MethodDelete, "/{id}", nethttp.NewHandler(userHandler.DeleteUser()))
				group.Method(http.MethodGet, "/", nethttp.NewHandler(userHandler.ListUsers()))
			})
		})

	}
}
