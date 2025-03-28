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
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/rest/nethttp"
	oapi "github.com/swaggest/rest/openapi"
	"gorm.io/gorm"
)

func UsersRouter(collector *oapi.Collector, db *gorm.DB, jwtConfig config.JWTConfig) func(r chi.Router) {
	// Initialize services
	userService := service.NewUserService(repository.NewGormRepository[models.User](db), jwtConfig)
	// Create a test user to have something to work with
	userService.Register(context.Background(), &models.CreateUserRequest{Email: "test@test.com", Password: "password", Name: "Test User"})

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)
	return func(r chi.Router) {
		r.Use(
			nethttp.OpenAPIAnnotationsMiddleware(collector, func(oc openapi.OperationContext) error {
				oc.SetTags(append(oc.Tags(), "/api/v1")...)
				return nil
			}),
		)

		// Public routes
		r.Group(func(r chi.Router) {
			r.Method(http.MethodPost, "/register", nethttp.NewHandler(userHandler.Register()))
			r.Method(http.MethodPost, "/login", nethttp.NewHandler(userHandler.Login()))
			r.With(
				customMiddleware.Auth(customMiddleware.AuthConfig{
					JWTConfig:               jwtConfig,
					PassthroughExpiredToken: true,
				}),
			).Method(http.MethodPost, "/refreshToken", nethttp.NewHandler(userHandler.RefreshToken()))
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(
				customMiddleware.Auth(customMiddleware.AuthConfig{
					JWTConfig: jwtConfig,
				}),
			)

			r.Method(http.MethodGet, "/{id}", nethttp.NewHandler(userHandler.GetUser()))
			r.Method(http.MethodPut, "/{id}", nethttp.NewHandler(userHandler.UpdateUser()))
			r.Method(http.MethodDelete, "/{id}", nethttp.NewHandler(userHandler.DeleteUser()))
			r.Method(http.MethodGet, "/", nethttp.NewHandler(userHandler.ListUsers()))
		})
	}
}
