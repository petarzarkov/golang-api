package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/petarzarkov/go-learning/api/handlers"
	customMiddleware "github.com/petarzarkov/go-learning/api/middleware"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/internal/repository"
	"github.com/petarzarkov/go-learning/internal/service"
	"github.com/petarzarkov/go-learning/pkg/database"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi31"
	"github.com/swaggest/rest/nethttp"
	"github.com/swaggest/rest/web"
	swgui "github.com/swaggest/swgui/v5emb"
	"github.com/swaggest/usecase"
	"github.com/swaggest/usecase/status"
)


func main() {
	s := web.NewService(openapi31.NewReflector())
	s.OpenAPISchema().SetTitle("Go API")
	s.OpenAPISchema().SetDescription("This is an example API using swaggest/rest.")
	s.OpenAPISchema().SetVersion("v1.0.0")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration %v", err)
	}

	// Initialize database
	db, err := database.ConnectDatabase(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect database: %v", err)
	}

	// Migrate the schema
	db.AutoMigrate(&models.User{})

    // Create a repository for User
    userRepo := repository.NewGormRepository[models.User](db)
	// Initialize services
	userService := service.NewUserService(userRepo, cfg.JWT.Secret)
	userService.Register(context.Background(), &models.CreateUserRequest{Email: "test@test.com", Password: "password", Name: "Test User"})

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)

	s.Use(
		middleware.RequestID,
		middleware.Logger,
		middleware.Recoverer,
		middleware.RealIP,
		middleware.Timeout(60 * time.Second),
	)

	s.Route("/api/v1/users", func(r chi.Router) {
		r.Use(
			nethttp.OpenAPIAnnotationsMiddleware(s.OpenAPICollector, func(oc openapi.OperationContext) error {
				oc.SetTags(append(oc.Tags(), "/api/v1")...)
				return nil
			}),
		)

		// Public routes
		r.Group(func(r chi.Router) {
			r.Method(http.MethodPost, "/register", nethttp.NewHandler(userHandler.Register()))
			r.Method(http.MethodPost, "/login", nethttp.NewHandler(userHandler.Login()))
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(
				customMiddleware.Auth(customMiddleware.AuthConfig{
					JWTSecret: cfg.JWT.Secret,
				}),
			)

			r.Method(http.MethodGet, "/{id}", nethttp.NewHandler(userHandler.GetUser()))
			r.Method(http.MethodPut, "/{id}", nethttp.NewHandler(userHandler.UpdateUser()))
			r.Method(http.MethodDelete, "/{id}", nethttp.NewHandler(userHandler.DeleteUser()))
			r.Method(http.MethodGet, "/", nethttp.NewHandler(userHandler.ListUsers()))
		})

	})
	
	s.Wrap(
		nethttp.OpenAPIAnnotationsMiddleware(s.OpenAPICollector, func(oc openapi.OperationContext) error {
			oc.SetTags(append(oc.Tags(), "/service")...)
			return nil
		}),
	)

	s.Get("/service/health", func() usecase.Interactor {
		u := usecase.NewInteractor(func(ctx context.Context, input, output *struct {
			Status string `json:"status"`
		}) error {
			output.Status = "ok"
			var result int
			db.Raw("SELECT 1 + 1").Scan(&result)
			if result != 2 {
				return status.Wrap(errors.New("DB error"), status.Internal)
			}
			return nil
		})
		u.SetTitle("Service health")
		u.SetDescription("Checks service health")
		return u
	}())


	// Serve Swagger UI
	s.Docs("/api", swgui.New)

	// Start the server
	log.Println(fmt.Sprintf("Starting server at http://localhost:%s/api", cfg.Server.Port))
	
	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Server.Port), s); err != nil {
		log.Fatal(err)
	}
}
