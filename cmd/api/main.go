package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/petarzarkov/go-learning/api/routers"
	"github.com/petarzarkov/go-learning/config"
	"github.com/petarzarkov/go-learning/internal/models"
	"github.com/petarzarkov/go-learning/pkg/database"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi31"
	"github.com/swaggest/rest/nethttp"
	"github.com/swaggest/rest/web"
	swg "github.com/swaggest/swgui"
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
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Migrate the schema
	db.AutoMigrate(&models.User{})

	s.Wrap(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Logger,
		middleware.Recoverer,
		nethttp.HTTPBearerSecurityMiddleware(s.OpenAPICollector, "bearerAuth", "JWT token", "JWT"),
		middleware.Timeout(60*time.Second),
	)

	s.Route("/api/v1", func(r chi.Router) {
		r.Use(
			nethttp.OpenAPIAnnotationsMiddleware(s.OpenAPICollector, func(oc openapi.OperationContext) error {
				oc.SetTags(append(oc.Tags(), "/api/v1")...)
				return nil
			}),
		)
		r.Group(routers.UsersRouter(db, cfg.JWT))
	})

	s.Route("/service", func(r chi.Router) {
		r.Use(
			nethttp.OpenAPIAnnotationsMiddleware(s.OpenAPICollector, func(oc openapi.OperationContext) error {
				oc.SetTags(append(oc.Tags(), "/service")...)
				return nil
			}),
		)
		r.Method(http.MethodGet, "/health", nethttp.NewHandler(func() usecase.Interactor {
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
		}()))
	})

	// Serve Swagger UI
	s.Docs("/api", swgui.NewWithConfig(swg.Config{
		ShowTopBar: false,
		SettingsUI: map[string]string{
			"persistAuthorization":   "true",
			"displayRequestDuration": "true",
			"tagsSorter":             "\"alpha\"",
			// Auto auth on login in Swagger UI
			"responseInterceptor": `function (response) {
				if (response.ok && response?.url?.includes("users/login")) {
					window.ui.preauthorizeApiKey("bearerAuth", response.body.access_token);
				}
				
				return response;
			}`,
		},
	}))

	// Handle unhandled routes, eventually serve static content here
	s.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		response := map[string]string{
			"message": "No handler for route " + r.URL.String(),
		}

		json.NewEncoder(w).Encode(response)
	}))

	// Start the server
	log.Println(fmt.Sprintf("Starting server at http://localhost:%s/api", cfg.Server.Port))

	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Server.Port), s); err != nil {
		log.Fatal(err)
	}
}
