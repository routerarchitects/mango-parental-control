package http

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/mango-parental-control/internal/db"
	"github.com/routerarchitects/mango-parental-control/internal/http/middleware"
	"github.com/routerarchitects/mango-parental-control/internal/http/routes"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/auth"
	subsystemroutes "github.com/routerarchitects/ow-common-mods/fiber/system-routes"
	"github.com/routerarchitects/ow-common-mods/servicerpc/owsec"
)

type Dependencies struct {
	DB                *db.Database
	ServerLogger      *slog.Logger
	ServerConfig      config.ServerConfig
	SubsystemConfig   subsystemroutes.Config
	PublicAuthConfig  auth.PublicAuthConfig
	PrivateAuthConfig auth.InternalAPIKeyConfig
	TokenValidator    *owsec.SecurityClient
	AuthEnabled       bool
}

type Module struct {
	server     *Server
	publicApp  *fiber.App
	privateApp *fiber.App
}

// NewModule initializes the HTTP apps, CORS, loggers, auth middlewares, and routes.
func NewModule(deps Dependencies) (*Module, error) {
	authMiddleware, err := middleware.NewServiceAuth(
		deps.AuthEnabled,
		deps.PublicAuthConfig,
		deps.PrivateAuthConfig,
		deps.TokenValidator,
	)
	if err != nil {
		return nil, err
	}

	appConfig := fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	publicApp := fiber.New(appConfig)
	privateApp := fiber.New(appConfig)

	// Register CORS policy for external UI calls
	middleware.RegisterPublicCORS(publicApp)

	// Register trace loggers
	middleware.RegisterRequestLog(publicApp, deps.ServerLogger)
	middleware.RegisterRequestLog(privateApp, deps.ServerLogger)

	// Configure public routes
	routes.RegisterPublic(publicApp, routes.Deps{
		DB:          deps.DB,
		AuthHandler: authMiddleware.PublicAuth,
		Subsystem:   deps.SubsystemConfig,
	})

	// Configure private routes
	routes.RegisterPrivate(privateApp, routes.Deps{
		DB:          deps.DB,
		AuthHandler: authMiddleware.PrivateAuth,
		Subsystem:   deps.SubsystemConfig,
	})

	return &Module{
		server:     NewServer(deps.ServerConfig, deps.ServerLogger),
		publicApp:  publicApp,
		privateApp: privateApp,
	}, nil
}

// Start launches the public and private HTTP listener servers in the background.
func (m *Module) Start(ctx context.Context) (<-chan error, error) {
	return m.server.Start(ctx, m.publicApp, m.privateApp)
}

// Shutdown gracefully stops both Fiber listeners.
func (m *Module) Shutdown() error {
	return errors.Join(m.publicApp.Shutdown(), m.privateApp.Shutdown())
}
