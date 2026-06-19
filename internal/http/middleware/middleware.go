package middleware

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/auth"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/requestlog"
	"github.com/routerarchitects/ow-common-mods/servicerpc/owsec"
)

// RegisterPublicCORS configures CORS policies on the public Fiber application.
func RegisterPublicCORS(app *fiber.App) {
	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-KEY", "X-INTERNAL-NAME"},
	}))
}

// RegisterRequestLog registers the correlation and structured request logger middleware.
func RegisterRequestLog(app *fiber.App, logger *slog.Logger) {
	app.Use(requestlog.RequestLogger(logger))
}

// ServiceAuth manages public and private authentication middleware state.
type ServiceAuth struct {
	PublicAuth  fiber.Handler
	PrivateAuth fiber.Handler
}

// NewServiceAuth creates and configures public and private auth handlers.
func NewServiceAuth(
	authEnabled bool,
	publicCfg auth.PublicAuthConfig,
	privateCfg auth.InternalAPIKeyConfig,
	validator *owsec.SecurityClient,
) (*ServiceAuth, error) {
	// Configure public auth handler (bypassed if AUTH_ENABLED=false)
	var publicAuth fiber.Handler
	if !authEnabled {
		publicAuth = func(c fiber.Ctx) error {
			return c.Next()
		}
	} else {
		if publicCfg.Validator == nil {
			publicCfg.Validator = validator
		}
		var err error
		publicAuth, err = auth.RequirePublicAuth(publicCfg)
		if err != nil {
			return nil, err
		}
	}

	// Configure private auth handler (always enforced for security)
	privateAuth, err := auth.RequireInternalAPIKey(privateCfg)
	if err != nil {
		return nil, err
	}

	return &ServiceAuth{
		PublicAuth:  publicAuth,
		PrivateAuth: privateAuth,
	}, nil
}
