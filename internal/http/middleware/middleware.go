package middleware

import (
	"fmt"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/auth"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/requestlog"
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
	logger *slog.Logger,
	authEnabled bool,
	publicCfg auth.PublicAuthConfig,
	privateCfg auth.InternalAPIKeyConfig,
	validator auth.PublicAuthValidator,
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
		if publicCfg.Validator == nil {
			return nil, fmt.Errorf("public authentication is enabled but no token validator is available")
		} else {
			publicCfg = withValidationLogging(logger, "Public auth validation rejected", publicCfg)

			rawPublicAuth, err := auth.RequirePublicAuth(publicCfg)
			if err != nil {
				return nil, err
			}
			publicAuth = withAuthLogging(logger, rawPublicAuth)
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

func withValidationLogging(logger *slog.Logger, msg string, cfg auth.PublicAuthConfig) auth.PublicAuthConfig {
	originalOnValidationError := cfg.OnValidationError
	cfg.OnValidationError = func(c fiber.Ctx, err error) error {
		logger.Warn(msg, "err", err, "path", c.Path(), "method", c.Method())
		if originalOnValidationError != nil {
			return originalOnValidationError(c, err)
		}
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	return cfg
}

func withAuthLogging(logger *slog.Logger, handler fiber.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		logger.Debug("Authenticating request", "path", c.Path(), "method", c.Method())
		err := handler(c)
		if err != nil {
			logger.Warn("Authentication rejected", "path", c.Path(), "method", c.Method(), "err", err)
			return err
		}
		if c.Response().StatusCode() == fiber.StatusUnauthorized {
			logger.Warn("Authentication rejected: no credentials or invalid validation", "path", c.Path(), "method", c.Method())
			return nil
		}
		logger.Debug("Authentication succeeded", "path", c.Path(), "method", c.Method())
		return nil
	}
}
