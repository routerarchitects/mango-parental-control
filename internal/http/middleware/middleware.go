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
		rawPublicAuth, err := auth.RequirePublicAuth(publicCfg)
		if err != nil {
			return nil, err
		}
		// Wrap the public auth handler to capture and log any authentication errors.
		publicAuth = func(c fiber.Ctx) error {
			slog.Info("Authenticating request", "path", c.Path(), "method", c.Method())
			err := rawPublicAuth(c)
			if err != nil {
				slog.Error("Authentication failed", "path", c.Path(), "method", c.Method(), "error", err)
				return err
			}
			slog.Info("Authentication succeeded", "path", c.Path(), "method", c.Method())
			return nil
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

// RegisterPublicDebugLogger adds a highly detailed logger to trace public request and response details.
func RegisterPublicDebugLogger(app *fiber.App) {
	app.Use(func(c fiber.Ctx) error {
		path := c.Path()
		method := c.Method()

		// Retrieve request body
		reqBody := string(c.Body())
		if len(reqBody) > 1000 {
			reqBody = reqBody[:1000] + "... (truncated)"
		}

		slog.Info("DEBUG PUBLIC REQUEST",
			"method", method,
			"path", path,
			"origin", c.Get("Origin"),
			"referrer", c.Get("Referer"),
			"auth", c.Get("Authorization"),
			"content_type", c.Get("Content-Type"),
			"body", reqBody,
		)

		err := c.Next()

		// Retrieve response body and status
		status := c.Response().StatusCode()
		respBody := string(c.Response().Body())
		if len(respBody) > 1000 {
			respBody = respBody[:1000] + "... (truncated)"
		}

		slog.Info("DEBUG PUBLIC RESPONSE",
			"method", method,
			"path", path,
			"status", status,
			"err", err,
			"access_control_allow_origin", string(c.Response().Header.Peek("Access-Control-Allow-Origin")),
			"access_control_allow_methods", string(c.Response().Header.Peek("Access-Control-Allow-Methods")),
			"access_control_allow_headers", string(c.Response().Header.Peek("Access-Control-Allow-Headers")),
			"body", respBody,
		)

		return err
	})
}

