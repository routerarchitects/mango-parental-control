package middleware

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/ow-common-mods/fiber/middleware/auth"
)

func TestServiceAuth_AuthDisabled(t *testing.T) {
	privateCfg := auth.InternalAPIKeyConfig{
		ExpectedAPIKey: "dummy-key",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serviceAuth, err := NewServiceAuth(logger, false, auth.PublicAuthConfig{}, privateCfg, nil)
	if err != nil {
		t.Fatalf("failed to create ServiceAuth: %v", err)
	}

	app := fiber.New()
	app.Get("/test-public", serviceAuth.PublicAuth, func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/test-public", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 OK when auth is disabled, got: %d", resp.StatusCode)
	}
}

func TestServiceAuth_PrivateAuth(t *testing.T) {
	privateCfg := auth.InternalAPIKeyConfig{
		ExpectedAPIKey: "secret-internal-api-key",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serviceAuth, err := NewServiceAuth(logger, false, auth.PublicAuthConfig{}, privateCfg, nil)
	if err != nil {
		t.Fatalf("failed to create ServiceAuth: %v", err)
	}

	app := fiber.New()
	app.Get("/test-private", serviceAuth.PrivateAuth, func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	t.Run("Rejects request without headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-private", nil)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for missing headers, got: %d", resp.StatusCode)
		}
	})

	t.Run("Rejects request without X-INTERNAL-NAME header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-private", nil)
		req.Header.Set("X-API-KEY", "secret-internal-api-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for missing X-INTERNAL-NAME, got: %d", resp.StatusCode)
		}
	})

	t.Run("Rejects request with invalid X-API-KEY header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-private", nil)
		req.Header.Set("X-INTERNAL-NAME", "test-service")
		req.Header.Set("X-API-KEY", "wrong-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for invalid API key, got: %d", resp.StatusCode)
		}
	})

	t.Run("Accepts request with valid X-INTERNAL-NAME and X-API-KEY headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-private", nil)
		req.Header.Set("X-INTERNAL-NAME", "test-service")
		req.Header.Set("X-API-KEY", "secret-internal-api-key")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test failed: %v", err)
		}
		if resp.StatusCode != fiber.StatusOK {
			t.Fatalf("expected 200 OK for valid credentials, got: %d", resp.StatusCode)
		}
	})
}

func TestRegisterPublicCORS(t *testing.T) {
	app := fiber.New()
	RegisterPublicCORS(app)

	app.Get("/test-cors", func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("OPTIONS", "/test-cors", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}

	corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
	if corsHeader != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin header to be '*', got: %s", corsHeader)
	}
}

func TestServiceAuth_PublicAuthMissingValidator(t *testing.T) {
	privateCfg := auth.InternalAPIKeyConfig{
		ExpectedAPIKey: "dummy-key",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewServiceAuth(logger, true, auth.PublicAuthConfig{}, privateCfg, nil)
	if err == nil {
		t.Fatal("expected error when auth is enabled but no validator is available, got nil")
	}
}
