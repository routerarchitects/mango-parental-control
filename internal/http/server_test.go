package http

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/mango-parental-control/internal/config"
)

func TestServer_Start_ValidationAndFallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("Fails on invalid ports configuration", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:    0,
			PrivatePort: 17008,
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "invalid HTTP ports configuration") {
			t.Fatalf("expected invalid HTTP ports error, got: %v", err)
		}
	})

	t.Run("Fails on identical public and private ports", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:    16008,
			PrivatePort: 16008,
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "public and private HTTP ports must not be identical") {
			t.Fatalf("expected identical ports error, got: %v", err)
		}
	})

	t.Run("Fails on empty certificate paths", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:    16008,
			PrivatePort: 17008,
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "TLS certificates path must not be empty") {
			t.Fatalf("expected empty TLS certificates path error, got: %v", err)
		}
	})

	t.Run("Public cert falls back to internal cert when public cert path is empty", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:       16008,
			PrivatePort:    17008,
			PublicTLS_CERT: "",
			PublicTLS_KEY:  "",
			TLS_CERT:       "/missing/internal-cert.pem",
			TLS_KEY:        "/missing/internal-key.pem",
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "TLS public certificate file /missing/internal-cert.pem does not exist") {
			t.Fatalf("expected fallback to internal cert path in error message, got: %v", err)
		}
	})

	t.Run("Explicit public cert is used when public cert path is provided", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:       16008,
			PrivatePort:    17008,
			PublicTLS_CERT: "/missing/public-cert.pem",
			PublicTLS_KEY:  "/missing/public-key.pem",
			TLS_CERT:       "/missing/internal-cert.pem",
			TLS_KEY:        "/missing/internal-key.pem",
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "TLS public certificate file /missing/public-cert.pem does not exist") {
			t.Fatalf("expected explicit public cert path in error message, got: %v", err)
		}
	})

	t.Run("Fails when internal private key file does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		dummyCert := filepath.Join(tmpDir, "dummy.crt")
		if err := os.WriteFile(dummyCert, []byte("dummy cert content"), 0644); err != nil {
			t.Fatalf("failed to create dummy cert file: %v", err)
		}

		srv := NewServer(config.ServerConfig{
			HTTPPort:       16008,
			PrivatePort:    17008,
			PublicTLS_CERT: dummyCert,
			PublicTLS_KEY:  dummyCert,
			TLS_CERT:       dummyCert,
			TLS_KEY:        "/missing/internal-key.pem",
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "TLS internal private key file /missing/internal-key.pem does not exist") {
			t.Fatalf("expected missing internal key error, got: %v", err)
		}
	})

	t.Run("Fails when only public cert is configured without key", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:       16008,
			PrivatePort:    17008,
			PublicTLS_CERT: "/some/public-cert.pem",
			PublicTLS_KEY:  "",
			TLS_CERT:       "/missing/internal-cert.pem",
			TLS_KEY:        "/missing/internal-key.pem",
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "RESTAPI_HOST_CERT and RESTAPI_HOST_KEY must be configured together") {
			t.Fatalf("expected partial public cert config error, got: %v", err)
		}
	})

	t.Run("Fails when only public key is configured without cert", func(t *testing.T) {
		srv := NewServer(config.ServerConfig{
			HTTPPort:       16008,
			PrivatePort:    17008,
			PublicTLS_CERT: "",
			PublicTLS_KEY:  "/some/public-key.pem",
			TLS_CERT:       "/missing/internal-cert.pem",
			TLS_KEY:        "/missing/internal-key.pem",
		}, logger)

		_, err := srv.Start(context.Background(), fiber.New(), fiber.New())
		if err == nil || !strings.Contains(err.Error(), "RESTAPI_HOST_CERT and RESTAPI_HOST_KEY must be configured together") {
			t.Fatalf("expected partial public cert config error, got: %v", err)
		}
	})
}
