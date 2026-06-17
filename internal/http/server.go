package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/ra-common-mods/apperror"
)

type Server struct {
	crt         string
	key         string
	port        int
	privatePort int
	logger      *slog.Logger
}

func NewServer(cfg config.ServerConfig, logger *slog.Logger) *Server {
	return &Server{
		crt:         cfg.TLS_CERT,
		key:         cfg.TLS_KEY,
		port:        cfg.HTTPPort,
		privatePort: cfg.PrivatePort,
		logger:      logger,
	}
}

// Start spawns the HTTP/HTTPS listeners in separate goroutines.
func (s *Server) Start(ctx context.Context, publicApp *fiber.App, privateApp *fiber.App) (<-chan error, error) {
	if s.port <= 0 || s.privatePort <= 0 {
		return nil, apperror.New(apperror.CodeInternal, "invalid HTTP ports configuration")
	}
	if s.port == s.privatePort {
		return nil, apperror.New(apperror.CodeInternal, "public and private HTTP ports must not be identical")
	}

	if s.crt == "" || s.key == "" {
		return nil, apperror.New(apperror.CodeInternal, "TLS certificates path must not be empty")
	}

	// Verify certificate paths exist
	if _, err := os.Stat(s.crt); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS certificate file %s does not exist", s.crt), err)
	}
	if _, err := os.Stat(s.key); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS private key file %s does not exist", s.key), err)
	}

	cert, err := tls.LoadX509KeyPair(s.crt, s.key)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, "failed to load TLS key pair", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	publicListener, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.port), tlsConfig)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to bind public port %d", s.port), err)
	}

	privateListener, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.privatePort), tlsConfig)
	if err != nil {
		_ = publicListener.Close()
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to bind private port %d", s.privatePort), err)
	}

	errCh := make(chan error, 2)

	// Start public server listener
	go func() {
		err := publicApp.Listener(publicListener)
		if err != nil && !isExpectedClose(ctx, err) {
			errCh <- fmt.Errorf("public server listener failed on port %d: %w", s.port, err)
			return
		}
		errCh <- nil
	}()

	// Start private server listener
	go func() {
		err := privateApp.Listener(privateListener)
		if err != nil && !isExpectedClose(ctx, err) {
			errCh <- fmt.Errorf("private server listener failed on port %d: %w", s.privatePort, err)
			return
		}
		errCh <- nil
	}()

	s.logger.Info("TLS servers started successfully", "public_port", s.port, "private_port", s.privatePort)
	return errCh, nil
}

func isExpectedClose(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return ctx != nil && ctx.Err() != nil
}
