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
	publicCrt   string
	publicKey   string
	port        int
	privatePort int
	logger      *slog.Logger
}

func NewServer(cfg config.ServerConfig, logger *slog.Logger) *Server {
	return &Server{
		crt:         cfg.TLS_CERT,
		key:         cfg.TLS_KEY,
		publicCrt:   cfg.PublicTLS_CERT,
		publicKey:   cfg.PublicTLS_KEY,
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

	// Resolve public certificate: fall back to internal only when both are empty.
	// When exactly one is configured, fail startup to prevent silent misconfiguration.
	pubCrt := s.publicCrt
	pubKey := s.publicKey
	if pubCrt == "" && pubKey == "" {
		pubCrt = s.crt
		pubKey = s.key
	} else if pubCrt == "" || pubKey == "" {
		return nil, apperror.New(apperror.CodeInternal, "RESTAPI_HOST_CERT and RESTAPI_HOST_KEY must be configured together; only one was provided")
	}

	if pubCrt == "" || pubKey == "" || s.crt == "" || s.key == "" {
		return nil, apperror.New(apperror.CodeInternal, "TLS certificates path must not be empty")
	}

	// Verify certificate paths exist
	if _, err := os.Stat(pubCrt); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS public certificate file %s does not exist. For cloud deployments, ensure RESTAPI_HOST_CERT is configured and points to the public certificate (usually restapi-public-cert.pem)", pubCrt), err)
	}
	if _, err := os.Stat(pubKey); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS public private key file %s does not exist. For cloud deployments, ensure RESTAPI_HOST_KEY is configured and points to the public private key (usually restapi-public-key.pem)", pubKey), err)
	}
	if _, err := os.Stat(s.crt); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS internal certificate file %s does not exist", s.crt), err)
	}
	if _, err := os.Stat(s.key); err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("TLS internal private key file %s does not exist", s.key), err)
	}

	publicCert, err := tls.LoadX509KeyPair(pubCrt, pubKey)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to load public TLS key pair from cert %s and key %s. Verify these are valid public certificates and keys.", pubCrt, pubKey), err)
	}

	privateCert, err := tls.LoadX509KeyPair(s.crt, s.key)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to load internal TLS key pair from cert %s and key %s.", s.crt, s.key), err)
	}

	publicTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{publicCert},
		MinVersion:   tls.VersionTLS12,
	}

	privateTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{privateCert},
		MinVersion:   tls.VersionTLS12,
	}

	publicListener, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.port), publicTlsConfig)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to bind public port %d", s.port), err)
	}

	privateListener, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.privatePort), privateTlsConfig)
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
