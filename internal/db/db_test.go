package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/routerarchitects/mango-parental-control/internal/config"
)

func setupTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVICE_NAME", "mango-parental-control")
	t.Setenv("SERVICE_TYPE", "mango-parental-control")
	t.Setenv("SERVICE_VERSION", "dev")
	t.Setenv("SYSTEM_URI_PRIVATE", "https://localhost:17008")
	t.Setenv("SYSTEM_URI_PUBLIC", "https://localhost:16008")
	t.Setenv("DISCOVERY_TOPIC", "service_events")
}

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Skipf("skipping test; failed to load config: %v", err)
	}
	if !strings.EqualFold(cfg.Database.StorageType, "postgresql") {
		t.Skip("skipping test; storage type is not postgresql")
	}
	return cfg
}

func adminConnect(t *testing.T, ctx context.Context, dbCfg config.PostgresConfig) *pgx.Conn {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=%s",
		dbCfg.Username, dbCfg.Password, dbCfg.Host, dbCfg.Port, dbCfg.SSLMode,
	)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("skipping database test; postgres unreachable: %v", err)
	}
	return conn
}

func TestConnect_UnreachableHost(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	t.Run("Connect returns error on unreachable database host", func(t *testing.T) {
		badCfg := cfg.Database
		badCfg.Host = "invalid-host-name-12345.local"
		badCfg.Port = 9999
		badCfg.Database = "should_not_reach_here"

		_, err := Connect(ctx, badCfg, logger)
		if err == nil {
			t.Fatal("expected Connect() to fail on unreachable host, got nil")
		}
	})
}

func TestConnect_Success(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	t.Run("Connect succeeds when DB already exists", func(t *testing.T) {
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		existingDBName := fmt.Sprintf("mango_test_connect_exists_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		// Pre-create the database using admin credentials.
		if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE "%s"`, existingDBName)); err != nil {
			t.Fatalf("failed to pre-create test database: %v", err)
		}
		defer func() {
			_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS "%s"`, existingDBName))
		}()

		existsCfg := cfg.Database
		existsCfg.Database = existingDBName
		dbConn, err := Connect(ctx, existsCfg, logger)
		if err != nil {
			t.Fatalf("expected Connect() to succeed, got: %v", err)
		}
		dbConn.Close()
	})
}
