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

// setupTestEnv sets required environment variables that discovery/logger packages
// enforce. Call this at the top of any test that loads config.
func setupTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SERVICE_NAME", "mango-parental-control")
	t.Setenv("SERVICE_TYPE", "mango-parental-control")
	t.Setenv("SERVICE_VERSION", "dev")
	t.Setenv("SYSTEM_URI_PRIVATE", "https://localhost:17008")
	t.Setenv("SYSTEM_URI_PUBLIC", "https://localhost:16008")
	t.Setenv("DISCOVERY_TOPIC", "service_events")
}

// loadTestConfig loads the service config and skips the test if the environment
// is not configured for a PostgreSQL connection.
func loadTestConfig(t *testing.T) config.Config {
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

// adminConnect opens a direct connection to the postgres admin database using
// the credentials from dbCfg. Fails the test immediately if unable to connect.
func adminConnect(t *testing.T, ctx context.Context, dbCfg config.PostgresConfig) *pgx.Conn {
	t.Helper()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=%s",
		dbCfg.Username, dbCfg.Password, dbCfg.Host, dbCfg.Port, dbCfg.SSLMode,
	)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to open admin connection: %v", err)
	}
	return conn
}

// TestEnsureDatabaseExists covers the four main paths through the
// ensureDatabaseExists helper:
//
//  1. The target database already exists  → no error, no CREATE issued.
//  2. The target database is absent       → CREATE DATABASE succeeds.
//  3. Admin connection cannot be opened   → error surfaces with the real cause.
//  4. CREATE DATABASE is denied           → error surfaces with the real cause.
func TestEnsureDatabaseExists(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	// ── (2) DB already exists ─────────────────────────────────────────────────
	// We explicitly pre-create a unique database so the test is deterministic:
	// ensureDatabaseExists must exercise the "already exists" branch, not the
	// create branch, regardless of what cfg.Database.Database points to.
	t.Run("DB Exists Path", func(t *testing.T) {
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		existingDBName := fmt.Sprintf("mango_test_exists_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		// Pre-create the database so it is guaranteed to exist.
		if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE "%s"`, existingDBName)); err != nil {
			t.Fatalf("failed to pre-create test database: %v", err)
		}
		defer func() {
			_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS "%s"`, existingDBName))
		}()

		// Now call ensureDatabaseExists against the known-existing database.
		existsCfg := cfg.Database
		existsCfg.Database = existingDBName
		err := ensureDatabaseExists(ctx, existsCfg, logger)
		if err != nil {
			t.Errorf("expected no error when database already exists, got: %v", err)
		}
	})

	// ── (3) DB is absent ──────────────────────────────────────────────────────
	t.Run("DB Missing Path", func(t *testing.T) {
		uniqueDBName := fmt.Sprintf("mango_test_create_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		// Admin connection used to verify existence and clean up afterwards.
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		// The database must not exist yet.
		var existsBefore bool
		_ = adminConn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
			uniqueDBName,
		).Scan(&existsBefore)
		if existsBefore {
			t.Fatalf("expected database %q to be absent before test", uniqueDBName)
		}

		// ensureDatabaseExists should create the database without error.
		missingCfg := cfg.Database
		missingCfg.Database = uniqueDBName
		err := ensureDatabaseExists(ctx, missingCfg, logger)
		if err != nil {
			t.Fatalf("expected no error when creating missing database, got: %v", err)
		}

		// Verify the database now exists.
		var existsAfter bool
		err = adminConn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
			uniqueDBName,
		).Scan(&existsAfter)
		if err != nil {
			t.Errorf("failed to query pg_database after create: %v", err)
		}
		if !existsAfter {
			t.Error("expected database to exist after ensureDatabaseExists call, but it does not")
		}

		// Cleanup: drop the test database.
		if _, err := adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE "%s"`, uniqueDBName)); err != nil {
			t.Logf("warning: failed to drop test database %s: %v", uniqueDBName, err)
		}
	})

	// ── (4a) Admin connection fails ───────────────────────────────────────────
	t.Run("Admin Connect Failure Path", func(t *testing.T) {
		unreachableCfg := cfg.Database
		unreachableCfg.Host = "invalid-host-name-12345.local"
		unreachableCfg.Port = 9999
		unreachableCfg.Database = "should_not_reach_here"

		err := ensureDatabaseExists(ctx, unreachableCfg, logger)
		if err == nil {
			t.Fatal("expected error due to unreachable admin host, got nil")
		}
		if !strings.Contains(err.Error(), "failed to connect to admin database") {
			t.Errorf("expected admin-connect error message, got: %v", err)
		}
	})

	// ── (4b) CREATE DATABASE fails: privilege denied ───────────────────────────
	// Create a restricted PostgreSQL role that has LOGIN but no CREATEDB
	// privilege, then verify that ensureDatabaseExists correctly surfaces the
	// create-failure error when that role is used.
	t.Run("No Create Privilege Path", func(t *testing.T) {
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		restrictedUser := "mango_noprivilege_test"
		restrictedPass := "mango_noprivilege_pass_123"

		// Ensure no leftover role from a previous failed run.
		_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS "%s"`, restrictedUser))

		// Create the role with LOGIN but without CREATEDB.
		_, err := adminConn.Exec(ctx, fmt.Sprintf(
			`CREATE ROLE "%s" WITH LOGIN PASSWORD '%s' NOCREATEDB`,
			restrictedUser, restrictedPass,
		))
		if err != nil {
			t.Skipf("skipping no-create-privilege test; could not create restricted role: %v", err)
		}
		defer func() {
			_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS "%s"`, restrictedUser))
		}()

		// Use the restricted role to attempt creating a brand-new database.
		restrictedCfg := cfg.Database
		restrictedCfg.Username = restrictedUser
		restrictedCfg.Password = restrictedPass
		restrictedCfg.Database = fmt.Sprintf("mango_test_noprivilege_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		err = ensureDatabaseExists(ctx, restrictedCfg, logger)
		if err == nil {
			t.Fatal("expected error due to NOCREATEDB role, got nil")
		}
		// The error must originate from the CREATE DATABASE step, not from the
		// admin connection step (the restricted role can still connect to postgres).
		if !strings.Contains(err.Error(), "failed to create database") {
			t.Errorf("expected create-database privilege error, got: %v", err)
		}
	})
}

// TestConnect_FailsFastOnBootstrapError verifies the full Connect() startup
// path — not just the helper — when the database bootstrap fails.
//
// The PR changed Connect() to return an error immediately when
// ensureDatabaseExists fails, so the test must validate that Connect() itself
// propagates the failure and does not silently continue to the pool/ping step.
func TestConnect_FailsFastOnBootstrapError(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	// ── Connect fails when admin host is unreachable ───────────────────────────
	t.Run("Connect returns error on unreachable admin host", func(t *testing.T) {
		badCfg := cfg.Database
		badCfg.Host = "invalid-host-name-12345.local"
		badCfg.Port = 9999
		badCfg.Database = "should_not_reach_here"

		_, err := Connect(ctx, badCfg, logger)
		if err == nil {
			t.Fatal("expected Connect() to fail on bootstrap error, got nil")
		}
		// The error must surface the bootstrap cause, not a generic ping failure.
		if !strings.Contains(err.Error(), "database bootstrap failed") {
			t.Errorf("expected bootstrap failure message from Connect(), got: %v", err)
		}
	})

	// ── Connect fails when role lacks CREATEDB privilege ─────────────────────
	t.Run("Connect returns error when role lacks CREATEDB privilege", func(t *testing.T) {
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		restrictedUser := "mango_connect_noprivilege_test"
		restrictedPass := "mango_connect_noprivilege_pass_123"

		_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS "%s"`, restrictedUser))

		_, err := adminConn.Exec(ctx, fmt.Sprintf(
			`CREATE ROLE "%s" WITH LOGIN PASSWORD '%s' NOCREATEDB`,
			restrictedUser, restrictedPass,
		))
		if err != nil {
			t.Skipf("skipping test; could not create restricted role: %v", err)
		}
		defer func() {
			_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS "%s"`, restrictedUser))
		}()

		restrictedCfg := cfg.Database
		restrictedCfg.Username = restrictedUser
		restrictedCfg.Password = restrictedPass
		restrictedCfg.Database = fmt.Sprintf("mango_connect_noprivilege_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		_, err = Connect(ctx, restrictedCfg, logger)
		if err == nil {
			t.Fatal("expected Connect() to fail when role lacks CREATEDB privilege, got nil")
		}
		if !strings.Contains(err.Error(), "database bootstrap failed") {
			t.Errorf("expected bootstrap failure message from Connect(), got: %v", err)
		}
	})
}

// TestConnect_SucceedsOnBootstrap verifies the full Connect() startup path for
// the two happy-path bootstrap scenarios:
//
//  1. The configured database already exists → Connect() opens the pool successfully.
//  2. The configured database is absent      → Connect() creates it, then opens the pool.
//
// These tests close the gap between the helper-level success tests in
// TestEnsureDatabaseExists and the full runtime startup behavior that the PR
// changed in Connect().
func TestConnect_SucceedsOnBootstrap(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	// ── Connect() succeeds when the target database already exists ────────────
	// We explicitly pre-create a unique database so Connect() is guaranteed to
	// exercise the "already exists" bootstrap path, not the create path.
	t.Run("Connect succeeds when DB already exists", func(t *testing.T) {
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		existingDBName := fmt.Sprintf("mango_test_connect_exists_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		// Pre-create the database so it is guaranteed to already exist.
		if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE "%s"`, existingDBName)); err != nil {
			t.Fatalf("failed to pre-create test database: %v", err)
		}
		defer func() {
			_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS "%s"`, existingDBName))
		}()

		// Connect() must succeed against the known-existing database.
		existsCfg := cfg.Database
		existsCfg.Database = existingDBName
		db, err := Connect(ctx, existsCfg, logger)
		if err != nil {
			t.Fatalf("expected Connect() to succeed when DB already exists, got: %v", err)
		}
		db.Close()
	})

	// ── Connect() succeeds when the target database is absent ─────────────────
	// Bootstrap creates it, then Connect() opens the pool against the new DB.
	t.Run("Connect succeeds when DB is missing and bootstrap creates it", func(t *testing.T) {
		uniqueDBName := fmt.Sprintf("mango_test_connect_create_%s",
			strings.ReplaceAll(uuid.New().String(), "-", "_"))

		// Admin connection is used only for the post-test cleanup (DROP DATABASE).
		adminConn := adminConnect(t, ctx, cfg.Database)
		defer adminConn.Close(ctx)

		missingCfg := cfg.Database
		missingCfg.Database = uniqueDBName

		// Connect() must bootstrap-create the database and succeed.
		db, err := Connect(ctx, missingCfg, logger)
		if err != nil {
			t.Fatalf("expected Connect() to succeed after bootstrap-creating missing DB, got: %v", err)
		}
		db.Close()

		// Verify the database was actually created by bootstrap.
		var exists bool
		_ = adminConn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
			uniqueDBName,
		).Scan(&exists)
		if !exists {
			t.Error("expected database to exist after Connect() bootstrap-created it, but it does not")
		}

		// Cleanup: drop the test database.
		if _, err := adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE "%s"`, uniqueDBName)); err != nil {
			t.Logf("warning: failed to drop test database %s: %v", uniqueDBName, err)
		}
	})
}
