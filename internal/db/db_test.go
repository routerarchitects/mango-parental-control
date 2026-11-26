package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func findSchemaDirForDBTest(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"db/schema", "../../db/schema", "../../../db/schema"} {
		if _, err := os.Stat(filepath.Join(p, "0004_cross_midnight_client_access.sql")); err == nil {
			return p
		}
	}
	t.Fatal("could not locate db/schema directory")
	return ""
}

func TestClientAccessMigrationAndConstraints(t *testing.T) {
	setupTestEnv(t)
	cfg := loadTestConfig(t)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	adminConn := adminConnect(t, ctx, cfg.Database)
	defer adminConn.Close(ctx)

	testDBName := fmt.Sprintf("mango_test_ca_constraints_%s",
		strings.ReplaceAll(uuid.New().String(), "-", "_"))

	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE "%s"`, testDBName)); err != nil {
		t.Fatalf("failed to pre-create test database: %v", err)
	}
	defer func() {
		_, _ = adminConn.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS "%s" WITH (FORCE)`, testDBName))
	}()

	testCfg := cfg.Database
	testCfg.Database = testDBName
	dbConn, err := Connect(ctx, testCfg, logger)
	if err != nil {
		t.Fatalf("expected Connect() to succeed, got: %v", err)
	}
	defer dbConn.Close()

	schemaDir := findSchemaDirForDBTest(t)

	// Step 1: Apply 0001..0003 manually so we can seed pre-0004 permanent and legacy timed rows.
	if _, err := dbConn.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("failed to create schema_migrations: %v", err)
	}

	preMigrations := []string{
		"0001_initial.sql",
		"0002_client_access.sql",
		"0003_permanent_client_access.sql",
	}
	for _, file := range preMigrations {
		content, err := os.ReadFile(filepath.Join(schemaDir, file))
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		if _, err := dbConn.Pool.Exec(ctx, string(content)); err != nil {
			t.Fatalf("failed to apply %s: %v", file, err)
		}
		if _, err := dbConn.Pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, file); err != nil {
			t.Fatalf("failed to record %s: %v", file, err)
		}
	}

	subID := uuid.New().String()
	_, err = dbConn.Pool.Exec(ctx, `
		INSERT INTO pc_client_access (subscriber_id, client_mac, start_date, stop_date, start_time, stop_time, created_at, updated_at)
		VALUES
			($1, 'AA:BB:CC:DD:EE:01', NULL, NULL, NULL, NULL, NOW(), NOW()),
			($1, 'AA:BB:CC:DD:EE:02', '2026-11-25', '2026-11-26', '07:30:00', '08:00:00', NOW(), NOW())
	`, subID)
	if err != nil {
		t.Fatalf("failed to seed pre-0004 rows: %v", err)
	}

	// Step 2: Run remaining migrations (0004) against the seeded database.
	if err := dbConn.RunMigrations(ctx, schemaDir); err != nil {
		t.Fatalf("RunMigrations (0004) failed: %v", err)
	}

	// Verify permanent row remained NULL and legacy row was backfilled in UTC.
	var permStartsAt, permExpiresAt *time.Time
	if err := dbConn.Pool.QueryRow(ctx, `
		SELECT starts_at, expires_at FROM pc_client_access
		WHERE subscriber_id = $1 AND client_mac = 'AA:BB:CC:DD:EE:01'
	`, subID).Scan(&permStartsAt, &permExpiresAt); err != nil {
		t.Fatalf("failed to query migrated permanent row: %v", err)
	}
	if permStartsAt != nil || permExpiresAt != nil {
		t.Errorf("expected permanent row timestamps to remain NULL, got starts_at=%v expires_at=%v", permStartsAt, permExpiresAt)
	}

	var legStartsAt, legExpiresAt *time.Time
	var legStartDate, legStopDate, legStartTime, legStopTime string
	if err := dbConn.Pool.QueryRow(ctx, `
		SELECT start_date, stop_date, start_time, stop_time, starts_at, expires_at
		FROM pc_client_access
		WHERE subscriber_id = $1 AND client_mac = 'AA:BB:CC:DD:EE:02'
	`, subID).Scan(&legStartDate, &legStopDate, &legStartTime, &legStopTime, &legStartsAt, &legExpiresAt); err != nil {
		t.Fatalf("failed to query migrated legacy row: %v", err)
	}
	wantStart := time.Date(2026, 11, 25, 7, 30, 0, 0, time.UTC)
	wantStop := time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
	if legStartDate != "2026-11-25" || legStopDate != "2026-11-26" || legStartTime != "07:30:00" || legStopTime != "08:00:00" {
		t.Errorf("unexpected migrated legacy strings: %s %s %s %s", legStartDate, legStopDate, legStartTime, legStopTime)
	}
	if legStartsAt == nil || legExpiresAt == nil || !legStartsAt.Equal(wantStart) || !legExpiresAt.Equal(wantStop) {
		t.Errorf("expected backfilled UTC timestamps %v..%v, got starts_at=%v expires_at=%v", wantStart, wantStop, legStartsAt, legExpiresAt)
	}

	// Step 3: Validate valid and malformed shapes against CHECK constraints.
	tStart := time.Date(2036, 7, 8, 23, 0, 0, 0, time.UTC)
	tStop := time.Date(2036, 7, 9, 1, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		mac       string
		startDate *string
		stopDate  *string
		startTime *string
		stopTime  *string
		startsAt  *time.Time
		expiresAt *time.Time
		wantErr   bool
	}{
		{
			name:    "valid permanent row",
			mac:     "AA:BB:CC:DD:EE:10",
			wantErr: false,
		},
		{
			name:      "valid legacy 4-field row with timestamps",
			mac:       "AA:BB:CC:DD:EE:11",
			startDate: strPtr("2036-07-08"),
			stopDate:  strPtr("2036-07-09"),
			startTime: strPtr("07:30:00"),
			stopTime:  strPtr("08:00:00"),
			startsAt:  &tStart,
			expiresAt: &tStop,
			wantErr:   false,
		},
		{
			name:      "valid legacy 4-field row with NULL timestamps (legacy allowance)",
			mac:       "AA:BB:CC:DD:EE:12",
			startDate: strPtr("2010-01-01"),
			stopDate:  strPtr("2010-01-02"),
			startTime: strPtr("00:00:00"),
			stopTime:  strPtr("01:00:00"),
			wantErr:   false,
		},
		{
			name:      "valid two-field ISO row",
			mac:       "AA:BB:CC:DD:EE:13",
			startDate: strPtr("2036-07-08T23:00:00"),
			stopDate:  strPtr("2036-07-09T01:00:00"),
			startsAt:  &tStart,
			expiresAt: &tStop,
			wantErr:   false,
		},
		{
			name:      "reject starts_at NOT NULL with expires_at NULL",
			mac:       "AA:BB:CC:DD:EE:20",
			startDate: strPtr("2036-07-08"),
			stopDate:  strPtr("2036-07-09"),
			startTime: strPtr("07:30:00"),
			stopTime:  strPtr("08:00:00"),
			startsAt:  &tStart,
			wantErr:   true,
		},
		{
			name:      "reject starts_at NULL with expires_at NOT NULL",
			mac:       "AA:BB:CC:DD:EE:21",
			startDate: strPtr("2036-07-08"),
			stopDate:  strPtr("2036-07-09"),
			startTime: strPtr("07:30:00"),
			stopTime:  strPtr("08:00:00"),
			expiresAt: &tStop,
			wantErr:   true,
		},
		{
			name:      "reject expires_at equal to starts_at",
			mac:       "AA:BB:CC:DD:EE:22",
			startDate: strPtr("2036-07-08T23:00:00"),
			stopDate:  strPtr("2036-07-09T01:00:00"),
			startsAt:  &tStart,
			expiresAt: &tStart,
			wantErr:   true,
		},
		{
			name:      "reject permanent row with stray start_time",
			mac:       "AA:BB:CC:DD:EE:23",
			startTime: strPtr("07:30:00"),
			wantErr:   true,
		},
		{
			name:      "reject permanent row with stray timestamps",
			mac:       "AA:BB:CC:DD:EE:24",
			startsAt:  &tStart,
			expiresAt: &tStop,
			wantErr:   true,
		},
		{
			name:      "reject legacy row missing stop_time",
			mac:       "AA:BB:CC:DD:EE:25",
			startDate: strPtr("2036-07-08"),
			stopDate:  strPtr("2036-07-09"),
			startTime: strPtr("07:30:00"),
			wantErr:   true,
		},
		{
			name:      "reject legacy row with stop_time <= start_time",
			mac:       "AA:BB:CC:DD:EE:26",
			startDate: strPtr("2036-07-08"),
			stopDate:  strPtr("2036-07-09"),
			startTime: strPtr("08:00:00"),
			stopTime:  strPtr("07:00:00"),
			wantErr:   true,
		},
		{
			name:      "reject ISO row with stray start_time",
			mac:       "AA:BB:CC:DD:EE:27",
			startDate: strPtr("2036-07-08T23:00:00"),
			stopDate:  strPtr("2036-07-09T01:00:00"),
			startTime: strPtr("23:00:00"),
			startsAt:  &tStart,
			expiresAt: &tStop,
			wantErr:   true,
		},
		{
			name:      "reject ISO row with NULL timestamps",
			mac:       "AA:BB:CC:DD:EE:28",
			startDate: strPtr("2036-07-08T23:00:00"),
			stopDate:  strPtr("2036-07-09T01:00:00"),
			wantErr:   true,
		},
		{
			name:      "reject mixed ISO start_date and legacy stop_date",
			mac:       "AA:BB:CC:DD:EE:29",
			startDate: strPtr("2036-07-08T23:00:00"),
			stopDate:  strPtr("2036-07-09"),
			startsAt:  &tStart,
			expiresAt: &tStop,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dbConn.Pool.Exec(ctx, `
				INSERT INTO pc_client_access (
					subscriber_id, client_mac, start_date, stop_date, start_time, stop_time,
					starts_at, expires_at, created_at, updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
			`, subID, tc.mac, tc.startDate, tc.stopDate, tc.startTime, tc.stopTime, tc.startsAt, tc.expiresAt)
			if (err != nil) != tc.wantErr {
				t.Fatalf("INSERT error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
