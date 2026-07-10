package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/ra-common-mods/apperror"
)

type Database struct {
	Pool *pgxpool.Pool
	log  *slog.Logger
}

// Connect establishes a connection pool to PostgreSQL and returns a Database wrapper.
func Connect(ctx context.Context, cfg config.PostgresConfig, log *slog.Logger) (*Database, error) {
	if !strings.EqualFold(cfg.StorageType, "postgresql") {
		return nil, apperror.New(apperror.CodeInternal, fmt.Sprintf("unsupported storage type: %s", cfg.StorageType))
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.SSLMode,
	)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, "failed to parse postgres dsn config", err)
	}

	// Set sane connection pool defaults
	poolConfig.MaxConns = 25
	poolConfig.MinConns = 2
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 10 * time.Minute

	log.InfoContext(ctx, "connecting to postgresql database", "host", cfg.Host, "port", cfg.Port, "database", cfg.Database)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, apperror.Wrap(apperror.CodeInternal, "failed to establish postgres connection pool", err)
	}

	// Verify the connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, apperror.Wrap(apperror.CodeInternal, "failed to ping database", err)
	}

	log.InfoContext(ctx, "successfully connected to database")

	return &Database{
		Pool: pool,
		log:  log,
	}, nil
}

// Close closes the connection pool.
func (db *Database) Close() {
	if db.Pool != nil {
		db.log.Info("closing database connection pool")
		db.Pool.Close()
	}
}

// RunMigrations automatically scans and applies SQL migrations from the schemaDir directory.
func (db *Database) RunMigrations(ctx context.Context, schemaDir string) error {
	db.log.InfoContext(ctx, "checking database migrations", "directory", schemaDir)

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		return apperror.Wrap(apperror.CodeInternal, "failed to create schema_migrations table", err)
	}

	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		return apperror.Wrap(apperror.CodeInternal, "failed to read schema directory", err)
	}

	var sqlFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			sqlFiles = append(sqlFiles, entry.Name())
		}
	}
	sort.Strings(sqlFiles)

	rows, err := db.Pool.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return apperror.Wrap(apperror.CodeInternal, "failed to query schema_migrations", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		applied[v] = true
	}

	for _, file := range sqlFiles {
		if applied[file] {
			continue
		}

		db.log.InfoContext(ctx, "applying database migration", "file", file)
		content, err := os.ReadFile(filepath.Join(schemaDir, file))
		if err != nil {
			return apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("failed to read migration file %s", file), err)
		}

		err = pgx.BeginFunc(ctx, db.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(content)); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", file)
			return err
		})
		if err != nil {
			return apperror.Wrap(apperror.CodeInternal, fmt.Sprintf("migration %s failed to execute", file), err)
		}

		db.log.InfoContext(ctx, "successfully applied migration", "file", file)
	}

	db.log.InfoContext(ctx, "all database migrations are up to date")
	return nil
}
