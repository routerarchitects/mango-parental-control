package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Set required environment variables enforced by discovery/logger common packages
	t.Setenv("SERVICE_NAME", "mango-parental-control")
	t.Setenv("SERVICE_TYPE", "mango-parental-control")
	t.Setenv("SERVICE_VERSION", "dev")
	t.Setenv("SYSTEM_URI_PRIVATE", "https://localhost:17008")
	t.Setenv("SYSTEM_URI_PUBLIC", "https://localhost:16008")
	t.Setenv("DISCOVERY_TOPIC", "service_events")

	// Backup env vars to avoid modifying the caller's environment
	discoveryEnabledEnv := os.Getenv("DISCOVERY_ENABLED")
	serviceRpcEnabledEnv := os.Getenv("SERVICE_RPC_ENABLED")
	authEnabledEnv := os.Getenv("AUTH_ENABLED")

	// Temporarily remove env vars to test defaults
	os.Unsetenv("DISCOVERY_ENABLED")
	os.Unsetenv("SERVICE_RPC_ENABLED")
	os.Unsetenv("AUTH_ENABLED")

	// Restore them after the test
	defer func() {
		if discoveryEnabledEnv != "" {
			os.Setenv("DISCOVERY_ENABLED", discoveryEnabledEnv)
		}
		if serviceRpcEnabledEnv != "" {
			os.Setenv("SERVICE_RPC_ENABLED", serviceRpcEnabledEnv)
		}
		if authEnabledEnv != "" {
			os.Setenv("AUTH_ENABLED", authEnabledEnv)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error loading configuration defaults, got: %v", err)
	}

	tests := []struct {
		got, want any
		name      string
	}{
		{cfg.Server.HTTPPort, 16008, "HTTPPort"},
		{cfg.Server.PrivatePort, 17008, "PrivatePort"},
		{cfg.Database.Port, 5432, "Database Port"},
		{cfg.Database.StorageType, "postgresql", "StorageType"},
		{cfg.Discovery.Enabled, true, "Discovery.Enabled"},
		{cfg.RPC.Enabled, true, "RPC.Enabled"},
		{cfg.Auth.Enabled, true, "Auth.Enabled"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("expected default %s to be %v, got: %v", tt.name, tt.want, tt.got)
		}
	}
}
