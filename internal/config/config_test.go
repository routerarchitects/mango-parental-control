package config

import (
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
