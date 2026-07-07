package app

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/routerarchitects/mango-parental-control/internal/config"
	"github.com/routerarchitects/ow-common-mods/servicediscovery"
	"github.com/routerarchitects/ra-common-mods/kafka"
)

func TestGetExpectedAPIKey(t *testing.T) {
	t.Run("With discovery enabled", func(t *testing.T) {
		// Mock discovery config
		dcfg := servicediscovery.Config{
			Topic:           "service_events",
			ServiceType:     "mango-parental-control",
			PrivateEndpoint: "localhost:17008",
			PublicEndpoint:  "localhost:16008",
			InstanceKey:     "custom-key",
		}
		disc, err := servicediscovery.New(dcfg, kafka.Config{}, slog.New(slog.NewTextHandler(os.Stdout, nil)))
		if err != nil {
			t.Logf("discovery New skipped/failed: %v", err)
			return
		}
		defer func() {
			_ = disc.Stop(context.Background())
		}()

		cfg := &config.Config{
			Discovery: config.DiscoveryConfig{
				Enabled: true,
			},
		}

		key, err := getExpectedAPIKey(disc, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "custom-key" {
			t.Fatalf("expected 'custom-key', got: %s", key)
		}
	})

	t.Run("With discovery disabled and InstanceKey set", func(t *testing.T) {
		cfg := &config.Config{
			Discovery: config.DiscoveryConfig{
				Enabled: false,
			},
		}
		cfg.Discovery.InstanceKey = "my-configured-key"

		key, err := getExpectedAPIKey(nil, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "my-configured-key" {
			t.Fatalf("expected 'my-configured-key', got: %s", key)
		}
	})

	t.Run("With discovery disabled, empty InstanceKey, and PublicEndpoint set", func(t *testing.T) {
		cfg := &config.Config{
			Discovery: config.DiscoveryConfig{
				Enabled: false,
			},
		}
		cfg.Discovery.PublicEndpoint = "http://localhost:16008"

		key, err := getExpectedAPIKey(nil, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedKey := sha256Hex("http://localhost:16008")
		if key != expectedKey {
			t.Fatalf("expected derived key '%s', got: %s", expectedKey, key)
		}
	})

	t.Run("With discovery disabled, empty InstanceKey, and empty PublicEndpoint", func(t *testing.T) {
		cfg := &config.Config{
			Discovery: config.DiscoveryConfig{
				Enabled: false,
			},
		}

		_, err := getExpectedAPIKey(nil, cfg)
		if err == nil {
			t.Fatalf("expected error for missing credentials and public endpoint, got nil")
		}
	})
}
