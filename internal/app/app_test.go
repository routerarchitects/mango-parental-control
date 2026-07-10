package app

import (
	"testing"
)

func TestResolveAPIKey(t *testing.T) {
	t.Run("With discovery key present", func(t *testing.T) {
		key, err := resolveAPIKey("discovery-generated-key", "some-config-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "discovery-generated-key" {
			t.Errorf("expected 'discovery-generated-key', got '%s'", key)
		}
	})

	t.Run("With discovery key empty and config key present", func(t *testing.T) {
		key, err := resolveAPIKey("", "some-config-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "some-config-key" {
			t.Errorf("expected 'some-config-key', got '%s'", key)
		}
	})

	t.Run("With both discovery key and config key empty", func(t *testing.T) {
		_, err := resolveAPIKey("", "")
		if err == nil {
			t.Fatal("expected error due to missing API key configuration, got nil")
		}
	})
}
