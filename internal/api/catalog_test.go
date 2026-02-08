package api

import (
	"testing"

	"github.com/vettid/vettid-agent/internal/nats"
)

func TestCatalogCache_EmptyInitially(t *testing.T) {
	c := NewCatalogCache()
	if c.Version() != 0 {
		t.Errorf("expected version 0, got %d", c.Version())
	}
	if c.Count() != 0 {
		t.Errorf("expected count 0, got %d", c.Count())
	}
	entries := c.List()
	if len(entries) != 0 {
		t.Errorf("expected empty list, got %d entries", len(entries))
	}
}

func TestCatalogCache_Update(t *testing.T) {
	c := NewCatalogCache()

	catalog := &nats.SecretCatalog{
		Version:   3,
		UpdatedAt: "2026-02-08T16:00:00Z",
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "openai_key", Category: "api_keys", AllowedActions: []string{"retrieve", "use"}},
			{SecretID: "s2", Name: "github_token", Category: "api_keys", AllowedActions: []string{"retrieve"}},
			{SecretID: "s3", Name: "deploy_key", Category: "ssh_keys", AllowedActions: []string{"use"}},
		},
	}
	c.Update(catalog)

	if c.Version() != 3 {
		t.Errorf("expected version 3, got %d", c.Version())
	}
	if c.Count() != 3 {
		t.Errorf("expected count 3, got %d", c.Count())
	}
}

func TestCatalogCache_Get(t *testing.T) {
	c := NewCatalogCache()
	c.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "test_key", Category: "api_keys"},
		},
	})

	entry := c.Get("s1")
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.Name != "test_key" {
		t.Errorf("expected name 'test_key', got %q", entry.Name)
	}

	missing := c.Get("nonexistent")
	if missing != nil {
		t.Errorf("expected nil for missing entry, got %+v", missing)
	}
}

func TestCatalogCache_GetReturnsCopy(t *testing.T) {
	c := NewCatalogCache()
	c.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "original", Category: "api_keys"},
		},
	})

	entry := c.Get("s1")
	entry.Name = "modified"

	// Original should be unchanged
	original := c.Get("s1")
	if original.Name != "original" {
		t.Errorf("Get should return a copy, but original was modified to %q", original.Name)
	}
}

func TestCatalogCache_ListByCategory(t *testing.T) {
	c := NewCatalogCache()
	c.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "key1", Category: "api_keys"},
			{SecretID: "s2", Name: "key2", Category: "api_keys"},
			{SecretID: "s3", Name: "ssh1", Category: "ssh_keys"},
		},
	})

	apiKeys := c.ListByCategory("api_keys")
	if len(apiKeys) != 2 {
		t.Errorf("expected 2 api_keys, got %d", len(apiKeys))
	}

	sshKeys := c.ListByCategory("ssh_keys")
	if len(sshKeys) != 1 {
		t.Errorf("expected 1 ssh_keys, got %d", len(sshKeys))
	}

	empty := c.ListByCategory("nonexistent")
	if len(empty) != 0 {
		t.Errorf("expected 0 entries for nonexistent category, got %d", len(empty))
	}
}

func TestCatalogCache_UpdateReplaces(t *testing.T) {
	c := NewCatalogCache()

	c.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "old_key", Category: "api_keys"},
		},
	})

	c.Update(&nats.SecretCatalog{
		Version: 2,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s2", Name: "new_key", Category: "api_keys"},
		},
	})

	if c.Version() != 2 {
		t.Errorf("expected version 2, got %d", c.Version())
	}
	if c.Count() != 1 {
		t.Errorf("expected count 1, got %d", c.Count())
	}
	if c.Get("s1") != nil {
		t.Error("old entry should be gone after update")
	}
	if c.Get("s2") == nil {
		t.Error("new entry should exist after update")
	}
}

func TestCatalogCache_ListReturnsCopy(t *testing.T) {
	c := NewCatalogCache()
	c.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "original", Category: "api_keys"},
		},
	})

	entries := c.List()
	entries[0].Name = "modified"

	// Original should be unchanged
	fresh := c.List()
	if fresh[0].Name != "original" {
		t.Errorf("List should return a copy, but original was modified to %q", fresh[0].Name)
	}
}
