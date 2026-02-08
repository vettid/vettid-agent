package api

import (
	"sync"
	"time"

	"github.com/vettid/vettid-agent/internal/nats"
)

// CatalogCache is a thread-safe in-memory cache of the secret catalog
// pushed from the vault.
type CatalogCache struct {
	mu      sync.RWMutex
	entries []nats.SecretCatalogEntry
	version uint64
	updated time.Time
}

// NewCatalogCache creates an empty catalog cache.
func NewCatalogCache() *CatalogCache {
	return &CatalogCache{}
}

// Update replaces the entire catalog atomically.
func (c *CatalogCache) Update(catalog *nats.SecretCatalog) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make([]nats.SecretCatalogEntry, len(catalog.Entries))
	copy(c.entries, catalog.Entries)
	c.version = catalog.Version
	c.updated = time.Now()
}

// List returns a copy of all catalog entries.
func (c *CatalogCache) List() []nats.SecretCatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]nats.SecretCatalogEntry, len(c.entries))
	copy(result, c.entries)
	return result
}

// ListByCategory returns entries matching the given category.
func (c *CatalogCache) ListByCategory(category string) []nats.SecretCatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []nats.SecretCatalogEntry
	for _, e := range c.entries {
		if e.Category == category {
			result = append(result, e)
		}
	}
	return result
}

// Get returns a catalog entry by secret ID, or nil if not found.
func (c *CatalogCache) Get(secretID string) *nats.SecretCatalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, e := range c.entries {
		if e.SecretID == secretID {
			entry := e
			return &entry
		}
	}
	return nil
}

// Version returns the current catalog version.
func (c *CatalogCache) Version() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// Count returns the number of entries in the catalog.
func (c *CatalogCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
