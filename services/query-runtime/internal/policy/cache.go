package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// CacheConfig tunes the L1 decision cache.
type CacheConfig struct {
	// PosTTL is how long an allowed decision is cached.
	PosTTL time.Duration
	// NegTTL is how long a denied decision is cached. Kept shorter than
	// PosTTL so newly granted access takes effect quickly.
	NegTTL time.Duration
	// MaxEntries bounds the cache; the oldest entries are evicted.
	MaxEntries int
}

// DefaultCacheConfig: allowed decisions live 60s, denied decisions 20s.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{PosTTL: 60 * time.Second, NegTTL: 20 * time.Second, MaxEntries: 100_000}
}

type cacheEntry struct {
	allowed   bool
	source    DecisionSource
	ruleID    string
	expiresAt time.Time
	order     uint64
	tenantID  string
	userID    string
	docID     string
	scope     string
}

// PolicyCache is a bounded, TTL'd decision cache. Invalidation removes
// entries immediately so privilege revocation takes effect on the next
// request (< 1s), not at TTL expiry. Entries retain their (tenant,
// user, document, scope) fields so invalidation can match precisely
// without relying on hash-key structure.
type PolicyCache struct {
	cfg CacheConfig
	now func() time.Time

	mu      sync.RWMutex
	entries map[string]cacheEntry
	order   uint64

	hits          uint64
	misses        uint64
	stored        uint64
	evictions     uint64
	invalidations uint64
}

// NewPolicyCache builds an L1 decision cache.
func NewPolicyCache(cfg CacheConfig) *PolicyCache {
	return &PolicyCache{cfg: cfg, now: time.Now, entries: map[string]cacheEntry{}}
}

// Key is the cache key: sha256 over (tenant, user, region, doc, scope,
// owner tags). Region is folded in so a region migration can never
// serve a decision computed under another region.
func Key(tenantID, userID, region, docID, scope string, ownerTags []string) string {
	sum := sha256.New()
	for _, part := range []string{tenantID, userID, region, docID, scope} {
		_, _ = sum.Write([]byte(part))
		_, _ = sum.Write([]byte{0})
	}
	for _, tag := range ownerTags {
		_, _ = sum.Write([]byte(tag))
		_, _ = sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// Get returns the cached decision if present and unexpired.
func (c *PolicyCache) Get(key string) (Decision, bool) {
	now := c.now()
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		c.recordMiss()
		return Decision{}, false
	}
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.evictions++
		c.misses++
		c.mu.Unlock()
		return Decision{}, false
	}
	c.recordHit()
	return Decision{
		Allowed: entry.allowed,
		Source:  entry.source,
		RuleID:  entry.ruleID,
		Reason:  "l1_cache",
	}, true
}

// Put stores a decision. When the cache is full, expired entries are
// dropped first, then the oldest are evicted to make room.
func (c *PolicyCache) Put(key string, decision Decision, ttl time.Duration, tenantID, userID, docID, scope string) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; exists {
		return // never overwrite a live entry (keeps order stable)
	}
	if len(c.entries) >= c.cfg.MaxEntries {
		c.evictExpiredLocked()
	}
	if len(c.entries) >= c.cfg.MaxEntries {
		c.evictOldestLocked(len(c.entries)/4 + 1)
	}
	c.order++
	c.entries[key] = cacheEntry{
		allowed:   decision.Allowed,
		source:    decision.Source,
		ruleID:    decision.RuleID,
		expiresAt: c.now().Add(ttl),
		order:     c.order,
		tenantID:  tenantID,
		userID:    userID,
		docID:     docID,
		scope:     scope,
	}
	c.stored++
}

// InvalidateObject drops every cached decision for a document or
// folder. Used by document-grant revocations.
func (c *PolicyCache) InvalidateObject(docID string) {
	if docID == "" {
		return
	}
	c.invalidate(func(e cacheEntry) bool { return e.docID == docID })
}

// InvalidateUser drops every cached decision involving a user. Used by
// terminations and role revocations.
func (c *PolicyCache) InvalidateUser(userID string) {
	if userID == "" {
		return
	}
	c.invalidate(func(e cacheEntry) bool { return e.userID == userID })
}

// InvalidateTenant drops every cached decision for a tenant. Used by
// bulk changes and group-membership events (whose member sets are not
// tracked per cache entry).
func (c *PolicyCache) InvalidateTenant(tenantID string) {
	if tenantID == "" {
		return
	}
	c.invalidate(func(e cacheEntry) bool { return e.tenantID == tenantID })
}

// InvalidateAll empties the cache.
func (c *PolicyCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidations += uint64(len(c.entries))
	c.entries = map[string]cacheEntry{}
}

func (c *PolicyCache) invalidate(match func(cacheEntry) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if match(entry) {
			delete(c.entries, key)
			c.invalidations++
		}
	}
}

func (c *PolicyCache) recordHit() {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
}

func (c *PolicyCache) recordMiss() {
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
}

// Stats summarizes cache behavior.
type Stats struct {
	Hits          uint64  `json:"hits"`
	Misses        uint64  `json:"misses"`
	Stored        uint64  `json:"stored"`
	Evictions     uint64  `json:"evictions"`
	Invalidations uint64  `json:"invalidations"`
	HitRate       float64 `json:"hit_rate"`
}

func (c *PolicyCache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := c.hits + c.misses
	rate := 0.0
	if total > 0 {
		rate = float64(c.hits) / float64(total)
	}
	return Stats{
		Hits: c.hits, Misses: c.misses, Stored: c.stored,
		Evictions: c.evictions, Invalidations: c.invalidations, HitRate: rate,
	}
}

func (c *PolicyCache) evictExpiredLocked() {
	now := c.now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			c.evictions++
		}
	}
}

// evictOldestLocked deletes the `count` entries with the smallest
// insertion order (true LRU insertion order).
func (c *PolicyCache) evictOldestLocked(count int) {
	keys := make([]string, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return c.entries[keys[i]].order < c.entries[keys[j]].order
	})
	for _, key := range keys[:min(count, len(keys))] {
		delete(c.entries, key)
		c.evictions++
	}
}
