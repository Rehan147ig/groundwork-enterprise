package policy

import (
	"context"
	"testing"
)

func TestPolicyCachePingHealthy(t *testing.T) {
	c := NewPolicyCache(DefaultCacheConfig())
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("expected healthy ping, got %v", err)
	}
}

func TestPolicyCachePingZeroValue(t *testing.T) {
	var c *PolicyCache
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected nil receiver ping to fail")
	}
}

func TestPolicyCachePingUninitialized(t *testing.T) {
	c := &PolicyCache{}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected zero-value cache ping to fail")
	}
}
