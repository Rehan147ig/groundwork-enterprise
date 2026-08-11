// Phase 8.2 connection pooling: all outbound HTTP dependencies
// (spicedb, connector gateway, webhook delivery) share the same
// configurable transport settings so a slow dependency cannot
// multiply connections unbounded.

package httpclient

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func TestDefaultPoolSanity(t *testing.T) {
	p := DefaultPool()
	if p.MaxIdleConns != 100 || p.MaxIdleConnsPerHost != 20 {
		t.Fatalf("default pool: %+v", p)
	}
	if p.IdleConnTimeout <= 0 {
		t.Fatalf("idle timeout must be positive: %+v", p)
	}
	if tr := p.Transport(); tr.MaxIdleConns != p.MaxIdleConns || tr.MaxIdleConnsPerHost != p.MaxIdleConnsPerHost {
		t.Fatalf("transport must reflect pool settings: %+v", tr)
	}
}

func TestPoolFromEnv(t *testing.T) {
	os.Setenv("GW_HTTP_POOL_MAX_IDLE", "7")
	os.Setenv("GW_HTTP_POOL_PER_HOST", "3")
	os.Setenv("GW_HTTP_POOL_IDLE_MS", "5000")
	t.Cleanup(func() {
		os.Unsetenv("GW_HTTP_POOL_MAX_IDLE")
		os.Unsetenv("GW_HTTP_POOL_PER_HOST")
		os.Unsetenv("GW_HTTP_POOL_IDLE_MS")
	})

	p := PoolFromEnv("GW_HTTP_POOL", DefaultPool())
	if p.MaxIdleConns != 7 || p.MaxIdleConnsPerHost != 3 {
		t.Fatalf("env overrides not applied: %+v", p)
	}
	if p.IdleConnTimeout != 5*time.Second {
		t.Fatalf("idle timeout from env: %v", p.IdleConnTimeout)
	}
}

func TestPoolFromEnvDefaultsWhenUnset(t *testing.T) {
	os.Unsetenv("GW_HTTP_POOL_MAX_IDLE")
	os.Unsetenv("GW_HTTP_POOL_PER_HOST")
	os.Unsetenv("GW_HTTP_POOL_IDLE_MS")
	p := PoolFromEnv("GW_HTTP_POOL", DefaultPool())
	if p != DefaultPool() {
		t.Fatalf("unset env must leave defaults: %+v", p)
	}
}

func TestPoolClientHonorsTimeout(t *testing.T) {
	p := DefaultPool()
	c := p.Client(2 * time.Second)
	if c.Timeout != 2*time.Second {
		t.Fatalf("client timeout: %v", c.Timeout)
	}
	if c.Transport == nil {
		t.Fatal("pooled client must carry the pooled transport")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type: %T", c.Transport)
	}
	if tr.MaxIdleConnsPerHost != p.MaxIdleConnsPerHost {
		t.Fatalf("client must use the pool transport: %+v", tr)
	}
}
