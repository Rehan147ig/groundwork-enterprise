// Package httpclient centralizes the outbound HTTP client pool
// configuration for the runtime's external dependencies (Qdrant,
// Elasticsearch, the embedding service, SpiceDB, and the outbox
// webhook). Default Go clients use the zero-value http.Transport:
// unbounded idle connections per host and no tuning — under load the
// process can hold far more sockets than it needs. A shared, env-tunable
// pool keeps every dependency's connection usage bounded and warm
// (Roadmap 8.1/8.2: connection pool configuration and overload
// protection).
package httpclient

import (
	"net/http"
	"os"
	"strconv"
	"time"
)

// PoolConfig sizes the shared http.Transport pool.
type PoolConfig struct {
	// MaxIdleConns caps idle connections across all hosts. 0 = no cap
	// (see WithDefaults).
	MaxIdleConns int
	// MaxIdleConnsPerHost caps idle connections per remote host.
	MaxIdleConnsPerHost int
	// IdleConnTimeout closes idle connections after this long.
	IdleConnTimeout time.Duration
}

// DefaultPool returns the production pool sizing. Keep-alive lets a
// small steady-state pool carry high QPS without churning sockets:
//
//	MaxIdleConns         100  — total idle ceiling across dependencies
//	MaxIdleConnsPerHost   20  — per-dependency keep-alive warmth
//	IdleConnTimeout      90s  — recycle idle sockets; load balancers
//	                            and proxies can stale them
func DefaultPool() PoolConfig {
	return PoolConfig{MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 90 * time.Second}
}

// PoolFromEnv overlays a pool config with GROUNDWORK_HTTP_POOL_* env
// vars (MAX_IDLE, PER_HOST, IDLE_MS). Invalid values fall back to the
// given defaults so a typo never silently disables pooling.
func PoolFromEnv(prefix string, base PoolConfig) PoolConfig {
	if v := envInt(os.Getenv(prefix + "_MAX_IDLE")); v > 0 {
		base.MaxIdleConns = v
	}
	if v := envInt(os.Getenv(prefix + "_PER_HOST")); v > 0 {
		base.MaxIdleConnsPerHost = v
	}
	if v := envInt(os.Getenv(prefix + "_IDLE_MS")); v > 0 {
		base.IdleConnTimeout = time.Duration(v) * time.Millisecond
	}
	return base
}

func envInt(v string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// Transport builds the pooled http.Transport.
func (p PoolConfig) Transport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        p.MaxIdleConns,
		MaxIdleConnsPerHost: p.MaxIdleConnsPerHost,
		IdleConnTimeout:     p.IdleConnTimeout,
	}
}

// Client returns a pooled client with the given request timeout.
func (p PoolConfig) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: p.Transport()}
}
