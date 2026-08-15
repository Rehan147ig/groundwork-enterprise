package runtime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"
)

type retryConfig struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
}

// cryptoJitter returns a uniform jitter in [0, n) drawn from crypto/rand.
// math/rand is deliberately avoided here: retry timing must not be
// predictable to an observer (predictable backoff would let an attacker
// time ACL-sync or circuit-breaker windows). On the astronomically rare
// entropy read failure it degrades to full delay (zero jitter) rather
// than failing the request.
func cryptoJitter(n int64) time.Duration {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return time.Duration(n)
	}
	return time.Duration(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}

func retryWithBackoff(ctx context.Context, cfg retryConfig, fn func() error) error {
	if cfg.Attempts <= 0 {
		cfg.Attempts = 3
	}
	if cfg.Base <= 0 {
		cfg.Base = 50 * time.Millisecond
	}
	if cfg.Max <= 0 {
		cfg.Max = 500 * time.Millisecond
	}
	var last error
	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		if err := fn(); err != nil {
			last = err
			if attempt == cfg.Attempts-1 {
				break
			}
			delay := cfg.Base << attempt
			if delay > cfg.Max {
				delay = cfg.Max
			}
			jitter := cryptoJitter(int64(delay / 2))
			timer := time.NewTimer(delay + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		return nil
	}
	return last
}
