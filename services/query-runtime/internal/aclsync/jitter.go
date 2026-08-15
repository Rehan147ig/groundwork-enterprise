package aclsync

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// cryptoJitter returns a uniform delay in [0, n) drawn from crypto/rand
// so retry/backoff timing is never predictable to an observer (a
// predictable sync window could allow an attacker to race ACL-sync
// reconciliation). math/rand is deliberately not used. On the rare
// entropy read failure it degrades to the full delay (zero jitter)
// rather than failing.
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
