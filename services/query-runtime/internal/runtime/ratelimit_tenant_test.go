package runtime

import (
	"sync"
	"testing"
	"time"
)

func TestTenantRateLimiterFixedWindow(t *testing.T) {
	rl := NewTenantRateLimiterWindow(2, time.Minute)

	if ok, _ := rl.Allow("tenant-a"); !ok {
		t.Fatal("request 1 should be allowed")
	}
	if ok, _ := rl.Allow("tenant-a"); !ok {
		t.Fatal("request 2 should be allowed")
	}
	ok, retry := rl.Allow("tenant-a")
	if ok {
		t.Fatal("request 3 should be blocked")
	}
	if retry <= 0 {
		t.Fatalf("blocked request should report a positive retry-after, got %v", retry)
	}

	if ok, _ := rl.Allow("tenant-b"); !ok {
		t.Fatal("a different tenant must not be affected by tenant-a's budget")
	}
}

func TestTenantRateLimiterUnlimitedAndNil(t *testing.T) {
	rl := NewTenantRateLimiter(0)
	for i := 0; i < 100; i++ {
		if ok, _ := rl.Allow("tenant-a"); !ok {
			t.Fatal("rpm=0 must be unlimited")
		}
	}
	var nilRL *TenantRateLimiter
	if ok, _ := nilRL.Allow("tenant-a"); !ok {
		t.Fatal("a nil limiter must allow (no enforcement configured)")
	}
}

func TestTenantRateLimiterWindowReset(t *testing.T) {
	rl := NewTenantRateLimiterWindow(1, 30*time.Millisecond)
	if ok, _ := rl.Allow("tenant-a"); !ok {
		t.Fatal("first request should be allowed")
	}
	if ok, _ := rl.Allow("tenant-a"); ok {
		t.Fatal("second request within the window should be blocked")
	}
	time.Sleep(40 * time.Millisecond)
	if ok, _ := rl.Allow("tenant-a"); !ok {
		t.Fatal("request after the window resets should be allowed")
	}
}

func TestTenantConcurrencyLimiter(t *testing.T) {
	cl := NewTenantConcurrencyLimiter(2)

	release1, ok := cl.Acquire("tenant-a")
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	release2, ok := cl.Acquire("tenant-a")
	if !ok {
		t.Fatal("second acquire should succeed")
	}
	if _, ok := cl.Acquire("tenant-a"); ok {
		t.Fatal("third acquire should be rejected at the cap")
	}
	if _, ok := cl.Acquire("tenant-b"); !ok {
		t.Fatal("a different tenant must not be affected")
	}

	release2()
	if _, ok := cl.Acquire("tenant-a"); !ok {
		t.Fatal("acquire after release should succeed")
	}
	release1()
}

func TestTenantConcurrencyLimiterUnlimitedAndNil(t *testing.T) {
	cl := NewTenantConcurrencyLimiter(0)
	for i := 0; i < 100; i++ {
		release, ok := cl.Acquire("tenant-a")
		if !ok {
			t.Fatal("limit<=0 must be unlimited")
		}
		release()
	}
	var nilCL *TenantConcurrencyLimiter
	if release, ok := nilCL.Acquire("tenant-a"); !ok {
		t.Fatal("a nil limiter must allow")
	} else {
		release()
	}
}

// Concurrent acquires from many goroutines must never exceed the cap.
func TestTenantConcurrencyLimiterStress(t *testing.T) {
	cl := NewTenantConcurrencyLimiter(3)
	const workers = 20
	var mu sync.Mutex
	inFlight := 0
	maxInFlight := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if release, ok := cl.Acquire("tenant-a"); ok {
					mu.Lock()
					inFlight++
					if inFlight > maxInFlight {
						maxInFlight = inFlight
					}
					mu.Unlock()
					time.Sleep(time.Microsecond)
					mu.Lock()
					inFlight--
					mu.Unlock()
					release()
				}
			}
		}()
	}
	wg.Wait()
	if maxInFlight > 3 {
		t.Fatalf("observed %d concurrent requests, cap is 3", maxInFlight)
	}
}
