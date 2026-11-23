//go:build windows

package access

import (
	"testing"
	"time"
)

// monoNow reads QueryUnbiasedInterruptTime: it advances with Go's own
// clock while the computer is awake. (That it stops while asleep is the
// call's documented behavior; no sleep is tried here.)
func TestMonoNowAdvances(t *testing.T) {
	a, start := monoNow(), time.Now()
	time.Sleep(200 * time.Millisecond)
	d, want := monoNow()-a, time.Since(start)
	if d <= 0 || d < want-50*time.Millisecond || d > want+50*time.Millisecond {
		t.Fatalf("monoNow advanced %v over %v", d, want)
	}
}
