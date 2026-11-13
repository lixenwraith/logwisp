package tokenbucket

import "testing"

// A bucket holds at least one token, whatever its capacity: below one it
// would admit nothing, ever, where a rate under 1/s means one at a time
func TestBucketBelowOneTokenStillAdmitsOne(t *testing.T) {
	for _, capacity := range []float64{0, 0.5} {
		b := New(capacity, 0.5)
		if !b.Allow() {
			t.Errorf("capacity %v: the first attempt was refused", capacity)
		}
		if b.Allow() {
			t.Errorf("capacity %v: a second attempt passed at once", capacity)
		}
	}
}
