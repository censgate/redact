package strategies

import (
	"math/rand"
	"sync"
	"time"
)

// sharedRNG provides a thread-safe random number generator that is seeded once
var (
	sharedRNG *rand.Rand
	rngOnce   sync.Once
)

// getRNG returns a shared random number generator that is initialized once
// This prevents the poor randomness issues caused by repeated seeding
func getRNG() *rand.Rand {
	rngOnce.Do(func() {
		sharedRNG = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	return sharedRNG
}

// randInt returns a random integer in the range [0, n)
func randInt(n int) int {
	return getRNG().Intn(n)
}

// randIntRange returns a random integer in the range [min, max)
func randIntRange(minVal, maxVal int) int {
	return getRNG().Intn(maxVal-minVal) + minVal
}
