package antidetect

import (
	"math/rand"
	"time"
)

// TimingProfile represents realistic request timing patterns
type TimingProfile struct {
	MinDelay    time.Duration
	MaxDelay    time.Duration
	BurstSize   int
	BurstDelay  time.Duration
	ThinkTime   time.Duration
}

// GetRealisticTimingProfiles returns predefined timing profiles that mimic human behavior
func GetRealisticTimingProfiles() []TimingProfile {
	return []TimingProfile{
		{
			MinDelay:   500 * time.Millisecond,
			MaxDelay:   2 * time.Second,
			BurstSize:  3,
			BurstDelay: 100 * time.Millisecond,
			ThinkTime:  5 * time.Second,
		},
		{
			MinDelay:   1 * time.Second,
			MaxDelay:   3 * time.Second,
			BurstSize:  2,
			BurstDelay: 200 * time.Millisecond,
			ThinkTime:  8 * time.Second,
		},
		{
			MinDelay:   300 * time.Millisecond,
			MaxDelay:   1500 * time.Millisecond,
			BurstSize:  5,
			BurstDelay: 50 * time.Millisecond,
			ThinkTime:  3 * time.Second,
		},
	}
}

// GetRandomTimingProfile returns a random timing profile
func GetRandomTimingProfile() TimingProfile {
	profiles := GetRealisticTimingProfiles()
	rand.Seed(time.Now().UnixNano())
	return profiles[rand.Intn(len(profiles))]
}

// CalculateDelay calculates a realistic delay based on the timing profile
func (tp TimingProfile) CalculateDelay() time.Duration {
	rand.Seed(time.Now().UnixNano())
	
	// Random delay between min and max
	delayRange := tp.MaxDelay - tp.MinDelay
	randomDelay := time.Duration(rand.Int63n(int64(delayRange)))
	
	return tp.MinDelay + randomDelay
}

// CalculateBurstDelay calculates delay for burst requests
func (tp TimingProfile) CalculateBurstDelay() time.Duration {
	rand.Seed(time.Now().UnixNano())
	
	// Add some randomness to burst delay
	variance := time.Duration(rand.Int63n(int64(tp.BurstDelay / 2)))
	return tp.BurstDelay + variance
}

// CalculateThinkTime calculates think time between request groups
func (tp TimingProfile) CalculateThinkTime() time.Duration {
	rand.Seed(time.Now().UnixNano())
	
	// Add randomness to think time (±50%)
	variance := time.Duration(rand.Int63n(int64(tp.ThinkTime)))
	if rand.Intn(2) == 0 {
		return tp.ThinkTime + variance
	}
	return tp.ThinkTime - variance/2
}

// RequestTimer manages request timing to mimic human behavior
type RequestTimer struct {
	profile      TimingProfile
	requestCount int
	lastRequest  time.Time
	burstCount   int
}

// NewRequestTimer creates a new request timer with a random profile
func NewRequestTimer() *RequestTimer {
	return &RequestTimer{
		profile:     GetRandomTimingProfile(),
		lastRequest: time.Now(),
	}
}

// NewRequestTimerWithProfile creates a new request timer with a specific profile
func NewRequestTimerWithProfile(profile TimingProfile) *RequestTimer {
	return &RequestTimer{
		profile:     profile,
		lastRequest: time.Now(),
	}
}

// WaitForNextRequest waits for the appropriate time before the next request
func (rt *RequestTimer) WaitForNextRequest() {
	now := time.Now()
	
	var delay time.Duration
	
	// Check if we're in a burst
	if rt.burstCount < rt.profile.BurstSize {
		delay = rt.profile.CalculateBurstDelay()
		rt.burstCount++
	} else {
		// End of burst, use think time
		delay = rt.profile.CalculateThinkTime()
		rt.burstCount = 0
	}
	
	// Ensure we don't make requests too quickly
	timeSinceLastRequest := now.Sub(rt.lastRequest)
	if timeSinceLastRequest < delay {
		time.Sleep(delay - timeSinceLastRequest)
	}
	
	rt.lastRequest = time.Now()
	rt.requestCount++
}

// GetNextDelay returns the next delay without waiting
func (rt *RequestTimer) GetNextDelay() time.Duration {
	if rt.burstCount < rt.profile.BurstSize {
		return rt.profile.CalculateBurstDelay()
	}
	return rt.profile.CalculateThinkTime()
}

// Reset resets the timer state
func (rt *RequestTimer) Reset() {
	rt.requestCount = 0
	rt.burstCount = 0
	rt.lastRequest = time.Now()
}

// SetProfile changes the timing profile
func (rt *RequestTimer) SetProfile(profile TimingProfile) {
	rt.profile = profile
}

// GetStats returns timing statistics
func (rt *RequestTimer) GetStats() (int, time.Time) {
	return rt.requestCount, rt.lastRequest
}

// JitterDelay adds random jitter to a base delay
func JitterDelay(baseDelay time.Duration, jitterPercent float64) time.Duration {
	if jitterPercent <= 0 {
		return baseDelay
	}
	
	rand.Seed(time.Now().UnixNano())
	
	// Calculate jitter range
	jitterRange := float64(baseDelay) * jitterPercent / 100.0
	jitter := time.Duration(rand.Float64() * jitterRange)
	
	// Randomly add or subtract jitter
	if rand.Intn(2) == 0 {
		return baseDelay + jitter
	}
	
	result := baseDelay - jitter
	if result < 0 {
		result = baseDelay / 2
	}
	
	return result
}

// ExponentialBackoff calculates exponential backoff delay for retries
func ExponentialBackoff(attempt int, baseDelay time.Duration, maxDelay time.Duration) time.Duration {
	if attempt <= 0 {
		return baseDelay
	}
	
	// Calculate exponential delay: baseDelay * 2^attempt
	delay := baseDelay
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
			break
		}
	}
	
	// Add jitter to avoid thundering herd
	return JitterDelay(delay, 25.0)
}

// RandomDelay generates a random delay within a range
func RandomDelay(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	
	rand.Seed(time.Now().UnixNano())
	diff := max - min
	randomDiff := time.Duration(rand.Int63n(int64(diff)))
	
	return min + randomDiff
}

// SleepWithJitter sleeps for a duration with added jitter
func SleepWithJitter(duration time.Duration, jitterPercent float64) {
	delay := JitterDelay(duration, jitterPercent)
	time.Sleep(delay)
}

// PageLoadDelay simulates realistic page load timing
func PageLoadDelay() time.Duration {
	// Simulate realistic page load times (500ms to 3s)
	return RandomDelay(500*time.Millisecond, 3*time.Second)
}

// ResourceLoadDelay simulates realistic resource load timing
func ResourceLoadDelay() time.Duration {
	// Simulate realistic resource load times (100ms to 1s)
	return RandomDelay(100*time.Millisecond, 1*time.Second)
}
