package antidetect

import (
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// RequestPattern represents a pattern of HTTP requests
type RequestPattern struct {
	Name        string
	Description string
	Requests    []PatternRequest
	Timing      PatternTiming
}

// PatternRequest represents a single request in a pattern
type PatternRequest struct {
	Method      string
	Path        string
	Headers     map[string]string
	Body        string
	Delay       time.Duration
	Priority    int
	Optional    bool
}

// PatternTiming controls timing between requests in a pattern
type PatternTiming struct {
	BaseDelay    time.Duration
	RandomJitter time.Duration
	ThinkTime    time.Duration
}

// BrowserRequestPatterns contains realistic browser request patterns
var BrowserRequestPatterns = map[string][]RequestPattern{
	"page_load": {
		{
			Name:        "Initial Page Load",
			Description: "Typical browser page load sequence",
			Requests: []PatternRequest{
				{
					Method:   "GET",
					Path:     "/",
					Headers:  map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
					Priority: 1,
				},
				{
					Method:   "GET",
					Path:     "/favicon.ico",
					Headers:  map[string]string{"Accept": "image/webp,image/apng,image/*,*/*;q=0.8"},
					Delay:    100 * time.Millisecond,
					Priority: 3,
					Optional: true,
				},
				{
					Method:   "GET",
					Path:     "/robots.txt",
					Headers:  map[string]string{"Accept": "text/plain,*/*;q=0.8"},
					Delay:    200 * time.Millisecond,
					Priority: 4,
					Optional: true,
				},
			},
			Timing: PatternTiming{
				BaseDelay:    50 * time.Millisecond,
				RandomJitter: 100 * time.Millisecond,
				ThinkTime:    2 * time.Second,
			},
		},
	},
	"resource_load": {
		{
			Name:        "Resource Loading",
			Description: "Loading CSS, JS, and images",
			Requests: []PatternRequest{
				{
					Method:   "GET",
					Path:     "/css/style.css",
					Headers:  map[string]string{"Accept": "text/css,*/*;q=0.1"},
					Priority: 2,
				},
				{
					Method:   "GET",
					Path:     "/js/app.js",
					Headers:  map[string]string{"Accept": "*/*"},
					Delay:    50 * time.Millisecond,
					Priority: 2,
				},
				{
					Method:   "GET",
					Path:     "/images/logo.png",
					Headers:  map[string]string{"Accept": "image/webp,image/apng,image/*,*/*;q=0.8"},
					Delay:    100 * time.Millisecond,
					Priority: 3,
				},
			},
			Timing: PatternTiming{
				BaseDelay:    25 * time.Millisecond,
				RandomJitter: 50 * time.Millisecond,
				ThinkTime:    500 * time.Millisecond,
			},
		},
	},
	"api_calls": {
		{
			Name:        "API Interaction",
			Description: "Typical API call patterns",
			Requests: []PatternRequest{
				{
					Method:   "GET",
					Path:     "/api/user",
					Headers:  map[string]string{"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
					Priority: 1,
				},
				{
					Method:   "GET",
					Path:     "/api/config",
					Headers:  map[string]string{"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
					Delay:    200 * time.Millisecond,
					Priority: 2,
				},
			},
			Timing: PatternTiming{
				BaseDelay:    100 * time.Millisecond,
				RandomJitter: 200 * time.Millisecond,
				ThinkTime:    1 * time.Second,
			},
		},
	},
}

// RequestPatternExecutor executes request patterns
type RequestPatternExecutor struct {
	client   *http.Client
	baseURL  string
	patterns map[string][]RequestPattern
}

// NewRequestPatternExecutor creates a new request pattern executor
func NewRequestPatternExecutor(client *http.Client, baseURL string) *RequestPatternExecutor {
	return &RequestPatternExecutor{
		client:   client,
		baseURL:  baseURL,
		patterns: BrowserRequestPatterns,
	}
}

// ExecutePattern executes a specific request pattern
func (rpe *RequestPatternExecutor) ExecutePattern(patternType string, patternIndex int) error {
	patterns, exists := rpe.patterns[patternType]
	if !exists || patternIndex >= len(patterns) {
		return nil // Pattern not found, skip silently
	}

	pattern := patterns[patternIndex]
	
	for _, req := range pattern.Requests {
		// Apply delay
		if req.Delay > 0 {
			time.Sleep(req.Delay)
		}

		// Apply pattern timing
		delay := pattern.Timing.BaseDelay
		if pattern.Timing.RandomJitter > 0 {
			jitter := time.Duration(rand.Int63n(int64(pattern.Timing.RandomJitter)))
			delay += jitter
		}
		time.Sleep(delay)

		// Execute request
		err := rpe.executeRequest(req)
		if err != nil && !req.Optional {
			return err
		}
	}

	// Apply think time after pattern completion
	if pattern.Timing.ThinkTime > 0 {
		time.Sleep(pattern.Timing.ThinkTime)
	}

	return nil
}

// executeRequest executes a single request
func (rpe *RequestPatternExecutor) executeRequest(req PatternRequest) error {
	url := rpe.baseURL + req.Path
	
	var body strings.Reader
	if req.Body != "" {
		body = *strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, url, &body)
	if err != nil {
		return err
	}

	// Set headers
	for header, value := range req.Headers {
		httpReq.Header.Set(header, value)
	}

	// Execute request
	resp, err := rpe.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// GetRandomPattern returns a random pattern of a specific type
func (rpe *RequestPatternExecutor) GetRandomPattern(patternType string) *RequestPattern {
	patterns, exists := rpe.patterns[patternType]
	if !exists || len(patterns) == 0 {
		return nil
	}

	rand.Seed(time.Now().UnixNano())
	return &patterns[rand.Intn(len(patterns))]
}

// AddCustomPattern adds a custom request pattern
func (rpe *RequestPatternExecutor) AddCustomPattern(patternType string, pattern RequestPattern) {
	if rpe.patterns[patternType] == nil {
		rpe.patterns[patternType] = make([]RequestPattern, 0)
	}
	rpe.patterns[patternType] = append(rpe.patterns[patternType], pattern)
}

// BehaviorSimulator simulates realistic browsing behavior
type BehaviorSimulator struct {
	executor    *RequestPatternExecutor
	userProfile UserProfile
}

// UserProfile represents different user behavior profiles
type UserProfile struct {
	Name            string
	ReadingSpeed    time.Duration // Time spent reading content
	ClickFrequency  time.Duration // Time between clicks
	ScrollBehavior  ScrollBehavior
	NavigationStyle NavigationStyle
}

// ScrollBehavior represents scrolling patterns
type ScrollBehavior struct {
	ScrollSpeed time.Duration
	PauseTime   time.Duration
	Direction   string // "down", "up", "random"
}

// NavigationStyle represents navigation patterns
type NavigationStyle struct {
	BackButtonUsage  float64 // Probability of using back button
	NewTabUsage      float64 // Probability of opening new tabs
	BookmarkUsage    float64 // Probability of bookmarking
}

// Predefined user profiles
var UserProfiles = map[string]UserProfile{
	"casual": {
		Name:         "Casual User",
		ReadingSpeed: 3 * time.Second,
		ClickFrequency: 5 * time.Second,
		ScrollBehavior: ScrollBehavior{
			ScrollSpeed: 500 * time.Millisecond,
			PauseTime:   2 * time.Second,
			Direction:   "down",
		},
		NavigationStyle: NavigationStyle{
			BackButtonUsage: 0.3,
			NewTabUsage:     0.2,
			BookmarkUsage:   0.1,
		},
	},
	"power": {
		Name:         "Power User",
		ReadingSpeed: 1 * time.Second,
		ClickFrequency: 2 * time.Second,
		ScrollBehavior: ScrollBehavior{
			ScrollSpeed: 200 * time.Millisecond,
			PauseTime:   500 * time.Millisecond,
			Direction:   "random",
		},
		NavigationStyle: NavigationStyle{
			BackButtonUsage: 0.5,
			NewTabUsage:     0.7,
			BookmarkUsage:   0.3,
		},
	},
	"researcher": {
		Name:         "Researcher",
		ReadingSpeed: 10 * time.Second,
		ClickFrequency: 8 * time.Second,
		ScrollBehavior: ScrollBehavior{
			ScrollSpeed: 1 * time.Second,
			PauseTime:   5 * time.Second,
			Direction:   "down",
		},
		NavigationStyle: NavigationStyle{
			BackButtonUsage: 0.7,
			NewTabUsage:     0.8,
			BookmarkUsage:   0.5,
		},
	},
}

// NewBehaviorSimulator creates a new behavior simulator
func NewBehaviorSimulator(executor *RequestPatternExecutor, profileName string) *BehaviorSimulator {
	profile, exists := UserProfiles[profileName]
	if !exists {
		profile = UserProfiles["casual"] // Default to casual
	}

	return &BehaviorSimulator{
		executor:    executor,
		userProfile: profile,
	}
}

// SimulatePageVisit simulates a realistic page visit
func (bs *BehaviorSimulator) SimulatePageVisit() error {
	// Execute page load pattern
	err := bs.executor.ExecutePattern("page_load", 0)
	if err != nil {
		return err
	}

	// Simulate reading time
	time.Sleep(bs.userProfile.ReadingSpeed)

	// Execute resource loading pattern
	err = bs.executor.ExecutePattern("resource_load", 0)
	if err != nil {
		return err
	}

	// Simulate scrolling behavior
	bs.simulateScrolling()

	// Possibly execute API calls
	if rand.Float64() < 0.3 { // 30% chance of API interaction
		err = bs.executor.ExecutePattern("api_calls", 0)
		if err != nil {
			return err
		}
	}

	return nil
}

// simulateScrolling simulates realistic scrolling behavior
func (bs *BehaviorSimulator) simulateScrolling() {
	scrollCount := 1 + rand.Intn(5) // 1-5 scroll actions
	
	for i := 0; i < scrollCount; i++ {
		time.Sleep(bs.userProfile.ScrollBehavior.ScrollSpeed)
		
		// Simulate pause while reading
		time.Sleep(bs.userProfile.ScrollBehavior.PauseTime)
	}
}

// SimulateBrowsingSession simulates a complete browsing session
func (bs *BehaviorSimulator) SimulateBrowsingSession(pageCount int) error {
	for i := 0; i < pageCount; i++ {
		err := bs.SimulatePageVisit()
		if err != nil {
			return err
		}

		// Simulate navigation delay between pages
		navigationDelay := bs.userProfile.ClickFrequency
		if rand.Float64() < 0.2 { // 20% chance of longer delay
			navigationDelay *= 3
		}
		time.Sleep(navigationDelay)
	}

	return nil
}

// GetRealisticHeaders returns headers that match the user profile
func (bs *BehaviorSimulator) GetRealisticHeaders() map[string]string {
	headers := make(map[string]string)
	
	// Add headers based on user profile
	switch bs.userProfile.Name {
	case "Power User":
		headers["DNT"] = "1"
		headers["Upgrade-Insecure-Requests"] = "1"
	case "Researcher":
		headers["Accept-Language"] = "en-US,en;q=0.9,es;q=0.8"
		headers["Cache-Control"] = "no-cache"
	default:
		headers["Accept-Language"] = "en-US,en;q=0.9"
	}
	
	return headers
}

// AdaptiveBehavior adjusts behavior based on response patterns
type AdaptiveBehavior struct {
	simulator     *BehaviorSimulator
	responseStats map[int]int // Status code -> count
	adaptations   int
}

// NewAdaptiveBehavior creates a new adaptive behavior simulator
func NewAdaptiveBehavior(simulator *BehaviorSimulator) *AdaptiveBehavior {
	return &AdaptiveBehavior{
		simulator:     simulator,
		responseStats: make(map[int]int),
	}
}

// RecordResponse records a response for adaptation
func (ab *AdaptiveBehavior) RecordResponse(statusCode int) {
	ab.responseStats[statusCode]++
	
	// Adapt behavior based on response patterns
	if ab.responseStats[429] > 3 { // Too many rate limits
		ab.adaptToRateLimit()
	} else if ab.responseStats[403] > 2 { // Too many blocks
		ab.adaptToBlocking()
	}
}

// adaptToRateLimit adapts behavior to avoid rate limiting
func (ab *AdaptiveBehavior) adaptToRateLimit() {
	profile := &ab.simulator.userProfile
	
	// Increase delays
	profile.ReadingSpeed *= 2
	profile.ClickFrequency *= 2
	profile.ScrollBehavior.PauseTime *= 2
	
	ab.adaptations++
}

// adaptToBlocking adapts behavior to avoid blocking
func (ab *AdaptiveBehavior) adaptToBlocking() {
	profile := &ab.simulator.userProfile
	
	// Make behavior more human-like
	profile.ReadingSpeed += 2 * time.Second
	profile.ClickFrequency += 3 * time.Second
	profile.ScrollBehavior.ScrollSpeed += 200 * time.Millisecond
	
	ab.adaptations++
}
