package antidetect

import (
	"fmt"
	"math"
	"net/http"
	"time"
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxRetries      int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	JitterPercent   float64
	RetryableErrors []int
	RetryableStatus []int
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:    3,
		BaseDelay:     1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		JitterPercent: 10.0,
		RetryableErrors: []int{
			// Network errors that might be temporary
		},
		RetryableStatus: []int{
			429, // Too Many Requests
			500, // Internal Server Error
			502, // Bad Gateway
			503, // Service Unavailable
			504, // Gateway Timeout
			520, // Cloudflare: Unknown Error
			521, // Cloudflare: Web Server Is Down
			522, // Cloudflare: Connection Timed Out
			523, // Cloudflare: Origin Is Unreachable
			524, // Cloudflare: A Timeout Occurred
			525, // Cloudflare: SSL Handshake Failed
			526, // Cloudflare: Invalid SSL Certificate
			527, // Cloudflare: Railgun Error
			530, // Cloudflare: Origin DNS Error
		},
	}
}

// RetryableRequest represents a request that can be retried
type RetryableRequest struct {
	Request     *http.Request
	Client      *http.Client
	Config      *RetryConfig
	OnRetry     func(attempt int, err error, resp *http.Response)
	OnSuccess   func(resp *http.Response)
	OnFailure   func(err error)
}

// Execute executes the request with retry logic
func (rr *RetryableRequest) Execute() (*http.Response, error) {
	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt <= rr.Config.MaxRetries; attempt++ {
		// Clone the request for each attempt
		req := rr.cloneRequest()
		
		// Execute the request
		resp, err := rr.Client.Do(req)
		
		// Check if we should retry
		if !rr.shouldRetry(attempt, err, resp) {
			if err == nil && rr.OnSuccess != nil {
				rr.OnSuccess(resp)
			}
			return resp, err
		}

		// Store the last error and response
		lastErr = err
		if lastResp != nil && lastResp.Body != nil {
			lastResp.Body.Close()
		}
		lastResp = resp

		// Call retry callback
		if rr.OnRetry != nil {
			rr.OnRetry(attempt, err, resp)
		}

		// Don't sleep after the last attempt
		if attempt < rr.Config.MaxRetries {
			delay := rr.calculateDelay(attempt)
			time.Sleep(delay)
		}
	}

	// All retries exhausted
	if rr.OnFailure != nil {
		rr.OnFailure(lastErr)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("request failed after %d retries: %v", rr.Config.MaxRetries, lastErr)
	}

	return lastResp, nil
}

// shouldRetry determines if a request should be retried
func (rr *RetryableRequest) shouldRetry(attempt int, err error, resp *http.Response) bool {
	// Don't retry if we've exceeded max retries
	if attempt >= rr.Config.MaxRetries {
		return false
	}

	// Retry on network errors
	if err != nil {
		return true
	}

	// Retry on specific status codes
	if resp != nil {
		for _, code := range rr.Config.RetryableStatus {
			if resp.StatusCode == code {
				return true
			}
		}
	}

	return false
}

// calculateDelay calculates the delay for the next retry
func (rr *RetryableRequest) calculateDelay(attempt int) time.Duration {
	// Exponential backoff
	delay := float64(rr.Config.BaseDelay) * math.Pow(rr.Config.BackoffFactor, float64(attempt))
	
	// Apply maximum delay
	if delay > float64(rr.Config.MaxDelay) {
		delay = float64(rr.Config.MaxDelay)
	}

	// Add jitter
	if rr.Config.JitterPercent > 0 {
		jitter := delay * rr.Config.JitterPercent / 100.0
		delay += (2*jitter*float64(time.Now().UnixNano()%1000)/1000.0 - jitter)
	}

	return time.Duration(delay)
}

// cloneRequest creates a copy of the HTTP request
func (rr *RetryableRequest) cloneRequest() *http.Request {
	req := rr.Request.Clone(rr.Request.Context())
	return req
}

// RetryClient wraps an HTTP client with retry functionality
type RetryClient struct {
	client *http.Client
	config *RetryConfig
}

// NewRetryClient creates a new retry client
func NewRetryClient(client *http.Client, config *RetryConfig) *RetryClient {
	if config == nil {
		config = DefaultRetryConfig()
	}
	
	return &RetryClient{
		client: client,
		config: config,
	}
}

// Do executes an HTTP request with retry logic
func (rc *RetryClient) Do(req *http.Request) (*http.Response, error) {
	retryableReq := &RetryableRequest{
		Request: req,
		Client:  rc.client,
		Config:  rc.config,
	}
	
	return retryableReq.Execute()
}

// DoWithCallbacks executes an HTTP request with retry logic and callbacks
func (rc *RetryClient) DoWithCallbacks(
	req *http.Request,
	onRetry func(attempt int, err error, resp *http.Response),
	onSuccess func(resp *http.Response),
	onFailure func(err error),
) (*http.Response, error) {
	retryableReq := &RetryableRequest{
		Request:   req,
		Client:    rc.client,
		Config:    rc.config,
		OnRetry:   onRetry,
		OnSuccess: onSuccess,
		OnFailure: onFailure,
	}
	
	return retryableReq.Execute()
}

// SetConfig updates the retry configuration
func (rc *RetryClient) SetConfig(config *RetryConfig) {
	rc.config = config
}

// GetConfig returns the current retry configuration
func (rc *RetryClient) GetConfig() *RetryConfig {
	return rc.config
}

// CircuitBreaker implements a circuit breaker pattern
type CircuitBreaker struct {
	maxFailures     int
	resetTimeout    time.Duration
	currentFailures int
	lastFailureTime time.Time
	state           CircuitState
}

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	if cb.state == CircuitOpen {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
	}

	err := fn()
	
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// recordFailure records a failure
func (cb *CircuitBreaker) recordFailure() {
	cb.currentFailures++
	cb.lastFailureTime = time.Now()
	
	if cb.currentFailures >= cb.maxFailures {
		cb.state = CircuitOpen
	}
}

// recordSuccess records a success
func (cb *CircuitBreaker) recordSuccess() {
	cb.currentFailures = 0
	cb.state = CircuitClosed
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	return cb.state
}

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	tokens    int
	maxTokens int
	refillRate time.Duration
	lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.refill()
	
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	
	return false
}

// Wait waits until a token is available
func (rl *RateLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(rl.refillRate / time.Duration(rl.maxTokens))
	}
}

// refill refills the token bucket
func (rl *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	
	tokensToAdd := int(elapsed / rl.refillRate)
	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}
}

// AdaptiveRetryConfig adjusts retry parameters based on success/failure rates
type AdaptiveRetryConfig struct {
	*RetryConfig
	successCount int
	failureCount int
	lastAdjust   time.Time
}

// NewAdaptiveRetryConfig creates a new adaptive retry configuration
func NewAdaptiveRetryConfig() *AdaptiveRetryConfig {
	return &AdaptiveRetryConfig{
		RetryConfig: DefaultRetryConfig(),
		lastAdjust:  time.Now(),
	}
}

// RecordSuccess records a successful request
func (arc *AdaptiveRetryConfig) RecordSuccess() {
	arc.successCount++
	arc.adjust()
}

// RecordFailure records a failed request
func (arc *AdaptiveRetryConfig) RecordFailure() {
	arc.failureCount++
	arc.adjust()
}

// adjust adjusts retry parameters based on success/failure rates
func (arc *AdaptiveRetryConfig) adjust() {
	// Adjust every minute
	if time.Since(arc.lastAdjust) < time.Minute {
		return
	}

	total := arc.successCount + arc.failureCount
	if total == 0 {
		return
	}

	successRate := float64(arc.successCount) / float64(total)
	
	// Adjust retry parameters based on success rate
	if successRate > 0.9 {
		// High success rate: reduce retries and delays
		if arc.MaxRetries > 1 {
			arc.MaxRetries--
		}
		arc.BaseDelay = time.Duration(float64(arc.BaseDelay) * 0.9)
	} else if successRate < 0.5 {
		// Low success rate: increase retries and delays
		if arc.MaxRetries < 5 {
			arc.MaxRetries++
		}
		arc.BaseDelay = time.Duration(float64(arc.BaseDelay) * 1.1)
	}

	// Reset counters
	arc.successCount = 0
	arc.failureCount = 0
	arc.lastAdjust = time.Now()
}
