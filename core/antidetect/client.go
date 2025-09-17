package antidetect

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/gocolly/colly/v2"
)

// AntiDetectConfig holds configuration for anti-detection features
type AntiDetectConfig struct {
	EnableTLSFingerprinting   bool
	EnableHTTP2Fingerprinting bool
	EnableUserAgentRotation   bool
	EnableHeaderRandomization bool
	EnableTimingRandomization bool
	EnableProxyRotation       bool
	EnableWAFDetection        bool
	EnableCloudflareBypass    bool
	EnableRetryLogic          bool
	EnableJA3Fingerprinting   bool
	EnableConnectionPooling   bool
	EnableRequestPatterns     bool
	BrowserProfile            string // "chrome", "firefox", "safari", "edge", "random"
	TimingProfile             *TimingProfile
	ProxyList                 []string
	MaxRetries                int
	RetryDelay                time.Duration
}

// DefaultAntiDetectConfig returns a default configuration with all features enabled
func DefaultAntiDetectConfig() *AntiDetectConfig {
	return &AntiDetectConfig{
		EnableTLSFingerprinting:   true,
		EnableHTTP2Fingerprinting: true,
		EnableUserAgentRotation:   true,
		EnableHeaderRandomization: true,
		EnableTimingRandomization: true,
		EnableProxyRotation:       false,
		EnableWAFDetection:        true,
		EnableCloudflareBypass:    true,
		EnableRetryLogic:          true,
		EnableJA3Fingerprinting:   true,
		EnableConnectionPooling:   true,
		EnableRequestPatterns:     true,
		BrowserProfile:            "random",
		TimingProfile:             nil, // Will use random
		ProxyList:                 []string{},
		MaxRetries:                3,
		RetryDelay:                1 * time.Second,
	}
}

// AntiDetectClient wraps an HTTP client with anti-detection capabilities
type AntiDetectClient struct {
	config           *AntiDetectConfig
	httpClient       *http.Client
	transport        *http.Transport
	timer            *RequestTimer
	userAgent        BrowserUserAgent
	tlsConfig        *tls.Config
	proxyRotator     *ProxyRotator
	cloudflareSolver *CloudflareSolver
	connectionPool   *ConnectionPool
	patternExecutor  *RequestPatternExecutor
	ja3Fingerprint   JA3Fingerprint
	wafBypassHeaders map[string]string
}

// NewAntiDetectClient creates a new anti-detection HTTP client
func NewAntiDetectClient(config *AntiDetectConfig) *AntiDetectClient {
	if config == nil {
		config = DefaultAntiDetectConfig()
	}

	client := &AntiDetectClient{
		config: config,
	}

	client.initialize()
	return client
}

// initialize sets up the client with anti-detection features
func (c *AntiDetectClient) initialize() {
	// Setup TLS configuration
	if c.config.EnableTLSFingerprinting {
		if c.config.BrowserProfile == "random" {
			c.tlsConfig = CreateRandomTLSConfig()
		} else {
			profile := GetBrowserProfiles()[0] // Default to Chrome
			for _, p := range GetBrowserProfiles() {
				if p.Name == c.config.BrowserProfile {
					profile = p
					break
				}
			}
			c.tlsConfig = CreateTLSConfig(profile)
		}
	} else {
		c.tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		}
	}

	// Setup HTTP transport
	c.transport = &http.Transport{
		TLSClientConfig:       c.tlsConfig,
		MaxIdleConns:          100,
		MaxConnsPerHost:       10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     c.config.EnableHTTP2Fingerprinting,
	}

	// Setup proxy rotation if enabled
	if c.config.EnableProxyRotation && len(c.config.ProxyList) > 0 {
		c.proxyRotator = NewProxyRotator(c.config.ProxyList, 3)
		if proxy := c.proxyRotator.GetNextProxy(); proxy != nil {
			proxyURL, err := url.Parse(proxy.URL)
			if err == nil {
				c.transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
	}

	// Setup HTTP client
	c.httpClient = &http.Client{
		Transport: c.transport,
		Timeout:   30 * time.Second,
	}

	// Wrap transport with retry logic if enabled
	if c.config.EnableRetryLogic {
		retryCfg := DefaultRetryConfig()
		retryCfg.MaxRetries = c.config.MaxRetries
		retryCfg.BaseDelay = c.config.RetryDelay
		c.httpClient.Transport = NewRetryRoundTripper(c.httpClient.Transport, retryCfg)
	}

	// Setup user agent
	if c.config.EnableUserAgentRotation {
		c.userAgent = GetUserAgentByBrowser(c.config.BrowserProfile)
	}

	// Setup timing
	if c.config.EnableTimingRandomization {
		if c.config.TimingProfile != nil {
			c.timer = NewRequestTimerWithProfile(*c.config.TimingProfile)
		} else {
			c.timer = NewRequestTimer()
		}
	}

	// Setup Cloudflare solver
	if c.config.EnableCloudflareBypass {
		c.cloudflareSolver = NewCloudflareSolver(c.httpClient, c.userAgent.UserAgent)
	}

	// Setup JA3 fingerprinting
	if c.config.EnableJA3Fingerprinting {
		c.ja3Fingerprint = GetRandomJA3Fingerprint(c.config.BrowserProfile)
	}

	// Setup connection pooling
	if c.config.EnableConnectionPooling {
		c.connectionPool = NewConnectionPool(100, 90*time.Second)
		c.connectionPool.SetTLSConfig(c.tlsConfig)
		c.transport = c.connectionPool.GetTransport()
		c.httpClient.Transport = c.transport
	}

	// Setup request patterns
	if c.config.EnableRequestPatterns {
		c.patternExecutor = NewRequestPatternExecutor(c.httpClient, "")
	}
}

// rotateProxy rotates to the next proxy in the list
func (c *AntiDetectClient) rotateProxy() {
	if c.proxyRotator == nil {
		return
	}

	if proxy := c.proxyRotator.GetNextProxy(); proxy != nil {
		proxyURL, err := url.Parse(proxy.URL)
		if err == nil {
			c.transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
}

// GetHTTPClient returns the configured HTTP client
func (c *AntiDetectClient) GetHTTPClient() *http.Client {
	return c.httpClient
}

// GetTransport returns the configured HTTP transport
func (c *AntiDetectClient) GetTransport() *http.Transport {
	return c.transport
}

// ApplyToCollyCollector applies anti-detection features to a Colly collector
func (c *AntiDetectClient) ApplyToCollyCollector(collector *colly.Collector) {
	// Set the HTTP client
	collector.SetClient(c.httpClient)

	// Apply user agent (string) if enabled so Colly sets UA header by default
	if c.config.EnableUserAgentRotation {
		collector.UserAgent = c.userAgent.UserAgent
	}

	// Apply headers (UA + WAF bypass + randomized hints) in a single place
	collector.OnRequest(func(r *colly.Request) {
		c.composeHeaders(*r.Headers)
	})

	// Apply timing randomization
	if c.config.EnableTimingRandomization && c.timer != nil {
		collector.OnRequest(func(r *colly.Request) {
			c.timer.WaitForNextRequest()
		})
	}

	// Apply WAF detection and response analysis
	if c.config.EnableWAFDetection {
		collector.OnResponse(func(r *colly.Response) {
			body := string(r.Body)

			// Create a mock HTTP response for WAF detection
			httpResp := &http.Response{
				StatusCode: r.StatusCode,
				Header:     *r.Headers,
			}

			// Detect WAF
			wafResult := DetectWAF(httpResp, body)
			if wafResult.Detected {
				// Store WAF-specific bypass headers for future requests
				c.wafBypassHeaders = GetWAFBypassHeaders(wafResult.WAFType)
			}

			// Handle Cloudflare challenges
			if c.config.EnableCloudflareBypass && IsCloudflareChallenge(httpResp, body) {
				if c.cloudflareSolver != nil {
					// This would need to be handled differently in a real implementation
					// as Colly doesn't easily support challenge solving mid-request
				}
			}

			// Check for rate limiting
			if IsRateLimited(httpResp, body) {
				// Increase delays for future requests
				if c.timer != nil {
					profile := c.timer.profile
					profile.MinDelay *= 2
					profile.MaxDelay *= 2
					c.timer.SetProfile(profile)
				}
			}
		})
	}

	// Apply retry logic with exponential backoff
	collector.OnError(func(r *colly.Response, err error) {
		if r.StatusCode >= 500 || r.StatusCode == 429 {
			// Rotate proxy if enabled
			if c.config.EnableProxyRotation {
				c.rotateProxy()
			}

			// Rotate user agent
			if c.config.EnableUserAgentRotation {
				c.userAgent = GetUserAgentByBrowser(c.config.BrowserProfile)
			}
		}
	})
}

// composeHeaders applies UA headers, WAF bypass headers, and randomized hints in order
func (c *AntiDetectClient) composeHeaders(h http.Header) {
	// 1) UA headers (stable per profile)
	if c.config.EnableUserAgentRotation {
		for header, value := range c.userAgent.Headers {
			h.Set(header, value)
		}
	}

	// 2) WAF bypass headers (contextual, may override UA headers)
	if c.wafBypassHeaders != nil {
		for header, value := range c.wafBypassHeaders {
			h.Set(header, value)
		}
	}

	// 3) Randomized hints (low-risk, human-like)
	// Accept-Language
	if h.Get("Accept-Language") == "" {
		languages := []string{
			"en-US,en;q=0.9",
			"en-US,en;q=0.8",
			"en-GB,en;q=0.9",
			"en-US,en;q=0.9,es;q=0.8",
		}
		idx := GetRandomInt(0, len(languages))
		if idx >= len(languages) {
			idx = 0
		}
		h.Set("Accept-Language", languages[idx])
	}

	// DNT occasionally
	if GetRandomInt(0, 2) == 0 {
		h.Set("DNT", "1")
	}

	// Viewport-Width hint for Chrome-like profiles
	if c.config.BrowserProfile == "chrome" || c.config.BrowserProfile == "random" {
		viewportWidths := []string{"1920", "1366", "1536", "1440", "1280"}
		vwIdx := GetRandomInt(0, len(viewportWidths))
		if vwIdx >= len(viewportWidths) {
			vwIdx = 0
		}
		h.Set("Viewport-Width", viewportWidths[vwIdx])
	}
}

// RotateFingerprint rotates the browser fingerprint
func (c *AntiDetectClient) RotateFingerprint() {
	// Rotate TLS config
	if c.config.EnableTLSFingerprinting {
		c.tlsConfig = CreateStealthTLSConfig()
		c.transport.TLSClientConfig = c.tlsConfig
	}

	// Rotate user agent
	if c.config.EnableUserAgentRotation {
		c.userAgent = GetUserAgentByBrowser(c.config.BrowserProfile)
	}

	// Rotate JA3 fingerprint
	if c.config.EnableJA3Fingerprinting {
		c.ja3Fingerprint = RandomizeJA3Fingerprint(c.ja3Fingerprint)
	}

	// Rotate proxy
	if c.config.EnableProxyRotation {
		c.rotateProxy()
	}

	// Reset timing
	if c.timer != nil {
		c.timer.Reset()
	}
}

// SetProxy sets a specific proxy
func (c *AntiDetectClient) SetProxy(proxyURL string) error {
	if proxyURL == "" {
		c.transport.Proxy = nil
		return nil
	}

	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	c.transport.Proxy = http.ProxyURL(proxy)
	return nil
}

// SetUserAgent sets a specific user agent
func (c *AntiDetectClient) SetUserAgent(userAgent string) {
	c.userAgent = BrowserUserAgent{
		UserAgent: userAgent,
		Headers:   make(map[string]string),
	}
}

// GetRandomInt returns a random integer between min and max (exclusive)
func GetRandomInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + int(time.Now().UnixNano())%(max-min)
}

// EnableDebugMode enables debug mode for the HTTP client
func (c *AntiDetectClient) EnableDebugMode() {
	// This would be used with Colly's debug functionality
	// The actual implementation depends on how you want to integrate with Colly's debugger
}

// GetStats returns statistics about the client
func (c *AntiDetectClient) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["browser_profile"] = c.config.BrowserProfile
	stats["tls_fingerprinting"] = c.config.EnableTLSFingerprinting
	stats["http2_fingerprinting"] = c.config.EnableHTTP2Fingerprinting
	stats["user_agent_rotation"] = c.config.EnableUserAgentRotation
	stats["current_user_agent"] = c.userAgent.UserAgent
	stats["ja3_fingerprinting"] = c.config.EnableJA3Fingerprinting
	stats["connection_pooling"] = c.config.EnableConnectionPooling
	stats["request_patterns"] = c.config.EnableRequestPatterns

	if c.timer != nil {
		requestCount, lastRequest := c.timer.GetStats()
		stats["request_count"] = requestCount
		stats["last_request"] = lastRequest
	}

	if c.connectionPool != nil {
		stats["connection_stats"] = c.connectionPool.GetConnectionStats()
	}

	if c.proxyRotator != nil {
		stats["proxy_stats"] = c.proxyRotator.GetProxyStats()
	}

	if c.config.EnableJA3Fingerprinting {
		stats["ja3_hash"] = GenerateJA3Hash(c.ja3Fingerprint)
	}

	return stats
}

// SimulateBrowserBehavior simulates realistic browser behavior patterns
func (c *AntiDetectClient) SimulateBrowserBehavior(baseURL string) error {
	if !c.config.EnableRequestPatterns || c.patternExecutor == nil {
		return nil
	}

	// Update base URL for pattern executor
	c.patternExecutor.baseURL = baseURL

	// Create behavior simulator
	simulator := NewBehaviorSimulator(c.patternExecutor, "casual")

	// Simulate a page visit
	return simulator.SimulatePageVisit()
}

// RotateJA3Fingerprint rotates the JA3 fingerprint
func (c *AntiDetectClient) RotateJA3Fingerprint() {
	if c.config.EnableJA3Fingerprinting {
		c.ja3Fingerprint = GetRandomJA3Fingerprint(c.config.BrowserProfile)

		// Update TLS config to match new fingerprint
		if c.config.EnableTLSFingerprinting {
			c.tlsConfig = CreateStealthTLSConfig()
			c.transport.TLSClientConfig = c.tlsConfig
		}
	}
}

// GetJA3Hash returns the current JA3 hash
func (c *AntiDetectClient) GetJA3Hash() string {
	if c.config.EnableJA3Fingerprinting {
		return GenerateJA3Hash(c.ja3Fingerprint)
	}
	return ""
}
