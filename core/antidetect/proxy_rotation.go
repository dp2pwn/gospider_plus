package antidetect

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProxyType represents different types of proxies
type ProxyType int

const (
	ProxyHTTP ProxyType = iota
	ProxyHTTPS
	ProxySOCKS4
	ProxySOCKS5
)

// ProxyInfo contains proxy configuration
type ProxyInfo struct {
	URL      string
	Type     ProxyType
	Username string
	Password string
	Timeout  time.Duration
	LastUsed time.Time
	Failures int
	Active   bool
}

// ProxyRotator manages proxy rotation
type ProxyRotator struct {
	proxies     []*ProxyInfo
	currentIdx  int
	maxFailures int
	mutex       sync.RWMutex
	client      *http.Client
}

// NewProxyRotator creates a new proxy rotator
func NewProxyRotator(proxyURLs []string, maxFailures int) *ProxyRotator {
	pr := &ProxyRotator{
		proxies:     make([]*ProxyInfo, 0, len(proxyURLs)),
		maxFailures: maxFailures,
		client:      &http.Client{Timeout: 30 * time.Second},
	}

	for _, proxyURL := range proxyURLs {
		if proxy := pr.parseProxy(proxyURL); proxy != nil {
			pr.proxies = append(pr.proxies, proxy)
		}
	}

	return pr
}

// parseProxy parses a proxy URL and creates ProxyInfo
func (pr *ProxyRotator) parseProxy(proxyURL string) *ProxyInfo {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil
	}

	proxy := &ProxyInfo{
		URL:     proxyURL,
		Timeout: 10 * time.Second,
		Active:  true,
	}

	// Extract username and password
	if u.User != nil {
		proxy.Username = u.User.Username()
		proxy.Password, _ = u.User.Password()
	}

	// Determine proxy type
	switch u.Scheme {
	case "http":
		proxy.Type = ProxyHTTP
	case "https":
		proxy.Type = ProxyHTTPS
	case "socks4":
		proxy.Type = ProxySOCKS4
	case "socks5":
		proxy.Type = ProxySOCKS5
	default:
		proxy.Type = ProxyHTTP
	}

	return proxy
}

// GetNextProxy returns the next available proxy
func (pr *ProxyRotator) GetNextProxy() *ProxyInfo {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	if len(pr.proxies) == 0 {
		return nil
	}

	// Find next active proxy
	attempts := 0
	for attempts < len(pr.proxies) {
		proxy := pr.proxies[pr.currentIdx]
		pr.currentIdx = (pr.currentIdx + 1) % len(pr.proxies)
		attempts++

		if proxy.Active && proxy.Failures < pr.maxFailures {
			proxy.LastUsed = time.Now()
			return proxy
		}
	}

	// If no active proxies, reset all and try again
	pr.resetProxies()
	if len(pr.proxies) > 0 {
		proxy := pr.proxies[0]
		proxy.LastUsed = time.Now()
		return proxy
	}

	return nil
}

// GetRandomProxy returns a random active proxy
func (pr *ProxyRotator) GetRandomProxy() *ProxyInfo {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	activeProxies := make([]*ProxyInfo, 0)
	for _, proxy := range pr.proxies {
		if proxy.Active && proxy.Failures < pr.maxFailures {
			activeProxies = append(activeProxies, proxy)
		}
	}

	if len(activeProxies) == 0 {
		return nil
	}

	rand.Seed(time.Now().UnixNano())
	return activeProxies[rand.Intn(len(activeProxies))]
}

// MarkProxyFailed marks a proxy as failed
func (pr *ProxyRotator) MarkProxyFailed(proxyURL string) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	for _, proxy := range pr.proxies {
		if proxy.URL == proxyURL {
			proxy.Failures++
			if proxy.Failures >= pr.maxFailures {
				proxy.Active = false
			}
			break
		}
	}
}

// MarkProxySuccess marks a proxy as successful
func (pr *ProxyRotator) MarkProxySuccess(proxyURL string) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	for _, proxy := range pr.proxies {
		if proxy.URL == proxyURL {
			proxy.Failures = 0
			proxy.Active = true
			break
		}
	}
}

// resetProxies resets all proxy failure counts
func (pr *ProxyRotator) resetProxies() {
	for _, proxy := range pr.proxies {
		proxy.Failures = 0
		proxy.Active = true
	}
}

// TestProxy tests if a proxy is working
func (pr *ProxyRotator) TestProxy(proxy *ProxyInfo) bool {
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   proxy.Timeout,
	}

	// Test with a simple HTTP request
	testURLs := []string{
		"http://httpbin.org/ip",
		"https://api.ipify.org",
		"http://icanhazip.com",
	}

	for _, testURL := range testURLs {
		resp, err := client.Get(testURL)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	return false
}

// TestAllProxies tests all proxies and updates their status
func (pr *ProxyRotator) TestAllProxies() {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	for _, proxy := range pr.proxies {
		if pr.TestProxy(proxy) {
			proxy.Active = true
			proxy.Failures = 0
		} else {
			proxy.Failures++
			if proxy.Failures >= pr.maxFailures {
				proxy.Active = false
			}
		}
	}
}

// GetActiveProxyCount returns the number of active proxies
func (pr *ProxyRotator) GetActiveProxyCount() int {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	count := 0
	for _, proxy := range pr.proxies {
		if proxy.Active && proxy.Failures < pr.maxFailures {
			count++
		}
	}
	return count
}

// GetProxyStats returns proxy statistics
func (pr *ProxyRotator) GetProxyStats() map[string]interface{} {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_proxies"] = len(pr.proxies)
	stats["active_proxies"] = pr.GetActiveProxyCount()
	stats["max_failures"] = pr.maxFailures

	proxyDetails := make([]map[string]interface{}, 0, len(pr.proxies))
	for _, proxy := range pr.proxies {
		detail := map[string]interface{}{
			"url":       proxy.URL,
			"type":      proxy.Type,
			"active":    proxy.Active,
			"failures":  proxy.Failures,
			"last_used": proxy.LastUsed,
		}
		proxyDetails = append(proxyDetails, detail)
	}
	stats["proxies"] = proxyDetails

	return stats
}

// CreateProxyTransport creates an HTTP transport with the given proxy
func CreateProxyTransport(proxy *ProxyInfo, tlsConfig interface{}) *http.Transport {
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return nil
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConns:        100,
		MaxConnsPerHost:     10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Set TLS config if provided
	if tlsConfig != nil {
		if tls, ok := tlsConfig.(*http.Transport); ok {
			transport.TLSClientConfig = tls.TLSClientConfig
		}
	}

	return transport
}

// ProxyChain represents a chain of proxies
type ProxyChain struct {
	proxies []*ProxyInfo
	current int
}

// NewProxyChain creates a new proxy chain
func NewProxyChain(proxies []*ProxyInfo) *ProxyChain {
	return &ProxyChain{
		proxies: proxies,
		current: 0,
	}
}

// GetNextInChain returns the next proxy in the chain
func (pc *ProxyChain) GetNextInChain() *ProxyInfo {
	if len(pc.proxies) == 0 {
		return nil
	}

	proxy := pc.proxies[pc.current]
	pc.current = (pc.current + 1) % len(pc.proxies)
	return proxy
}

// ProxyHealthChecker monitors proxy health
type ProxyHealthChecker struct {
	rotator  *ProxyRotator
	interval time.Duration
	stopChan chan bool
}

// NewProxyHealthChecker creates a new proxy health checker
func NewProxyHealthChecker(rotator *ProxyRotator, interval time.Duration) *ProxyHealthChecker {
	return &ProxyHealthChecker{
		rotator:  rotator,
		interval: interval,
		stopChan: make(chan bool),
	}
}

// Start starts the health checker
func (phc *ProxyHealthChecker) Start() {
	ticker := time.NewTicker(phc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			phc.rotator.TestAllProxies()
		case <-phc.stopChan:
			return
		}
	}
}

// Stop stops the health checker
func (phc *ProxyHealthChecker) Stop() {
	phc.stopChan <- true
}

// GetFreeProxies returns a list of free proxy URLs for testing
func GetFreeProxies() []string {
	return []string{
		// Note: These are example URLs. In practice, you would use actual proxy services
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:3128",
		"socks5://proxy3.example.com:1080",
		"http://proxy4.example.com:8888",
		"https://proxy5.example.com:443",
	}
}

// ValidateProxy validates a proxy URL format
func ValidateProxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	if u.Host == "" {
		return fmt.Errorf("proxy URL must include host")
	}

	validSchemes := []string{"http", "https", "socks4", "socks5"}
	validScheme := false
	for _, scheme := range validSchemes {
		if u.Scheme == scheme {
			validScheme = true
			break
		}
	}

	if !validScheme {
		return fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	return nil
}
