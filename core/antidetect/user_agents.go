package antidetect

import (
	"math/rand"
	"time"
)

// BrowserUserAgent represents a browser user agent with associated headers
type BrowserUserAgent struct {
	UserAgent string
	Headers   map[string]string
}

// Chrome user agents with realistic headers
var ChromeUserAgents = []BrowserUserAgent{
	{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"macOS"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Linux"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
}

// Firefox user agents with realistic headers
var FirefoxUserAgents = []BrowserUserAgent{
	{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
		},
	},
}

// Safari user agents with realistic headers
var SafariUserAgents = []BrowserUserAgent{
	{
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
		},
	},
	{
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
		},
	},
}

// Edge user agents with realistic headers
var EdgeUserAgents = []BrowserUserAgent{
	{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br",
			"Cache-Control":             "max-age=0",
			"Sec-Ch-Ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		},
	},
}

// GetAllUserAgents returns all available user agents
func GetAllUserAgents() []BrowserUserAgent {
	var all []BrowserUserAgent
	all = append(all, ChromeUserAgents...)
	all = append(all, FirefoxUserAgents...)
	all = append(all, SafariUserAgents...)
	all = append(all, EdgeUserAgents...)
	return all
}

// GetRandomUserAgent returns a random user agent with headers
func GetRandomUserAgent() BrowserUserAgent {
	agents := GetAllUserAgents()
	rand.Seed(time.Now().UnixNano())
	return agents[rand.Intn(len(agents))]
}

// GetRandomChromeUserAgent returns a random Chrome user agent
func GetRandomChromeUserAgent() BrowserUserAgent {
	rand.Seed(time.Now().UnixNano())
	return ChromeUserAgents[rand.Intn(len(ChromeUserAgents))]
}

// GetRandomFirefoxUserAgent returns a random Firefox user agent
func GetRandomFirefoxUserAgent() BrowserUserAgent {
	rand.Seed(time.Now().UnixNano())
	return FirefoxUserAgents[rand.Intn(len(FirefoxUserAgents))]
}

// GetRandomSafariUserAgent returns a random Safari user agent
func GetRandomSafariUserAgent() BrowserUserAgent {
	rand.Seed(time.Now().UnixNano())
	return SafariUserAgents[rand.Intn(len(SafariUserAgents))]
}

// GetRandomEdgeUserAgent returns a random Edge user agent
func GetRandomEdgeUserAgent() BrowserUserAgent {
	rand.Seed(time.Now().UnixNano())
	return EdgeUserAgents[rand.Intn(len(EdgeUserAgents))]
}

// GetUserAgentByBrowser returns a random user agent for a specific browser
func GetUserAgentByBrowser(browser string) BrowserUserAgent {
	switch browser {
	case "chrome":
		return GetRandomChromeUserAgent()
	case "firefox":
		return GetRandomFirefoxUserAgent()
	case "safari":
		return GetRandomSafariUserAgent()
	case "edge":
		return GetRandomEdgeUserAgent()
	default:
		return GetRandomUserAgent()
	}
}

// HeaderOrder defines the order of headers to mimic real browsers
var BrowserHeaderOrder = []string{
	"Host",
	"Connection",
	"Cache-Control",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Accept-Encoding",
	"Accept-Language",
}

// GetOrderedHeaders returns headers in browser-like order
func GetOrderedHeaders(headers map[string]string) []string {
	var ordered []string
	
	// Add headers in browser order
	for _, header := range BrowserHeaderOrder {
		if value, exists := headers[header]; exists {
			ordered = append(ordered, header+": "+value)
		}
	}
	
	// Add any remaining headers
	for header, value := range headers {
		found := false
		for _, orderedHeader := range BrowserHeaderOrder {
			if header == orderedHeader {
				found = true
				break
			}
		}
		if !found {
			ordered = append(ordered, header+": "+value)
		}
	}
	
	return ordered
}
