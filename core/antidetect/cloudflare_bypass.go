package antidetect

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CloudflareChallenge represents a Cloudflare challenge
type CloudflareChallenge struct {
	URL         string
	Method      string
	Headers     map[string]string
	FormData    map[string]string
	JSChallenge string
	Delay       time.Duration
}

// CloudflareSolver handles Cloudflare challenge solving
type CloudflareSolver struct {
	client    *http.Client
	userAgent string
}

// NewCloudflareSolver creates a new Cloudflare solver
func NewCloudflareSolver(client *http.Client, userAgent string) *CloudflareSolver {
	return &CloudflareSolver{
		client:    client,
		userAgent: userAgent,
	}
}

// SolveChallenge attempts to solve a Cloudflare challenge
func (cs *CloudflareSolver) SolveChallenge(resp *http.Response, body string) (*http.Response, error) {
	challenge, err := cs.parseChallenge(resp, body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse challenge: %v", err)
	}

	// Wait for the required delay
	if challenge.Delay > 0 {
		time.Sleep(challenge.Delay)
	}

	// Submit the challenge
	return cs.submitChallenge(challenge)
}

// parseChallenge extracts challenge information from the response
func (cs *CloudflareSolver) parseChallenge(resp *http.Response, body string) (*CloudflareChallenge, error) {
	challenge := &CloudflareChallenge{
		URL:      resp.Request.URL.String(),
		Method:   "POST",
		Headers:  make(map[string]string),
		FormData: make(map[string]string),
		Delay:    5 * time.Second, // Default delay
	}

	// Extract form action URL
	actionRegex := regexp.MustCompile(`<form[^>]+action="([^"]+)"`)
	if matches := actionRegex.FindStringSubmatch(body); len(matches) > 1 {
		actionURL := matches[1]
		if strings.HasPrefix(actionURL, "/") {
			baseURL := fmt.Sprintf("%s://%s", resp.Request.URL.Scheme, resp.Request.URL.Host)
			challenge.URL = baseURL + actionURL
		} else {
			challenge.URL = actionURL
		}
	}

	// Extract hidden form fields
	hiddenFieldRegex := regexp.MustCompile(`<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"`)
	matches := hiddenFieldRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			challenge.FormData[match[1]] = match[2]
		}
	}

	// Extract JavaScript challenge if present
	jsRegex := regexp.MustCompile(`setTimeout\(function\(\)\{\s*var\s+s,t,o,p,b,r,e,a,k,i,n,g,f,\s*([^}]+)\}\s*,\s*(\d+)\)`)
	if matches := jsRegex.FindStringSubmatch(body); len(matches) > 2 {
		challenge.JSChallenge = matches[1]
		if delay, err := strconv.Atoi(matches[2]); err == nil {
			challenge.Delay = time.Duration(delay) * time.Millisecond
		}
	}

	// Extract jschl_vc and pass values
	jschlVcRegex := regexp.MustCompile(`name="jschl_vc" value="([^"]+)"`)
	if matches := jschlVcRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.FormData["jschl_vc"] = matches[1]
	}

	passRegex := regexp.MustCompile(`name="pass" value="([^"]+)"`)
	if matches := passRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.FormData["pass"] = matches[1]
	}

	// Calculate jschl_answer if JavaScript challenge is present
	if challenge.JSChallenge != "" {
		answer, err := cs.solveJSChallenge(challenge.JSChallenge, resp.Request.URL.Host)
		if err == nil {
			challenge.FormData["jschl_answer"] = strconv.Itoa(answer)
		}
	}

	return challenge, nil
}

// solveJSChallenge attempts to solve the JavaScript challenge
func (cs *CloudflareSolver) solveJSChallenge(jsCode, hostname string) (int, error) {
	// This is a simplified JavaScript challenge solver
	// In a real implementation, you would need a more sophisticated JS engine
	
	// Extract the initial value
	initRegex := regexp.MustCompile(`var\s+s,t,o,p,b,r,e,a,k,i,n,g,f,\s*([^=]+)=([^;]+);`)
	if matches := initRegex.FindStringSubmatch(jsCode); len(matches) > 2 {
		// Try to parse the initial value
		if val, err := strconv.Atoi(strings.TrimSpace(matches[2])); err == nil {
			// Add hostname length as Cloudflare often does
			result := val + len(hostname)
			return result, nil
		}
	}

	// Fallback: return hostname length
	return len(hostname), nil
}

// submitChallenge submits the solved challenge
func (cs *CloudflareSolver) submitChallenge(challenge *CloudflareChallenge) (*http.Response, error) {
	// Prepare form data
	formData := url.Values{}
	for key, value := range challenge.FormData {
		formData.Set(key, value)
	}

	// Create request
	req, err := http.NewRequest(challenge.Method, challenge.URL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", cs.userAgent)
	req.Header.Set("Referer", challenge.URL)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add custom headers
	for key, value := range challenge.Headers {
		req.Header.Set(key, value)
	}

	// Submit the challenge
	return cs.client.Do(req)
}

// IsCloudflareClearanceCookie checks if the response contains a Cloudflare clearance cookie
func IsCloudflareClearanceCookie(resp *http.Response) bool {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cf_clearance" {
			return true
		}
	}
	return false
}

// ExtractCloudflareCookies extracts Cloudflare-related cookies from the response
func ExtractCloudflareCookies(resp *http.Response) []*http.Cookie {
	var cfCookies []*http.Cookie
	
	cfCookieNames := []string{"cf_clearance", "__cflb", "__cfuid", "__cfduid"}
	
	for _, cookie := range resp.Cookies() {
		for _, cfName := range cfCookieNames {
			if cookie.Name == cfName {
				cfCookies = append(cfCookies, cookie)
				break
			}
		}
	}
	
	return cfCookies
}

// CloudflareTurnstileChallenge represents a Turnstile challenge
type CloudflareTurnstileChallenge struct {
	SiteKey   string
	Action    string
	CData     string
	Callback  string
	Theme     string
	Size      string
}

// ParseTurnstileChallenge extracts Turnstile challenge information
func ParseTurnstileChallenge(body string) (*CloudflareTurnstileChallenge, error) {
	challenge := &CloudflareTurnstileChallenge{}

	// Extract site key
	siteKeyRegex := regexp.MustCompile(`data-sitekey="([^"]+)"`)
	if matches := siteKeyRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.SiteKey = matches[1]
	}

	// Extract action
	actionRegex := regexp.MustCompile(`data-action="([^"]+)"`)
	if matches := actionRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.Action = matches[1]
	}

	// Extract cdata
	cdataRegex := regexp.MustCompile(`data-cdata="([^"]+)"`)
	if matches := cdataRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.CData = matches[1]
	}

	// Extract callback
	callbackRegex := regexp.MustCompile(`data-callback="([^"]+)"`)
	if matches := callbackRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.Callback = matches[1]
	}

	// Extract theme
	themeRegex := regexp.MustCompile(`data-theme="([^"]+)"`)
	if matches := themeRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.Theme = matches[1]
	}

	// Extract size
	sizeRegex := regexp.MustCompile(`data-size="([^"]+)"`)
	if matches := sizeRegex.FindStringSubmatch(body); len(matches) > 1 {
		challenge.Size = matches[1]
	}

	if challenge.SiteKey == "" {
		return nil, fmt.Errorf("no Turnstile site key found")
	}

	return challenge, nil
}

// CloudflareBypassHeaders returns headers that might help bypass Cloudflare
func CloudflareBypassHeaders() map[string]string {
	return map[string]string{
		"CF-Connecting-IP":    "127.0.0.1",
		"CF-IPCountry":        "US",
		"CF-RAY":              "000000000-XXX",
		"CF-Visitor":          `{"scheme":"https"}`,
		"X-Forwarded-Proto":   "https",
		"X-Forwarded-For":     "127.0.0.1",
		"X-Real-IP":           "127.0.0.1",
		"X-Originating-IP":    "127.0.0.1",
		"X-Remote-IP":         "127.0.0.1",
		"X-Remote-Addr":       "127.0.0.1",
		"X-Client-IP":         "127.0.0.1",
		"X-Cluster-Client-IP": "127.0.0.1",
	}
}

// GenerateFakeCFRay generates a fake CF-Ray header value
func GenerateFakeCFRay() string {
	// CF-Ray format: 8 hex digits + "-" + 3 letter airport code
	airports := []string{"LAX", "JFK", "ORD", "DFW", "DEN", "LAS", "PHX", "ATL", "IAH", "BOS"}
	hexChars := "0123456789abcdef"
	
	ray := ""
	for i := 0; i < 8; i++ {
		ray += string(hexChars[time.Now().UnixNano()%int64(len(hexChars))])
	}
	
	airport := airports[time.Now().UnixNano()%int64(len(airports))]
	
	return ray + "-" + airport
}

// IsCloudflareBlocked checks if the request was blocked by Cloudflare
func IsCloudflareBlocked(resp *http.Response, body string) bool {
	// Check status codes
	blockedCodes := []int{403, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530}
	for _, code := range blockedCodes {
		if resp.StatusCode == code {
			// Check for Cloudflare indicators
			if resp.Header.Get("CF-Ray") != "" || 
			   strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") ||
			   strings.Contains(strings.ToLower(body), "cloudflare") {
				return true
			}
		}
	}
	
	return false
}
