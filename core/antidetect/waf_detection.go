package antidetect

import (
	"net/http"
	"regexp"
	"strings"
)

// WAFType represents different types of WAFs
type WAFType int

const (
	WAFUnknown WAFType = iota
	WAFCloudflare
	WAFAkamai
	WAFIncapsula
	WAFSucuri
	WAFBarracuda
	WAFModSecurity
	WAFAWS
	WAFAzure
	WAFGoogleCloud
	WAFCrowdStrike
	WAFPerimeter81
	WAFRadware
)

// WAFDetectionResult contains information about detected WAF
type WAFDetectionResult struct {
	Detected    bool
	WAFType     WAFType
	WAFName     string
	Confidence  float64
	Headers     map[string]string
	StatusCode  int
	Body        string
	Reason      string
}

// WAFSignature represents a WAF detection signature
type WAFSignature struct {
	Name        string
	WAFType     WAFType
	Headers     map[string]*regexp.Regexp
	BodyRegex   *regexp.Regexp
	StatusCodes []int
	Confidence  float64
}

// GetWAFSignatures returns known WAF signatures
func GetWAFSignatures() []WAFSignature {
	return []WAFSignature{
		{
			Name:    "Cloudflare",
			WAFType: WAFCloudflare,
			Headers: map[string]*regexp.Regexp{
				"Server":           regexp.MustCompile(`(?i)cloudflare`),
				"CF-Ray":           regexp.MustCompile(`.+`),
				"CF-Cache-Status":  regexp.MustCompile(`.+`),
				"CF-Request-ID":    regexp.MustCompile(`.+`),
				"Set-Cookie":       regexp.MustCompile(`(?i)__cflb|__cfuid|cf_clearance`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)cloudflare|attention required|checking your browser|ray id|cf-error-details`),
			StatusCodes: []int{403, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530},
			Confidence:  0.9,
		},
		{
			Name:    "Akamai",
			WAFType: WAFAkamai,
			Headers: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)akamaighost|akamai`),
				"X-Akamai":   regexp.MustCompile(`.+`),
				"Set-Cookie": regexp.MustCompile(`(?i)ak_bmsc|akamai`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)akamai|reference #\d+\.\w+\.\d+\.\w+`),
			StatusCodes: []int{403, 406},
			Confidence:  0.8,
		},
		{
			Name:    "Incapsula",
			WAFType: WAFIncapsula,
			Headers: map[string]*regexp.Regexp{
				"X-Iinfo":    regexp.MustCompile(`.+`),
				"Set-Cookie": regexp.MustCompile(`(?i)incap_ses|visid_incap`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)incapsula|request unsuccessful|incident id`),
			StatusCodes: []int{403},
			Confidence:  0.8,
		},
		{
			Name:    "Sucuri",
			WAFType: WAFSucuri,
			Headers: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)sucuri`),
				"X-Sucuri":   regexp.MustCompile(`.+`),
				"Set-Cookie": regexp.MustCompile(`(?i)sucuri`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)sucuri|access denied|blocked by sucuri`),
			StatusCodes: []int{403},
			Confidence:  0.8,
		},
		{
			Name:    "Barracuda",
			WAFType: WAFBarracuda,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)barracuda`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)barracuda|you have been blocked`),
			StatusCodes: []int{403},
			Confidence:  0.7,
		},
		{
			Name:    "ModSecurity",
			WAFType: WAFModSecurity,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)mod_security|modsecurity`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)mod_security|modsecurity|not acceptable|406 not acceptable`),
			StatusCodes: []int{403, 406, 501},
			Confidence:  0.6,
		},
		{
			Name:    "AWS WAF",
			WAFType: WAFAWS,
			Headers: map[string]*regexp.Regexp{
				"Server":     regexp.MustCompile(`(?i)awselb|amazon`),
				"X-Amzn":     regexp.MustCompile(`.+`),
				"X-Amz":      regexp.MustCompile(`.+`),
				"Set-Cookie": regexp.MustCompile(`(?i)awsalb|awsalbcors`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)aws|amazon|request blocked`),
			StatusCodes: []int{403},
			Confidence:  0.7,
		},
		{
			Name:    "Azure WAF",
			WAFType: WAFAzure,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)microsoft|azure`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)azure|microsoft|blocked by policy`),
			StatusCodes: []int{403},
			Confidence:  0.7,
		},
		{
			Name:    "Google Cloud Armor",
			WAFType: WAFGoogleCloud,
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)gws|google`),
			},
			BodyRegex:   regexp.MustCompile(`(?i)google|cloud armor|error 403`),
			StatusCodes: []int{403},
			Confidence:  0.7,
		},
	}
}

// DetectWAF analyzes an HTTP response to detect WAF presence
func DetectWAF(resp *http.Response, body string) *WAFDetectionResult {
	result := &WAFDetectionResult{
		Detected:   false,
		WAFType:    WAFUnknown,
		Headers:    make(map[string]string),
		StatusCode: resp.StatusCode,
		Body:       body,
	}

	// Copy response headers
	for name, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[name] = values[0]
		}
	}

	signatures := GetWAFSignatures()
	maxConfidence := 0.0

	for _, sig := range signatures {
		confidence := calculateWAFConfidence(sig, resp, body)
		if confidence > maxConfidence {
			maxConfidence = confidence
			result.WAFType = sig.WAFType
			result.WAFName = sig.Name
			result.Confidence = confidence
		}
	}

	// Consider it detected if confidence is above threshold
	if maxConfidence > 0.5 {
		result.Detected = true
		result.Reason = "WAF signatures detected"
	}

	return result
}

// calculateWAFConfidence calculates confidence score for a WAF signature
func calculateWAFConfidence(sig WAFSignature, resp *http.Response, body string) float64 {
	score := 0.0
	maxScore := 0.0

	// Check headers
	for headerName, headerRegex := range sig.Headers {
		maxScore += 1.0
		if headerValue := resp.Header.Get(headerName); headerValue != "" {
			if headerRegex.MatchString(headerValue) {
				score += 1.0
			}
		}
	}

	// Check body
	if sig.BodyRegex != nil {
		maxScore += 1.0
		if sig.BodyRegex.MatchString(body) {
			score += 1.0
		}
	}

	// Check status codes
	if len(sig.StatusCodes) > 0 {
		maxScore += 0.5
		for _, code := range sig.StatusCodes {
			if resp.StatusCode == code {
				score += 0.5
				break
			}
		}
	}

	if maxScore == 0 {
		return 0
	}

	return (score / maxScore) * sig.Confidence
}

// IsCloudflareChallenge checks if the response is a Cloudflare challenge
func IsCloudflareChallenge(resp *http.Response, body string) bool {
	// Check for Cloudflare challenge indicators
	cfRay := resp.Header.Get("CF-Ray")
	server := resp.Header.Get("Server")
	
	if cfRay != "" || strings.Contains(strings.ToLower(server), "cloudflare") {
		// Check for challenge page content
		challengePatterns := []string{
			"checking your browser",
			"please wait while we check your browser",
			"challenge",
			"cf-browser-verification",
			"cf-challenge-form",
			"jschl_vc",
			"jschl_answer",
			"cf-turnstile",
		}
		
		bodyLower := strings.ToLower(body)
		for _, pattern := range challengePatterns {
			if strings.Contains(bodyLower, pattern) {
				return true
			}
		}
	}
	
	return false
}

// IsRateLimited checks if the response indicates rate limiting
func IsRateLimited(resp *http.Response, body string) bool {
	// Common rate limiting status codes
	rateLimitCodes := []int{429, 503, 509}
	for _, code := range rateLimitCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	// Check for rate limiting headers
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-Rate-Limit-Limit",
		"X-Rate-Limit-Remaining",
		"Retry-After",
	}
	
	for _, header := range rateLimitHeaders {
		if resp.Header.Get(header) != "" {
			return true
		}
	}

	// Check body for rate limiting messages
	rateLimitPatterns := []string{
		"rate limit",
		"too many requests",
		"request limit exceeded",
		"quota exceeded",
		"throttled",
	}
	
	bodyLower := strings.ToLower(body)
	for _, pattern := range rateLimitPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

// GetWAFBypassHeaders returns headers that might help bypass specific WAFs
func GetWAFBypassHeaders(wafType WAFType) map[string]string {
	headers := make(map[string]string)
	
	switch wafType {
	case WAFCloudflare:
		headers["CF-Connecting-IP"] = "127.0.0.1"
		headers["CF-IPCountry"] = "US"
		headers["X-Forwarded-For"] = "127.0.0.1"
		headers["X-Real-IP"] = "127.0.0.1"
	case WAFAkamai:
		headers["Akamai-Origin-Hop"] = "1"
		headers["X-Forwarded-For"] = "127.0.0.1"
	case WAFIncapsula:
		headers["X-Forwarded-For"] = "127.0.0.1"
		headers["X-Real-IP"] = "127.0.0.1"
	case WAFAWS:
		headers["X-Forwarded-For"] = "127.0.0.1"
		headers["X-Real-IP"] = "127.0.0.1"
		headers["X-AWS-ALB-Target-Group-ARN"] = "bypass"
	default:
		headers["X-Forwarded-For"] = "127.0.0.1"
		headers["X-Real-IP"] = "127.0.0.1"
		headers["X-Originating-IP"] = "127.0.0.1"
		headers["X-Remote-IP"] = "127.0.0.1"
		headers["X-Remote-Addr"] = "127.0.0.1"
	}
	
	return headers
}
