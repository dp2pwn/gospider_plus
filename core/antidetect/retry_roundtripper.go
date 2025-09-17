package antidetect

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// RetryRoundTripper wraps a base RoundTripper and applies retry logic on errors or retryable status codes
type RetryRoundTripper struct {
	base http.RoundTripper
	cfg  *RetryConfig
}

// NewRetryRoundTripper creates a new retrying RoundTripper
func NewRetryRoundTripper(base http.RoundTripper, cfg *RetryConfig) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if cfg == nil {
		cfg = DefaultRetryConfig()
	}
	return &RetryRoundTripper{base: base, cfg: cfg}
}

func (rt *RetryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Prepare body reloader if present
	var bodyCopy []byte
	var hasBody bool
	if req.Body != nil {
		if req.GetBody != nil {
			hasBody = true
		} else {
			// Best-effort: read once to allow retries
			b, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			bodyCopy = b
			hasBody = len(bodyCopy) > 0
		}
	}

	attempts := rt.cfg.MaxRetries + 1
	var resp *http.Response
	var err error

	for attempt := 0; attempt < attempts; attempt++ {
		// Reset body if needed
		if hasBody {
			if req.GetBody != nil {
				req.Body, _ = req.GetBody()
			} else if len(bodyCopy) > 0 {
				req.Body = io.NopCloser(bytes.NewReader(bodyCopy))
			}
		}

		resp, err = rt.base.RoundTrip(req)
		if !rt.shouldRetry(attempt, err, resp) {
			return resp, err
		}

		// Respect context cancellation
		if req.Context().Err() != nil {
			return resp, req.Context().Err()
		}

		// Backoff with jitter
		delay := (&RetryableRequest{Config: rt.cfg}).calculateDelay(attempt)
		time.Sleep(delay)
	}

	return resp, err
}

func (rt *RetryRoundTripper) shouldRetry(attempt int, err error, resp *http.Response) bool {
	if attempt >= rt.cfg.MaxRetries {
		return false
	}
	if err != nil {
		return true
	}
	if resp != nil {
		for _, code := range rt.cfg.RetryableStatus {
			if resp.StatusCode == code {
				return true
			}
		}
	}
	return false
}
