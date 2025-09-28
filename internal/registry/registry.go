package registry

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/jaeles-project/gospider/internal/netutil"
	"github.com/jaeles-project/gospider/stringset"
)

type URLRegistry struct {
	once       sync.Once
	filter     *stringset.StringFilter
	respMu     sync.Mutex
	respHashes map[string]string
}

func NewURLRegistry() *URLRegistry {
	return &URLRegistry{}
}

func (r *URLRegistry) ensure() {
	r.once.Do(func() {
		r.filter = stringset.NewStringFilter()
		r.respHashes = make(map[string]string)
	})
}

func (r *URLRegistry) Duplicate(raw string) bool {
	return r.DuplicateRequest(http.MethodGet, raw, "")
}

func (r *URLRegistry) DuplicateRequest(method, rawURL, body string) bool {
	key := canonicalRequestKey(method, rawURL, body)
	if key == "" {
		return false
	}

	r.ensure()
	return r.filter.Duplicate(key)
}

func (r *URLRegistry) MarkResponse(method, rawURL string, body []byte) bool {
	key := canonicalRequestKey(method, rawURL, "")
	if key == "" {
		return false
	}
	hash := hashContent(body)

	r.ensure()
	r.respMu.Lock()
	defer r.respMu.Unlock()
	previous, seen := r.respHashes[key]
	if seen && previous == hash {
		return true
	}
	r.respHashes[key] = hash
	return false
}

func (r *URLRegistry) Filter() *stringset.StringFilter {
	r.ensure()
	return r.filter
}

func canonicalRequestKey(method, rawURL, body string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return method + " " + strings.TrimSpace(rawURL)
	}

	parsed.Fragment = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = normalizeHost(parsed)
	parsed.Path = netutil.NormalizePathComponent(parsed.Path)

	if parsed.RawQuery != "" {
		parsed.RawQuery = netutil.NormalizeQuery(parsed.RawQuery)
	}

	canonicalURL := netutil.NormalizeDisplayURL(parsed.String())

	hash := hashContentString(body)
	if hash != "" {
		return method + " " + canonicalURL + " body:" + hash
	}
	return method + " " + canonicalURL
}

func hashContent(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	return hashContentString(string(content))
}

func hashContentString(content string) string {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return ""
	}
	sum := sha1.Sum([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

func normalizeHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		return host
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		return host
	}
	return host + ":" + port
}
