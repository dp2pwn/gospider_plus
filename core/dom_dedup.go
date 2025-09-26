package core

import (
	"bytes"
	"hash/fnv"
	"math/bits"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

// DOMDeduper tracks DOM signatures to avoid reprocessing near-duplicate documents.
type DOMDeduper struct {
	threshold int
	mu        sync.Mutex
	buckets   map[string][]uint64
}

// NewDOMDeduper returns a deduper that treats signatures within the given Hamming distance as duplicates.
func NewDOMDeduper(threshold int) *DOMDeduper {
	if threshold <= 0 {
		threshold = 6
	}
	return &DOMDeduper{threshold: threshold, buckets: make(map[string][]uint64)}
}

// ShouldSkip computes the DOM signature and reports whether it is similar to a previously seen document for the domain.
func (d *DOMDeduper) ShouldSkip(domain string, body []byte) (bool, uint64, error) {
	if len(body) == 0 {
		return false, 0, nil
	}
	sig, err := ComputeDOMSignature(body)
	if err != nil {
		return false, 0, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	seen := d.buckets[domain]
	for _, existing := range seen {
		if HammingDistance(existing, sig) <= d.threshold {
			return true, sig, nil
		}
	}
	d.buckets[domain] = append(seen, sig)
	return false, sig, nil
}

// ComputeDOMSignature normalises the DOM tree and calculates a SimHash-style 64-bit signature.
func ComputeDOMSignature(body []byte) (uint64, error) {
	reader := bytes.NewReader(body)
	doc, err := goquery.NewDocumentFromReader(reader)
	if err != nil {
		return 0, err
	}
	features := make([]string, 0, 256)
	doc.Find("*").EachWithBreak(func(_ int, sel *goquery.Selection) bool {
		node := sel.Get(0)
		if node == nil {
			return true
		}
		tag := strings.ToLower(node.Data)
		if tag == "" {
			return true
		}
		features = append(features, "tag:"+tag)
		for _, attr := range node.Attr {
			name := strings.ToLower(attr.Key)
			if name == "" {
				continue
			}
			if strings.HasPrefix(name, "data-") {
				continue
			}
			if name == "style" {
				continue
			}
			features = append(features, "attr:"+name)
		}
		if tag != "script" && tag != "style" {
			if strings.TrimSpace(sel.Text()) != "" {
				features = append(features, "text:present")
			}
		}
		if len(features) >= 2048 {
			return false
		}
		return true
	})
	if len(features) == 0 {
		features = append(features, "empty")
	}
	return simhash(features), nil
}

func simhash(features []string) uint64 {
	if len(features) == 0 {
		return 0
	}
	var weights [64]int
	for _, feature := range features {
		h := fnv.New64a()
		_, _ = h.Write([]byte(feature))
		sig := h.Sum64()
		for i := 0; i < 64; i++ {
			if (sig>>uint(i))&1 == 1 {
				weights[i]++
			} else {
				weights[i]--
			}
		}
	}
	var result uint64
	for i := 0; i < 64; i++ {
		if weights[i] >= 0 {
			result |= 1 << uint(i)
		}
	}
	return result
}

// HammingDistance calculates the Hamming distance between two 64-bit signatures.
func HammingDistance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

func isLikelyHTML(contentType string, body []byte) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed)
	return bytes.HasPrefix(lower, []byte("<!doctype html")) || bytes.HasPrefix(lower, []byte("<html"))
}

func isLikelyJS(contentType string, body []byte) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "ecmascript") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed)
	return bytes.HasPrefix(lower, []byte("function")) || bytes.HasPrefix(lower, []byte("(()")) || bytes.Contains(lower[:min(64, len(lower))], []byte("var "))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
