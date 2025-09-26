package core

import (
	"regexp"
	"strings"
	"sync"
)

type domRule struct {
	name       string
	confidence string
	pattern    *regexp.Regexp
	sinks      []string
}

// DOMFinding captures a static sink suspicion discovered during passive analysis.
type DOMFinding struct {
	URL        string
	Source     string
	Sink       string
	Snippet    string
	Confidence string
}

// DOMAnalyzer scans HTML/JS for common DOM sink antipatterns inspired by domdig.
type DOMAnalyzer struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	rules []domRule
}

// NewDOMAnalyzer initialises the rule set.
func NewDOMAnalyzer() *DOMAnalyzer {
	rules := []domRule{
		{
			name:       "innerHTML-assignment",
			confidence: "medium",
			pattern:    regexp.MustCompile(`(?i)(innerHTML|outerHTML)\s*=\s*([^;\n]+)`),
			sinks:      []string{`location`, `document\.cookie`, `document\.url`, `document\.documentURI`, `document\.referrer`, `window\.name`, `localStorage`, `sessionStorage`, `search`, `hash`},
		},
		{
			name:       "document-write",
			confidence: "medium",
			pattern:    regexp.MustCompile(`(?i)document\.(write|writeln)\s*\(([^)]*)\)`),
			sinks:      []string{`location`, `document\.cookie`, `document\.url`, `hash`, `search`, `responseText`},
		},
		{
			name:       "eval-family",
			confidence: "high",
			pattern:    regexp.MustCompile(`(?i)(eval|Function|setTimeout|setInterval)\s*\(([^)]*)\)`),
			sinks:      []string{`location`, `document\.cookie`, `document\.url`, `hash`, `search`, `innerHTML`, `outerHTML`},
		},
		{
			name:       "postMessage-relay",
			confidence: "medium",
			pattern:    regexp.MustCompile(`(?i)postMessage\s*\(([^,]+),`),
			sinks:      []string{`location`, `document\.url`, `hash`, `origin`},
		},
	}
	return &DOMAnalyzer{
		seen:  make(map[string]struct{}),
		rules: rules,
	}
}

// Analyze runs the rule set and returns new findings for the given document source label (html/javascript).
func (a *DOMAnalyzer) Analyze(url, code, sourceLabel string) []DOMFinding {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rules == nil {
		return nil
	}
	findings := make([]DOMFinding, 0)
	for _, rule := range a.rules {
		matches := rule.pattern.FindAllStringSubmatchIndex(code, -1)
		for _, idxs := range matches {
			if len(idxs) < 4 {
				continue
			}
			sinkName := strings.TrimSpace(code[idxs[2]:idxs[3]])
			snippet := strings.TrimSpace(code[idxs[0]:idxs[1]])
			if snippet == "" {
				continue
			}
			if isSanitisedSnippet(snippet) {
				continue
			}
			if !containsSuspiciousSource(strings.TrimSpace(code[idxs[4]:idxs[5]]), rule.sinks) {
				continue
			}
			key := url + "|" + rule.name + "|" + snippet
			if _, ok := a.seen[key]; ok {
				continue
			}
			a.seen[key] = struct{}{}
			findings = append(findings, DOMFinding{
				URL:        url,
				Source:     sourceLabel,
				Sink:       sinkName,
				Snippet:    snippet,
				Confidence: rule.confidence,
			})
		}
	}
	return findings
}

func containsSuspiciousSource(snippet string, patterns []string) bool {
	lower := strings.ToLower(snippet)
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, lower); matched {
			return true
		}
	}
	return false
}

func isSanitisedSnippet(snippet string) bool {
	lower := strings.ToLower(snippet)
	if strings.Contains(lower, "dompurify") || strings.Contains(lower, "sanitize") {
		return true
	}
	if strings.Contains(lower, ".replace(") && strings.Contains(lower, "<") {
		return true
	}
	return false
}
