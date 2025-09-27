package core

import (
	"net/url"
	"path"
	"strings"
)

var (
	linkExclusionFragments = []string{
		"wp-content", "wp-includes", "woocommerce", "captcha", "node_modules", "spinner.gif",
		"fontawesome", "gravatar", "schema.org", "gstatic.com", "cloudfront.net/static",
	}

	fileExtensionExclusions = map[string]struct{}{
		".zip": {}, ".dmg": {}, ".rpm": {}, ".deb": {}, ".gz": {}, ".tar": {}, ".tar.gz": {},
		".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".svg": {}, ".bmp": {}, ".ico": {},
		".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {}, ".mp3": {}, ".mp4": {},
		".avi": {}, ".mov": {}, ".mpeg": {}, ".css": {}, ".scss": {}, ".less": {}, ".exe": {},
	}
)

// NormalizeURL attempts to resolve the provided candidate relative to base and
// filters the result using xnLinkFinder-style exclusion lists.
func NormalizeURL(base *url.URL, candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}

	// Drop javascript/data/mailto style links early.
	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "data:") {
		return "", false
	}

	// Handle protocol-relative URLs explicitly when base is available.
	if strings.HasPrefix(candidate, "//") {
		if base != nil {
			candidate = base.Scheme + ":" + candidate
		} else {
			candidate = "http:" + candidate
		}
	}

	// Strip wrapping quotes or whitespace artifacts.
	candidate = strings.Trim(candidate, "\"'<>[](){} ")
	if candidate == "" {
		return "", false
	}

	var resolved *url.URL
	var err error
	if base != nil {
		resolved, err = base.Parse(candidate)
	} else {
		resolved, err = url.Parse(candidate)
	}
	if err != nil {
		return "", false
	}

	// Ensure we preserve scheme/host from base when missing.
	if resolved.Scheme == "" && base != nil {
		resolved.Scheme = base.Scheme
	}
	if resolved.Host == "" && base != nil {
		resolved.Host = base.Host
	}

	if resolved.Host == "" {
		return "", false
	}

	// Normalise path and drop fragments.
	resolved.Fragment = ""
	cleanedPath, ok := cleanPath(resolved.Path)
	if !ok {
		return "", false
	}
	resolved.Path = cleanedPath

	if hasRecursiveQuery(resolved) {
		return "", false
	}

	if shouldExclude(resolved) {
		return "", false
	}

	return resolved.String(), true
}

func cleanPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/", true
	}

	// Normalise slashes and separators.
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}

	trailingSlash := strings.HasSuffix(p, "/")
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return "/", true
	}

	parts := strings.Split(trimmed, "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, part)
		}
	}

	if len(segments) == 0 {
		return "/", true
	}

	if hasPathLoops(segments) {
		return "", false
	}

	normalized := "/" + strings.Join(segments, "/")
	if len(normalized) > 2048 {
		return "", false
	}
	if trailingSlash && normalized != "/" {
		normalized += "/"
	}
	return normalized, true
}

func hasPathLoops(segments []string) bool {
	if len(segments) > 128 {
		return true
	}

	lower := make([]string, len(segments))
	for i, seg := range segments {
		lower[i] = strings.ToLower(seg)
	}

	const maxRepeat = 3
	repeat := 1
	for i := 1; i < len(lower); i++ {
		if lower[i] == lower[i-1] {
			repeat++
			if repeat >= maxRepeat {
				return true
			}
		} else {
			repeat = 1
		}
	}

	const cycleThreshold = 3
	for cycleLen := 2; cycleLen <= 4 && cycleLen*cycleThreshold <= len(lower); cycleLen++ {
		if hasRepeatedCycle(lower, cycleLen, cycleThreshold) {
			return true
		}
	}

	return false
}

func hasRepeatedCycle(segments []string, cycleLen, threshold int) bool {
	limit := len(segments) - cycleLen*threshold
	if limit < 0 {
		return false
	}
	for start := 0; start <= len(segments)-cycleLen*threshold; start++ {
		repeats := 1
		for pos := start + cycleLen; pos+cycleLen <= len(segments); pos += cycleLen {
			if equalSegmentSlices(segments[start:start+cycleLen], segments[pos:pos+cycleLen]) {
				repeats++
				if repeats >= threshold {
					return true
				}
			} else {
				break
			}
		}
	}
	return false
}

func equalSegmentSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasRecursiveQuery(u *url.URL) bool {
	if u == nil || u.RawQuery == "" {
		return false
	}

	if len(u.RawQuery) > 4096 {
		return true
	}

	const repeatThreshold = 3

	hostLower := strings.ToLower(u.Hostname())
	rawLower := strings.ToLower(u.RawQuery)
	if hostLower != "" && strings.Count(rawLower, hostLower) >= repeatThreshold {
		return true
	}

	encodedHTTPCount := strings.Count(rawLower, "http%3a%2f%2f") + strings.Count(rawLower, "https%3a%2f%2f")
	if encodedHTTPCount >= repeatThreshold {
		return true
	}

	decoded, err := url.QueryUnescape(u.RawQuery)
	if err == nil {
		decodedLower := strings.ToLower(decoded)
		if hostLower != "" && strings.Count(decodedLower, hostLower) >= repeatThreshold {
			return true
		}
		if strings.Count(decodedLower, "http://") >= repeatThreshold || strings.Count(decodedLower, "https://") >= repeatThreshold {
			return true
		}
		if strings.Count(decodedLower, "404;") >= repeatThreshold {
			return true
		}
	}

	return false
}

func shouldExclude(u *url.URL) bool {
	pathLower := strings.ToLower(u.Path)
	for _, frag := range linkExclusionFragments {
		if strings.Contains(pathLower, frag) {
			return true
		}
	}

	ext := strings.ToLower(path.Ext(u.Path))
	if ext != "" {
		if _, ok := fileExtensionExclusions[ext]; ok {
			return true
		}
	}

	return false
}
