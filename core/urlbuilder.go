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
	resolved.Path = cleanPath(resolved.Path)

	if shouldExclude(resolved) {
		return "", false
	}

	return resolved.String(), true
}

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	// Collapse duplicate slashes.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
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
