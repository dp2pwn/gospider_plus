package core

import (
	"net/url"
	"testing"

	"github.com/gocolly/colly/v2"
	"github.com/stretchr/testify/assert"
)

// setupTestProcessor creates a mock crawler and URL processor for testing.
func setupTestProcessor(t *testing.T) (*URLProcessor, *URLRegistry, *CrawlStats) {
	siteURL, _ := url.Parse("http://example.com")
	registry := NewURLRegistry()
	stats := NewCrawlStats()

	// Create a minimal Crawler for the processor to use
	crawler := &Crawler{
		site:     siteURL,
		registry: registry,
		Stats:    stats,
		Quiet:    true,
	}
	processor := NewURLProcessor(crawler)

	return processor, registry, stats
}

func TestURLProcessor_Process(t *testing.T) {
	processor, registry, stats := setupTestProcessor(t)

	// Mock a colly request. It's needed for URL normalization context.
	// We don't need a real collector associated with it anymore.
	req := &colly.Request{
		URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		Ctx: colly.NewContext(),
	}

	// Case 1: Process a new, valid URL
	testURL := "/about"
	normalizedURL := "http://example.com/about"

	resultURL := processor.Process(testURL, "html", "href", req)
	assert.Equal(t, normalizedURL, resultURL, "Process should return the normalized URL")

	// Assert that the URL was added to the registry
	assert.True(t, registry.Duplicate(normalizedURL), "URL should be in registry after processing")
	assert.Equal(t, int64(1), stats.GetURLsFound(), "URL count should be incremented for a new URL")

	// Case 2: Process a duplicate URL
	resultURL = processor.Process(testURL, "html", "href", req)
	assert.Equal(t, "", resultURL, "Process should return an empty string for a duplicate URL")
	assert.Equal(t, int64(1), stats.GetURLsFound(), "URL count should not increment for a duplicate URL")

	// Case 3: Process an invalid URL
	resultURL = processor.Process("javascript:void(0)", "html", "href", req)
	assert.Equal(t, "", resultURL, "Process should return an empty string for an invalid URL")
	assert.Equal(t, int64(1), stats.GetURLsFound(), "URL count should not increment for an invalid URL")
}

func TestURLProcessor_ProcessJSURL(t *testing.T) {
	processor, registry, stats := setupTestProcessor(t)

	// We need a real collector for this test to verify visits
	c := colly.NewCollector()
	var visitedURLs []string
	c.OnRequest(func(r *colly.Request) {
		visitedURLs = append(visitedURLs, r.URL.String())
	})
	processor.crawler.C = c // Inject the collector

	// Case 1: Process a new JS URL
	jsURL := "http://example.com/assets/app.js"
	processor.ProcessJSURL(jsURL, "javascript", "script")

	assert.True(t, registry.Duplicate(jsURL), "JS URL should be in registry")
	assert.Equal(t, int64(1), stats.GetURLsFound(), "URL count should be incremented")
	assert.Contains(t, visitedURLs, jsURL, "Collector should visit the JS URL")

	// Case 2: Process a minified JS URL
	minifiedJSURL := "http://example.com/assets/vendor.min.js"
	expectedOriginalURL := "http://example.com/assets/vendor.js"
	processor.ProcessJSURL(minifiedJSURL, "javascript", "script")

	assert.True(t, registry.Duplicate(minifiedJSURL), "Minified JS URL should be in registry")
	assert.Contains(t, visitedURLs, minifiedJSURL, "Collector should visit the minified JS URL")
	assert.Contains(t, visitedURLs, expectedOriginalURL, "Collector should also visit the non-minified JS URL")
}