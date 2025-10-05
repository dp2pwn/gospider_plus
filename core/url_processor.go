package core

import (
	"fmt"
	"strings"

	"github.com/gocolly/colly/v2"
	jsoniter "github.com/json-iterator/go"
)

// URLProcessor handles the processing of URLs found by the crawler.
// It is responsible for normalizing, filtering, and queueing URLs for crawling.
type URLProcessor struct {
	crawler     *Crawler
	registry    *URLRegistry
	initialHost string
}

// NewURLProcessor creates a new URLProcessor.
func NewURLProcessor(crawler *Crawler) *URLProcessor {
	return &URLProcessor{
		crawler:     crawler,
		registry:    crawler.registry,
		initialHost: crawler.site.Hostname(),
	}
}

// Process handles a found URL, normalizes it, checks for duplicates, and returns it for visiting.
func (p *URLProcessor) Process(rawURL, source, outputType string, request *colly.Request) string {
	// Normalize the URL against the request's URL first, then the crawler's site URL.
	normalizedURL, ok := NormalizeURL(request.URL, rawURL)
	if !ok {
		normalizedURL, ok = NormalizeURL(p.crawler.site, rawURL)
		if !ok {
			return ""
		}
	}

	// Check for duplicates before proceeding.
	if p.registry.Duplicate(normalizedURL) {
		return ""
	}

	if p.crawler.Stats != nil {
		p.crawler.Stats.IncrementURLsFound()
	}

	p.logOutput(normalizedURL, source, outputType)

	// Return the URL to be visited.
	return normalizedURL
}

// ProcessJSURL handles URLs found in JavaScript files. It's similar to Process but adapted for JS files.
func (p *URLProcessor) ProcessJSURL(rawURL, source, outputType string) {
	if p.registry.Duplicate(rawURL) {
		return
	}

	if p.crawler.Stats != nil {
		p.crawler.Stats.IncrementURLsFound()
	}

	p.logOutput(rawURL, source, outputType)

	// Special handling for .min.js files
	if strings.Contains(rawURL, ".min.js") {
		originalJS := strings.ReplaceAll(rawURL, ".min.js", ".js")
		_ = p.crawler.C.Visit(originalJS)
	}

	_ = p.crawler.C.Visit(rawURL)
}

// logOutput handles the printing and storing of the found URL.
func (p *URLProcessor) logOutput(url, source, outputType string) {
	outputFormat := fmt.Sprintf("[%s] - %s", outputType, url)

	if p.crawler.JsonOutput {
		sout := SpiderOutput{
			Input:      p.crawler.Input,
			Source:     source,
			OutputType: outputType,
			Output:     url,
		}
		if data, err := jsoniter.MarshalToString(sout); err == nil {
			outputFormat = data
		}
	} else if p.crawler.Quiet {
		outputFormat = url
	}

	fmt.Println(outputFormat)
	if p.crawler.Output != nil {
		p.crawler.Output.WriteToFile(outputFormat)
	}
}