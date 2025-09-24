package core

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	katanaOutput "github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/filters"
)

// DeepCrawlWithKatana performs an additional deep crawl using Katana standard engine.
func (crawler *Crawler) DeepCrawlWithKatana(cfg CrawlerConfig) error {
	if cfg.Registry == nil {
		cfg.Registry = NewURLRegistry()
	}

	options := types.DefaultOptions
	intensity := cfg.Intensity
	if intensity == "" {
		intensity = IntensityUltra
	}

	options.URLs = goflags.StringSlice{crawler.Input}
	options.MaxDepth = resolveKatanaDepth(cfg.MaxDepth, cfg.Intensity)
	if cfg.MaxConcurrency > 0 {
		options.Concurrency = cfg.MaxConcurrency
		options.Parallelism = cfg.MaxConcurrency
	}
	if cfg.Delay > 0 {
		options.Delay = int(cfg.Delay / time.Second)
	}
	if cfg.Timeout > 0 {
		options.Timeout = int(cfg.Timeout / time.Second)
	}
	if options.Timeout <= 0 {
		options.Timeout = types.DefaultOptions.Timeout
	}
	if intensity == IntensityUltra {
		multiplier := 10
		baseConc := options.Concurrency
		if baseConc <= 0 {
			if cfg.MaxConcurrency > 0 {
				baseConc = cfg.MaxConcurrency
			} else {
				baseConc = 10
			}
		}
		options.Concurrency = baseConc * multiplier
		options.Parallelism = baseConc * multiplier
		if options.RateLimit <= 0 {
			options.RateLimit = 150
		}
		options.RateLimit *= multiplier
		if options.RateLimitMinute > 0 {
			options.RateLimitMinute *= multiplier
		} else {
			options.RateLimitMinute = options.RateLimit * multiplier
		}
		if options.CrawlDuration == 0 {
			options.CrawlDuration = 30 * time.Minute
		} else {
			options.CrawlDuration *= time.Duration(multiplier)
		}
		options.KnownFiles = "all"
		options.TechDetect = true
		options.NoScope = true
		options.DisplayOutScope = true
	}

	if cfg.Proxy != "" {
		options.Proxy = cfg.Proxy
	}
	if cfg.NoRedirect {
		options.DisableRedirects = true
	}

	if len(cfg.Headers) > 0 {
		hdrs := make(goflags.StringSlice, 0, len(cfg.Headers))
		hdrs = append(hdrs, cfg.Headers...)
		options.CustomHeaders = hdrs
	}
	if cfg.Cookie != "" {
		options.CustomHeaders = append(options.CustomHeaders, fmt.Sprintf("Cookie: %s", cfg.Cookie))
	}
	if cfg.UserAgent != "" && cfg.UserAgent != "web" && cfg.UserAgent != "mobi" {
		options.CustomHeaders = append(options.CustomHeaders, fmt.Sprintf("User-Agent: %s", cfg.UserAgent))
	}

	options.Silent = crawler.Quiet && !crawler.JsonOutput
	options.JSON = false
	options.Verbose = false
	options.Debug = false

	options.PathClimb = true
	options.ScrapeJSResponses = true
	options.ScrapeJSLuiceResponses = true
	options.FormExtraction = true
	options.AutomaticFormFill = true
	options.XhrExtraction = true

	options.FieldScope = resolveFieldScope(cfg, crawler.site)
	scopeSlice, outScopeSlice := buildScopeRules(cfg, crawler.site)
	if len(scopeSlice) > 0 {
		options.Scope = scopeSlice
	}
	if len(outScopeSlice) > 0 {
		options.OutOfScope = outScopeSlice
	}

	options.OnResult = func(res katanaOutput.Result) {
		crawler.handleKatanaResult(res)
	}

	crawlerOptions, err := types.NewCrawlerOptions(&options)
	if err != nil {
		return err
	}
	defer crawlerOptions.Close()

	if cfg.Registry != nil {
		crawlerOptions.UniqueFilter = newFilterAdapter(cfg.Registry, crawlerOptions.UniqueFilter)
	}

	if crawlerOptions.OutputWriter != nil {
		_ = crawlerOptions.OutputWriter.Close()
	}
	crawlerOptions.OutputWriter = noopWriter{}

	katanaCrawler, err := standard.New(crawlerOptions)
	if err != nil {
		return err
	}
	defer katanaCrawler.Close()

	return katanaCrawler.Crawl(crawler.Input)
}

func resolveKatanaDepth(depth int, intensity ExtractorIntensity) int {
	if depth <= 0 {
		depth = 25
	}
	if intensity == IntensityUltra {
		if depth < 25 {
			depth = 25
		}
		depth *= 10
		if depth < 100 {
			depth = 100
		}
	}
	return depth
}

func resolveFieldScope(cfg CrawlerConfig, site *url.URL) string {
	if cfg.WhitelistDomain != "" {
		return cfg.WhitelistDomain
	}
	if cfg.Subs {
		return "rdn"
	}
	return "fqdn"
}

func buildScopeRules(cfg CrawlerConfig, site *url.URL) (goflags.StringSlice, goflags.StringSlice) {
	var scopeSlice goflags.StringSlice
	var outScopeSlice goflags.StringSlice

	hostPattern := regexp.QuoteMeta(site.Hostname())
	if cfg.Whitelist != "" {
		scopeSlice = append(scopeSlice, cfg.Whitelist)
	} else {
		if cfg.Subs {
			scopeSlice = append(scopeSlice, fmt.Sprintf("(?i)%s", hostPattern))
		} else {
			scopeSlice = append(scopeSlice, fmt.Sprintf("(?i)^https?://%s", hostPattern))
		}
	}

	if cfg.Blacklist != "" {
		outScopeSlice = append(outScopeSlice, cfg.Blacklist)
	}
	return scopeSlice, outScopeSlice
}

type noopWriter struct{}

func (noopWriter) Close() error                       { return nil }
func (noopWriter) Write(*katanaOutput.Result) error   { return nil }
func (noopWriter) WriteErr(*katanaOutput.Error) error { return nil }

type filterAdapter struct {
	registry *URLRegistry
	inner    filters.Filter
}

func newFilterAdapter(reg *URLRegistry, inner filters.Filter) filters.Filter {
	return &filterAdapter{registry: reg, inner: inner}
}

func (f *filterAdapter) Close() {
	if f.inner != nil {
		f.inner.Close()
	}
}

func (f *filterAdapter) UniqueURL(u string) bool {
	if f.inner != nil && !f.inner.UniqueURL(u) {
		return false
	}
	if f.registry != nil && f.registry.DuplicateRequest(http.MethodGet, u, "") {
		return false
	}
	return true
}

func (f *filterAdapter) UniqueContent(content []byte) bool {
	if f.inner != nil {
		return f.inner.UniqueContent(content)
	}
	return true
}

func (f *filterAdapter) IsCycle(u string) bool {
	if f.inner != nil {
		return f.inner.IsCycle(u)
	}
	return false
}

func (crawler *Crawler) handleKatanaResult(res katanaOutput.Result) {
	method := ""
	body := ""
	target := ""
	if res.Request != nil {
		method = res.Request.Method
		body = res.Request.Body
		target = res.Request.URL
	}
	if target == "" && res.Response != nil && res.Response.Resp != nil && res.Response.Resp.Request != nil && res.Response.Resp.Request.URL != nil {
		target = res.Response.Resp.Request.URL.String()
	}
	if target == "" {
		return
	}
	target = NormalizeDisplayURL(target)
	if crawler.isDuplicateRequest(method, target, body) {
		return
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	status := 0
	length := 0
	if res.Response != nil {
		status = res.Response.StatusCode
		if res.Response.ContentLength > 0 {
			length = int(res.Response.ContentLength)
		} else if res.Response.Body != "" {
			length = len(res.Response.Body)
		}
	}
	if method == http.MethodPost && status > 0 {
		Logger.Infof("[post-hit] %s %s (%d)", method, target, status)
	}
	line := crawler.renderKatanaLine(res, target, method, status, length)
	if line == "" {
		return
	}
	if !crawler.Quiet || crawler.JsonOutput {
		fmt.Println(line)
	} else if crawler.Quiet {
		fmt.Println(line)
	}
	if crawler.Output != nil {
		crawler.Output.WriteToFile(line)
	}
}

func (crawler *Crawler) renderKatanaLine(res katanaOutput.Result, target, method string, status, length int) string {
	source := "katana"
	if res.Request != nil && res.Request.Source != "" {
		source = res.Request.Source
	}
	methodTag := strings.ToUpper(strings.TrimSpace(method))
	if methodTag == "" {
		methodTag = http.MethodGet
	}
	outputType := "katana"
	if methodTag != http.MethodGet {
		outputType = "katana-" + strings.ToLower(methodTag)
	}
	if crawler.JsonOutput {
		sout := SpiderOutput{
			Input:      crawler.Input,
			Source:     source,
			OutputType: outputType,
			Output:     target,
			StatusCode: status,
			Length:     length,
		}
		if data, err := jsoniter.MarshalToString(sout); err == nil {
			return data
		}
	}
	if crawler.Quiet {
		if methodTag != http.MethodGet {
			return fmt.Sprintf("%s %s", methodTag, target)
		}
		return target
	}
	builder := strings.Builder{}
	builder.WriteString("[katana]")
	if methodTag != http.MethodGet {
		builder.WriteString("[" + methodTag + "]")
	}
	if status > 0 {
		builder.WriteString(fmt.Sprintf("[%d]", status))
	}
	builder.WriteString(" ")
	builder.WriteString(target)
	if length > 0 {
		builder.WriteString(fmt.Sprintf(" (%d)", length))
	}
	if source != "" {
		builder.WriteString(fmt.Sprintf(" <- %s", source))
	}
	return builder.String()
}
