package core

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/jaeles-project/gospider/core/antidetect"
	"github.com/jaeles-project/gospider/stringset"
)

type Crawler struct {
	C                   *colly.Collector
	LinkFinderCollector *colly.Collector
	Output              *Output
	AntiDetectClient    *antidetect.AntiDetectClient

	subSet       *stringset.StringFilter
	awsSet       *stringset.StringFilter
	jsSet        *stringset.StringFilter
	jsRequestSet *stringset.StringFilter
	urlSet       *stringset.StringFilter
	formSet      *stringset.StringFilter

	site             *url.URL
	domain           string
	Input            string
	Quiet            bool
	JsonOutput       bool
	length           bool
	raw              bool
	subs             bool
	reflected        bool
	reflectedPayload string
	reflectedStore   map[string]*reflectionEntry
	reflectedMutex   sync.Mutex
	reflectedWriter  *Output
	registry         *URLRegistry
	backoffMutex     sync.Mutex
	backoff429       int
	backoff403       int
	backoffError     int

	filterLength_slice []int
	domDedup           bool
	domDedupThresh     int
	domDeduper         *DOMDeduper
	domSkip            map[string]bool
	domSkipMu          sync.RWMutex
	baselineFuzzCap    int
	payloadVariants    []PayloadVariant
	baselinePayloads   []PayloadVariant
	payloadRNG         *rand.Rand
	payloadRNGMutex    sync.Mutex
	domAnalyzer        *DOMAnalyzer
	jsRequestLogSet    *stringset.StringFilter

	hybridEnabled  bool
	hybridWorkers  int
	stateGraph     *ApplicationStateGraph
	browserPool    *BrowserPool
	hybridQueue    chan string
	hybridVisited  *stringset.StringFilter
	hybridAPISet   *stringset.StringFilter
	hybridCtx      context.Context
	hybridCancel   context.CancelFunc
	hybridWG       sync.WaitGroup
	hybridActive   atomic.Bool
	hybridVisitCap int
	hybridEnqueued int64
}

type SpiderOutput struct {
	Input      string `json:"input"`
	Source     string `json:"source"`
	OutputType string `json:"type"`
	Output     string `json:"output"`
	StatusCode int    `json:"status"`
	Length     int    `json:"length"`
	Param      string `json:"param,omitempty"`
	Payload    string `json:"payload,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
}

func (crawler *Crawler) isDuplicateURL(raw string) bool {
	return crawler.isDuplicateRequest(http.MethodGet, raw, "")
}

func (crawler *Crawler) isDuplicateRequest(method, raw, body string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	if crawler.registry != nil {
		if crawler.registry.DuplicateRequest(method, raw, body) {
			return true
		}
	}
	if method == http.MethodGet {
		value := strings.TrimSpace(raw)
		if value == "" {
			return true
		}
		if crawler.urlSet == nil {
			crawler.urlSet = stringset.NewStringFilter()
		}
		return crawler.urlSet.Duplicate(value)
	}
	return false
}

func (crawler *Crawler) shouldSkipDOM(raw string) bool {
	if !crawler.domDedup {
		return false
	}
	crawler.domSkipMu.RLock()
	defer crawler.domSkipMu.RUnlock()
	return crawler.domSkip != nil && crawler.domSkip[raw]
}

func (crawler *Crawler) setDOMSkip(raw string, skip bool) {
	if !crawler.domDedup {
		return
	}
	if crawler.domSkip == nil {
		crawler.domSkip = make(map[string]bool)
	}
	crawler.domSkipMu.Lock()
	if skip {
		crawler.domSkip[raw] = true
	} else {
		delete(crawler.domSkip, raw)
	}
	crawler.domSkipMu.Unlock()
}

func (crawler *Crawler) emitDOMFindings(url, body, sourceLabel string) {
	if crawler.domAnalyzer == nil {
		return
	}
	findings := crawler.domAnalyzer.Analyze(url, body, sourceLabel)
	if len(findings) == 0 {
		return
	}
	for _, finding := range findings {
		rendered := fmt.Sprintf("[dom-sink] - [%s] %s -> %s", finding.Confidence, finding.Source, finding.Sink)
		if finding.Snippet != "" {
			rendered = fmt.Sprintf("%s :: %s", rendered, finding.Snippet)
		}
		output := rendered
		if crawler.JsonOutput {
			sout := SpiderOutput{
				Input:      crawler.Input,
				Source:     finding.Source,
				OutputType: "dom-sink",
				Output:     url,
				Param:      finding.Sink,
				Payload:    finding.Snippet,
				Confidence: finding.Confidence,
				Snippet:    finding.Snippet,
			}
			if data, err := jsoniter.MarshalToString(sout); err == nil {
				output = data
			}
		} else if crawler.Quiet {
			output = fmt.Sprintf("%s %s", url, finding.Sink)
		}
		fmt.Println(output)
		if crawler.Output != nil {
			crawler.Output.WriteToFile(output)
		}
	}
}
func (crawler *Crawler) maybeThrottleMutations(reflected bool) {
	if reflected {
		return
	}
	if crawler.baselineFuzzCap <= 0 {
		return
	}
	crawler.payloadRNGMutex.Lock()
	rng := crawler.payloadRNG
	crawler.payloadRNGMutex.Unlock()
	if rng == nil {
		return
	}
	wait := 50 + rng.Intn(120)
	time.Sleep(time.Duration(wait) * time.Millisecond)
}

func NewCrawler(site *url.URL, cfg CrawlerConfig) *Crawler {
	domain := GetDomain(site)
	if domain == "" {
		Logger.Error("Failed to parse domain")
		os.Exit(1)
	}
	Logger.Infof("Start crawling: %s", site)
	registry := cfg.Registry
	if registry == nil {
		registry = NewURLRegistry()
	}

	quiet := cfg.Quiet
	jsonOutput := cfg.JSONOutput
	maxDepth := cfg.MaxDepth
	concurrent := cfg.MaxConcurrency
	delay := cfg.Delay
	randomDelay := cfg.RandomDelay
	length := cfg.Length
	raw := cfg.Raw
	subs := cfg.Subs
	reflected := cfg.Reflected

	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(maxDepth),
		colly.IgnoreRobotsTxt(),
	)

	antiDetectConfig := antidetect.DefaultAntiDetectConfig()

	if cfg.Stealth {
		antiDetectConfig.EnableTLSFingerprinting = true
		antiDetectConfig.EnableHTTP2Fingerprinting = true
		antiDetectConfig.EnableUserAgentRotation = true
		antiDetectConfig.EnableHeaderRandomization = true
		antiDetectConfig.EnableTimingRandomization = true
		antiDetectConfig.BrowserProfile = "random"
	}

	antiDetectClient := antidetect.NewAntiDetectClient(antiDetectConfig)

	if cfg.Proxy != "" {
		Logger.Infof("Proxy: %s", cfg.Proxy)
		if err := antiDetectClient.SetProxy(cfg.Proxy); err != nil {
			Logger.Errorf("Failed to set proxy: %s", err)
		}
	}

	client := antiDetectClient.GetHTTPClient()

	if cfg.Timeout <= 0 {
		Logger.Info("Your input timeout is 0. Gospider will set it to 10 seconds")
		client.Timeout = 10 * time.Second
	} else {
		client.Timeout = cfg.Timeout
	}

	if cfg.NoRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			nextLocation := req.Response.Header.Get("Location")
			Logger.Debugf("Found Redirect: %s", nextLocation)
			if strings.Contains(nextLocation, site.Hostname()) {
				Logger.Infof("Redirecting to: %s", nextLocation)
				return nil
			}
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = nil
	}

	antiDetectClient.ApplyToCollyCollector(c)

	burpFile := cfg.BurpFile
	if burpFile != "" {
		bF, err := os.Open(burpFile)
		if err != nil {
			Logger.Errorf("Failed to open Burp File: %s", err)
		} else {
			rd := bufio.NewReader(bF)
			req, err := http.ReadRequest(rd)
			if err != nil {
				Logger.Errorf("Failed to Parse Raw Request in %s: %s", burpFile, err)
			} else {
				c.OnRequest(func(r *colly.Request) {
					r.Headers.Set("Cookie", GetRawCookie(req.Cookies()))
				})

				c.OnRequest(func(r *colly.Request) {
					for k, v := range req.Header {
						r.Headers.Set(strings.TrimSpace(k), strings.TrimSpace(v[0]))
					}
				})

			}
		}
	}

	if cfg.Cookie != "" && burpFile == "" {
		cookie := cfg.Cookie
		c.OnRequest(func(r *colly.Request) {
			r.Headers.Set("Cookie", cookie)
		})
	}

	if burpFile == "" {
		for _, h := range cfg.Headers {
			headerArgs := strings.SplitN(h, ":", 2)
			if len(headerArgs) != 2 {
				continue
			}
			headerKey := strings.TrimSpace(headerArgs[0])
			headerValue := strings.TrimSpace(headerArgs[1])
			if headerKey == "" {
				continue
			}
			c.OnRequest(func(r *colly.Request) {
				r.Headers.Set(headerKey, headerValue)
			})
		}
	}

	switch ua := cfg.UserAgent; {
	case ua == "mobi":
		extensions.RandomMobileUserAgent(c)
	case ua == "web":
		extensions.RandomUserAgent(c)
	default:
		c.UserAgent = ua
	}

	extensions.Referer(c)

	var output *Output
	if cfg.OutputDir != "" {
		filename := strings.ReplaceAll(site.Hostname(), ".", "_")
		output = NewOutput(cfg.OutputDir, filename)
	}

	var reflectedOutput *Output
	if cfg.ReflectedOutput != "" {
		reflectedOutput = NewOutputPath(cfg.ReflectedOutput)
		reflected = true
	}

	filterLengthSlice := []int{}
	if cfg.FilterLength != "" {
		lengthArgs := strings.Split(cfg.FilterLength, ",")
		for i := 0; i < len(lengthArgs); i++ {
			if v, err := strconv.Atoi(lengthArgs[i]); err == nil {
				filterLengthSlice = append(filterLengthSlice, v)
			}
		}
	}

	reg := ""
	hostPattern := regexp.QuoteMeta(site.Hostname())
	if subs {
		reg = "(?i)" + hostPattern
	} else {
		reg = "(?i)(?:https?://)" + hostPattern
	}

	sRegex := regexp.MustCompile(reg)
	c.URLFilters = append(c.URLFilters, sRegex)

	c.OnRequest(func(r *colly.Request) {
		if depthStr := r.Ctx.Get("__depth"); depthStr != "" {
			if depth, err := strconv.Atoi(depthStr); err == nil {
				r.Depth = depth
			}
		}
	})

	if err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: concurrent,
		Delay:       delay,
		RandomDelay: randomDelay,
	}); err != nil {
		Logger.Errorf("Failed to set Limit Rule: %s", err)
		os.Exit(1)
	}

	disallowedRegex := `(?i)\.(png|apng|bmp|gif|ico|cur|jpg|jpeg|jfif|pjp|pjpeg|svg|tif|tiff|webp|xbm|3gp|aac|flac|mpg|mpeg|mp3|mp4|m4a|m4v|m4p|oga|ogg|ogv|mov|wav|webm|eot|woff|woff2|ttf|otf|css)(?:\?|#|$)`
	c.DisallowedURLFilters = append(c.DisallowedURLFilters, regexp.MustCompile(disallowedRegex))

	if cfg.Blacklist != "" {
		c.DisallowedURLFilters = append(c.DisallowedURLFilters, regexp.MustCompile(cfg.Blacklist))
	}

	if cfg.Whitelist != "" {
		c.URLFilters = make([]*regexp.Regexp, 0)
		c.URLFilters = append(c.URLFilters, regexp.MustCompile(cfg.Whitelist))
	}

	if cfg.WhitelistDomain != "" {
		c.URLFilters = make([]*regexp.Regexp, 0)
		c.URLFilters = append(c.URLFilters, regexp.MustCompile("http(s)?://"+cfg.WhitelistDomain))
	}

	linkFinderCollector := c.Clone()
	linkFinderCollector.URLFilters = nil
	if cfg.Whitelist != "" {
		linkFinderCollector.URLFilters = append(linkFinderCollector.URLFilters, regexp.MustCompile(cfg.Whitelist))
	}
	if cfg.WhitelistDomain != "" {
		linkFinderCollector.URLFilters = append(linkFinderCollector.URLFilters, regexp.MustCompile("http(s)?://"+cfg.WhitelistDomain))
	}

	payloadVariants := DefaultPayloadVariants()
	baselinePayloads := SelectBaselinePayloads(payloadVariants)
	if len(baselinePayloads) == 0 {
		baselinePayloads = payloadVariants
	}
	var domDeduper *DOMDeduper
	if cfg.DomDedup {
		domDeduper = NewDOMDeduper(cfg.DomDedupThresh)
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	crawler := &Crawler{
		C:                   c,
		LinkFinderCollector: linkFinderCollector,
		AntiDetectClient:    antiDetectClient,
		site:                site,
		Quiet:               quiet,
		Input:               site.String(),
		JsonOutput:          jsonOutput,
		length:              length,
		raw:                 raw,
		domain:              domain,
		Output:              output,
		reflectedWriter:     reflectedOutput,
		registry:            registry,
		urlSet:              stringset.NewStringFilter(),
		subSet:              stringset.NewStringFilter(),
		jsSet:               stringset.NewStringFilter(),
		jsRequestSet:        stringset.NewStringFilter(),
		formSet:             stringset.NewStringFilter(),
		awsSet:              stringset.NewStringFilter(),
		subs:                subs,
		reflected:           reflected,
		reflectedPayload:    defaultReflectedPayload,
		reflectedStore:      make(map[string]*reflectionEntry),
		filterLength_slice:  filterLengthSlice,
		domDedup:            cfg.DomDedup,
		domDedupThresh:      cfg.DomDedupThresh,
		domDeduper:          domDeduper,
		domSkip:             make(map[string]bool),
		baselineFuzzCap:     cfg.BaselineFuzzCap,
		payloadVariants:     payloadVariants,
		baselinePayloads:    baselinePayloads,
		payloadRNG:          rng,
		domAnalyzer:         NewDOMAnalyzer(),
	}
	crawler.initializeHybrid(cfg)
	return crawler
}

func (crawler *Crawler) feedLinkfinder(jsFileUrl string, OutputType string, source string) {

	if !crawler.jsSet.Duplicate(jsFileUrl) {
		outputFormat := fmt.Sprintf("[%s] - %s", OutputType, jsFileUrl)

		if crawler.JsonOutput {
			sout := SpiderOutput{
				Input:      crawler.Input,
				Source:     source,
				OutputType: OutputType,
				Output:     jsFileUrl,
			}
			if data, err := jsoniter.MarshalToString(sout); err == nil {
				outputFormat = data
				fmt.Println(outputFormat)
			}

		} else if !crawler.Quiet {
			fmt.Println(outputFormat)
		}

		if crawler.Output != nil {
			crawler.Output.WriteToFile(outputFormat)
		}

		// If JS file is minimal format. Try to find original format
		if strings.Contains(jsFileUrl, ".min.js") {
			originalJS := strings.ReplaceAll(jsFileUrl, ".min.js", ".js")
			_ = crawler.LinkFinderCollector.Visit(originalJS)
		}

		// Send Javascript to Link Finder Collector
		_ = crawler.LinkFinderCollector.Visit(jsFileUrl)

	}
}

func (crawler *Crawler) emitJSRequest(req JSRequest, origin string) bool {
	if crawler.jsRequestLogSet == nil {
		crawler.jsRequestLogSet = stringset.NewStringFilter()
	}
	if crawler.jsRequestSet == nil {
		crawler.jsRequestSet = stringset.NewStringFilter()
	}

	key := buildRequestKey(req)
	if crawler.jsRequestSet.Duplicate(key) {
		return false
	}

	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = "GET"
	}

	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = origin
	}

	displayKey := strings.ToUpper(method) + " " + strings.TrimSpace(req.RawURL)
	shouldLog := true
	if crawler.jsRequestLogSet.Duplicate(displayKey) {
		shouldLog = false
	}
	rendered := fmt.Sprintf("[js-request] - [%s] %s", method, req.RawURL)
	if crawler.JsonOutput {
		sout := SpiderOutput{
			Input:      crawler.Input,
			Source:     source,
			OutputType: "js-request",
			Output:     strings.TrimSpace(method + " " + req.RawURL),
			Length:     len(req.Body),
		}
		if data, err := jsoniter.MarshalToString(sout); err == nil {
			rendered = data
		}
	} else if crawler.Quiet {
		rendered = strings.TrimSpace(method + " " + req.RawURL)
	}

	if shouldLog {
		fmt.Println(rendered)
		if crawler.Output != nil {
			crawler.Output.WriteToFile(rendered)
		}
	}

	return true
}

func (crawler *Crawler) Start(linkfinder bool) {
	// Setup Link Finder
	if linkfinder {
		crawler.setupLinkFinder()
	}

	// Handle url
	crawler.C.OnHTML("[href]", func(e *colly.HTMLElement) {
		if crawler.shouldSkipDOM(e.Request.URL.String()) {
			return
		}
		raw := e.Attr("href")
		urlString, ok := NormalizeURL(e.Request.URL, raw)
		if !ok {
			urlString, ok = NormalizeURL(crawler.site, raw)
			if !ok {
				return
			}
		}
		if !crawler.isDuplicateURL(urlString) {
			outputFormat := fmt.Sprintf("[href] - %s", urlString)
			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "form",
					Output:     urlString,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
					fmt.Println(outputFormat)
				}
			} else if !crawler.Quiet {
				fmt.Println(outputFormat)
			}
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
			_ = e.Request.Visit(urlString)
		}
	})

	// Handle form
	crawler.C.OnHTML("form", func(e *colly.HTMLElement) {
		if crawler.shouldSkipDOM(e.Request.URL.String()) {
			return
		}
		formURL := e.Request.URL.String()
		if !crawler.formSet.Duplicate(formURL) {
			outputFormat := fmt.Sprintf("[form] - %s", formURL)
			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "form",
					Output:     formURL,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
					fmt.Println(outputFormat)
				}
			} else if !crawler.Quiet {
				fmt.Println(outputFormat)
			}
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
		}

		requests := ExtractFormRequests(e.DOM, e.Request.URL)
		for _, req := range requests {
			req.Source = formURL
			crawler.processGeneratedRequest(req, formURL, e.Request.Depth)
		}
	})

	// Find Upload Form
	uploadFormSet := stringset.NewStringFilter()
	crawler.C.OnHTML(`input[type="file"]`, func(e *colly.HTMLElement) {
		if crawler.shouldSkipDOM(e.Request.URL.String()) {
			return
		}
		uploadUrl := e.Request.URL.String()
		if !uploadFormSet.Duplicate(uploadUrl) {
			outputFormat := fmt.Sprintf("[upload-form] - %s", uploadUrl)
			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "upload-form",
					Output:     uploadUrl,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
					fmt.Println(outputFormat)
				}
			} else if !crawler.Quiet {
				fmt.Println(outputFormat)
			}
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
		}

	})

	// Handle js files
	crawler.C.OnHTML("[src]", func(e *colly.HTMLElement) {
		if crawler.shouldSkipDOM(e.Request.URL.String()) {
			return
		}
		jsFileUrl, ok := NormalizeURL(e.Request.URL, e.Attr("src"))
		if !ok {
			jsFileUrl, ok = NormalizeURL(crawler.site, e.Attr("src"))
			if !ok {
				return
			}
		}

		fileExt := GetExtType(jsFileUrl)
		if fileExt == ".js" || fileExt == ".xml" || fileExt == ".json" {
			crawler.feedLinkfinder(jsFileUrl, "javascript", "body")
		}
	})

	crawler.C.OnResponse(func(response *colly.Response) {
		if response.Ctx != nil && response.Ctx.Get("reflected") == "true" {
			crawler.handleReflectedResponse(response)
			return
		}
		if crawler.reflected {
			crawler.handleBaselineReflection(response)
		}

		var urlStr string
		if response.Request != nil && response.Request.URL != nil {
			urlStr = response.Request.URL.String()
		}
		contentType := strings.ToLower(response.Headers.Get("Content-Type"))
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = strings.TrimSpace(contentType[:idx])
		}
		htmlLike := isLikelyHTML(contentType, response.Body)
		jsLike := isLikelyJS(contentType, response.Body)
		if htmlLike && urlStr != "" {
			crawler.enqueueHybrid(urlStr)
		}
		if crawler.domDedup && urlStr != "" {
			if htmlLike && crawler.domDeduper != nil {
				skip, _, err := crawler.domDeduper.ShouldSkip(crawler.domain, response.Body)
				if err != nil {
					Logger.Debugf("dom-dedup failed for %s: %v", urlStr, err)
				} else {
					crawler.setDOMSkip(urlStr, skip)
					if skip {
						Logger.Debugf("dom-dedup skip %s (threshold=%d)", urlStr, crawler.domDedupThresh)
					}
				}
			} else {
				crawler.setDOMSkip(urlStr, false)
			}
		}

		duplicateContent := false
		if crawler.registry != nil && response.Request != nil && response.Request.URL != nil {
			duplicateContent = crawler.registry.MarkResponse(response.Request.Method, response.Request.URL.String(), response.Body)
		}
		crawler.recordBackoff(response.StatusCode)
		respStr := DecodeChars(string(response.Body))

		if crawler.domAnalyzer != nil && urlStr != "" && (htmlLike || jsLike) && !crawler.shouldSkipDOM(urlStr) {
			sourceLabel := "html"
			if jsLike && !htmlLike {
				sourceLabel = "javascript"
			}
			crawler.emitDOMFindings(urlStr, respStr, sourceLabel)
		}

		if len(crawler.filterLength_slice) == 0 || !contains(crawler.filterLength_slice, len(respStr)) {
			if duplicateContent {
				return
			}

			// Verify which link is working
			u := NormalizeDisplayURL(response.Request.URL.String())
			outputFormat := fmt.Sprintf("[url] - [code-%d] - %s", response.StatusCode, u)

			if crawler.length {
				outputFormat = fmt.Sprintf("[url] - [code-%d] - [len_%d] - %s", response.StatusCode, len(respStr), u)
			}

			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "url",
					StatusCode: response.StatusCode,
					Output:     u,
					Length:     strings.Count(respStr, "\n"),
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
				}
			} else if crawler.Quiet {
				outputFormat = u
			}
			fmt.Println(outputFormat)
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
			if InScope(response.Request.URL, crawler.C.URLFilters) {
				crawler.findSubdomains(respStr)
				crawler.findAWSS3(respStr)
			}

			if crawler.raw {
				outputFormat := fmt.Sprintf("[Raw] - \n%s\n", respStr) //PRINTCLEAN RAW for link visited only
				if !crawler.Quiet {
					fmt.Println(outputFormat)
				}
				if crawler.Output != nil {
					crawler.Output.WriteToFile(outputFormat)
				}
			}
		}
	})

	crawler.C.OnError(func(response *colly.Response, err error) {
		Logger.Debugf("Error request: %s - Status code: %v - Error: %s", response.Request.URL.String(), response.StatusCode, err)
		crawler.recordBackoff(response.StatusCode)
		/*
			1xx Informational
			2xx Success
			3xx Redirection
			4xx Client Error
			5xx Server Error
		*/
		if response.StatusCode == 404 || response.StatusCode == 429 || response.StatusCode < 100 || response.StatusCode >= 500 {
			return
		}

		u := NormalizeDisplayURL(response.Request.URL.String())
		outputFormat := fmt.Sprintf("[url] - [code-%d] - %s", response.StatusCode, u)

		if crawler.JsonOutput {
			sout := SpiderOutput{
				Input:      crawler.Input,
				Source:     "body",
				OutputType: "url",
				StatusCode: response.StatusCode,
				Output:     u,
				Length:     strings.Count(DecodeChars(string(response.Body)), "\n"),
			}
			if data, err := jsoniter.MarshalToString(sout); err == nil {
				outputFormat = data
				fmt.Println(outputFormat)
			}
		} else if crawler.Quiet {
			fmt.Println(u)
		} else {
			fmt.Println(outputFormat)
		}

		if crawler.Output != nil {
			crawler.Output.WriteToFile(outputFormat)
		}
	})

	if crawler.subs {
		crawler.bootstrapSubdomains()
	}
	err := crawler.C.Visit(crawler.site.String())
	if err != nil {
		Logger.Errorf("Failed to start %s: %s", crawler.site.String(), err)
	}
}

func (crawler *Crawler) bootstrapSubdomains() {
	seeds := FetchSubdomains(crawler.domain)
	if len(seeds) == 0 {
		return
	}
	for _, sub := range seeds {
		if sub == "" {
			continue
		}
		if crawler.subSet != nil && crawler.subSet.Duplicate(sub) {
			continue
		}
		if crawler.subSet == nil {
			crawler.subSet = stringset.NewStringFilter()
		}
		_ = crawler.subSet.Duplicate(sub)

		logLine := "[subdomains] - " + sub
		if crawler.JsonOutput {
			sout := SpiderOutput{
				Input:      crawler.Input,
				Source:     "crt.sh",
				OutputType: "subdomain",
				Output:     sub,
			}
			if data, err := jsoniter.MarshalToString(sout); err == nil {
				logLine = data
			}
		} else if crawler.Quiet {
			logLine = sub
		}

		if !crawler.Quiet || crawler.JsonOutput {
			fmt.Println(logLine)
		}
		if crawler.Output != nil {
			crawler.Output.WriteToFile(logLine)
		}

		for _, scheme := range []string{"https", "http"} {
			seedURL := fmt.Sprintf("%s://%s", scheme, sub)
			if crawler.isDuplicateURL(seedURL) {
				continue
			}
			_ = crawler.C.Visit(seedURL)
		}
	}
}

// Find subdomains from response
func (crawler *Crawler) findSubdomains(resp string) {
	if !crawler.subs {
		return
	}
	subs := GetSubdomains(resp, crawler.domain)
	for _, sub := range subs {
		if !crawler.subSet.Duplicate(sub) {
			outputFormat := fmt.Sprintf("[subdomains] - %s", sub)

			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "subdomain",
					Output:     sub,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
				}
				fmt.Println(outputFormat)
			} else if !crawler.Quiet {
				outputFormat = fmt.Sprintf("[subdomains] - http://%s", sub)
				fmt.Println(outputFormat)
				outputFormat = fmt.Sprintf("[subdomains] - https://%s", sub)
				fmt.Println(outputFormat)
			}
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
		}
	}
}

// Find AWS S3 from response

func (crawler *Crawler) recordBackoff(status int) {
	sleep := time.Duration(0)
	if status >= 200 && status < 400 {
		crawler.backoffMutex.Lock()
		crawler.backoff429, crawler.backoff403, crawler.backoffError = 0, 0, 0
		crawler.backoffMutex.Unlock()
		return
	}

	crawler.backoffMutex.Lock()
	switch status {
	case http.StatusTooManyRequests:
		crawler.backoff429++
		sleep = time.Duration(minInt(crawler.backoff429, 5)) * time.Second
	case http.StatusForbidden:
		crawler.backoff403++
		if crawler.backoff403%3 == 0 {
			sleep = 2 * time.Second
		}
	default:
		crawler.backoffError++
		if crawler.backoffError%5 == 0 {
			sleep = 2 * time.Second
		}
	}
	crawler.backoffMutex.Unlock()

	if sleep > 0 {
		time.Sleep(sleep)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (crawler *Crawler) findAWSS3(resp string) {
	aws := GetAWSS3(resp)
	for _, e := range aws {
		if !crawler.awsSet.Duplicate(e) {
			outputFormat := fmt.Sprintf("[aws-s3] - %s", e)
			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "aws",
					Output:     e,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
				}
			}
			fmt.Println(outputFormat)
			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}
		}
	}
}

// Setup link finder
func (crawler *Crawler) setupLinkFinder() {
	crawler.LinkFinderCollector.OnResponse(func(response *colly.Response) {
		if response.Ctx != nil && response.Ctx.Get("reflected") == "true" {
			crawler.handleReflectedResponse(response)
			return
		}
		if crawler.reflected {
			crawler.handleBaselineReflection(response)
		}
		crawler.recordBackoff(response.StatusCode)
		if response.StatusCode == 404 || response.StatusCode == 429 || response.StatusCode < 100 {
			return
		}

		respStr := string(response.Body)

		if len(crawler.filterLength_slice) == 0 || !contains(crawler.filterLength_slice, len(respStr)) {

			// Verify which link is working
			u := NormalizeDisplayURL(response.Request.URL.String())
			outputFormat := fmt.Sprintf("[url] - [code-%d] - %s", response.StatusCode, u)

			if crawler.length {
				outputFormat = fmt.Sprintf("[url] - [code-%d] - [len_%d] - %s", response.StatusCode, len(respStr), u)
			}

			if crawler.JsonOutput {
				sout := SpiderOutput{
					Input:      crawler.Input,
					Source:     "body",
					OutputType: "url",
					StatusCode: response.StatusCode,
					Output:     u,
					Length:     strings.Count(respStr, "\n"),
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
				}
			} else if crawler.Quiet {
				outputFormat = u
			}
			fmt.Println(outputFormat)

			if crawler.Output != nil {
				crawler.Output.WriteToFile(outputFormat)
			}

			if InScope(response.Request.URL, crawler.C.URLFilters) {

				crawler.findSubdomains(respStr)
				crawler.findAWSS3(respStr)

				paths, jsRequests, err := LinkFinder(respStr, response.Request.URL)
				if err != nil {
					Logger.Error(err)
					return
				}

				currentBase := crawler.site
				if parsed, err := url.Parse(u); err == nil {
					currentBase = parsed
				}

				for _, relPath := range paths {
					var outputFormat string
					// JS Regex Result
					if crawler.JsonOutput {
						sout := SpiderOutput{
							Input:      crawler.Input,
							Source:     response.Request.URL.String(),
							OutputType: "linkfinder",
							Output:     relPath,
						}
						if data, err := jsoniter.MarshalToString(sout); err == nil {
							outputFormat = data
						}
					} else if !crawler.Quiet {
						outputFormat = fmt.Sprintf("[linkfinder] - [from: %s] - %s", response.Request.URL.String(), relPath)
					}
					fmt.Println(outputFormat)

					if crawler.Output != nil {
						crawler.Output.WriteToFile(outputFormat)
					}
					rebuildURL, ok := NormalizeURL(currentBase, relPath)
					if !ok {
						rebuildURL, ok = NormalizeURL(crawler.site, relPath)
					}
					if !ok {
						continue
					}

					// Try to request JS path
					// Try to generate URLs with main site
					fileExt := GetExtType(rebuildURL)
					if fileExt == ".js" || fileExt == ".xml" || fileExt == ".json" || fileExt == ".map" {
						crawler.feedLinkfinder(rebuildURL, "linkfinder", "javascript")
					} else if !crawler.isDuplicateURL(rebuildURL) {

						if crawler.JsonOutput {
							sout := SpiderOutput{
								Input:      crawler.Input,
								Source:     response.Request.URL.String(),
								OutputType: "linkfinder",
								Output:     rebuildURL,
							}
							if data, err := jsoniter.MarshalToString(sout); err == nil {
								outputFormat = data
							}
						} else if !crawler.Quiet {
							outputFormat = fmt.Sprintf("[linkfinder] - %s", rebuildURL)
						}

						fmt.Println(outputFormat)

						if crawler.Output != nil {
							crawler.Output.WriteToFile(outputFormat)
						}
						_ = crawler.C.Visit(rebuildURL)
					}

					// Try to generate URLs with the site where Javascript file host in (must be in main or sub domain)

					urlWithJSHostIn, ok := NormalizeURL(crawler.site, relPath)
					if ok {
						fileExt := GetExtType(urlWithJSHostIn)
						if fileExt == ".js" || fileExt == ".xml" || fileExt == ".json" || fileExt == ".map" {
							crawler.feedLinkfinder(urlWithJSHostIn, "linkfinder", "javascript")
						} else {
							if crawler.isDuplicateURL(urlWithJSHostIn) {
								continue
							} else {

								if crawler.JsonOutput {
									sout := SpiderOutput{
										Input:      crawler.Input,
										Source:     response.Request.URL.String(),
										OutputType: "linkfinder",
										Output:     urlWithJSHostIn,
									}
									if data, err := jsoniter.MarshalToString(sout); err == nil {
										outputFormat = data
									}
								} else if !crawler.Quiet {
									outputFormat = fmt.Sprintf("[linkfinder] - %s", urlWithJSHostIn)
								}
								fmt.Println(outputFormat)

								if crawler.Output != nil {
									crawler.Output.WriteToFile(outputFormat)
								}
								_ = crawler.C.Visit(urlWithJSHostIn) //not print care for lost link
							}
						}

					}

				}

				for _, jsReq := range jsRequests {
					crawler.processGeneratedRequest(jsReq, response.Request.URL.String(), response.Request.Depth)
				}

				if crawler.raw {

					outputFormat := fmt.Sprintf("[Raw] - \n%s\n", respStr) //PRINTCLEAN RAW for link visited only
					if !crawler.Quiet {
						fmt.Println(outputFormat)
					}

					if crawler.Output != nil {
						crawler.Output.WriteToFile(outputFormat)
					}
				}
			}
		}
	})
}

func (crawler *Crawler) initializeHybrid(cfg CrawlerConfig) {
	if !cfg.HybridCrawl {
		return
	}

	workers := cfg.HybridWorkers
	if workers <= 0 {
		workers = 2
	}

	navTimeout := cfg.HybridNavigationTimeout
	if navTimeout <= 0 {
		navTimeout = 12 * time.Second
	}

	stabilization := cfg.HybridStabilizationDelay
	if stabilization <= 0 {
		stabilization = 600 * time.Millisecond
	}

	headless := cfg.HybridHeadless
	initScripts := make([]string, 0, len(cfg.HybridInitScripts))
	for _, script := range cfg.HybridInitScripts {
		script = strings.TrimSpace(script)
		if script != "" {
			initScripts = append(initScripts, script)
		}
	}

	poolCfg := BrowserPoolConfig{
		PoolSize:           workers,
		NavigationTimeout:  navTimeout,
		StabilizationDelay: stabilization,
		Headless:           &headless,
		InitScripts:        initScripts,
	}

	crawler.stateGraph = NewApplicationStateGraph()
	crawler.browserPool = NewBrowserPool(poolCfg)

	queueSize := workers * 4
	if queueSize < 8 {
		queueSize = 8
	}
	crawler.hybridQueue = make(chan string, queueSize)
	crawler.hybridVisited = stringset.NewStringFilter()
	crawler.hybridAPISet = stringset.NewStringFilter()
	crawler.hybridWorkers = workers
	crawler.hybridEnqueued = 0
	crawler.hybridVisitCap = cfg.HybridVisitLimit
	if crawler.hybridVisitCap <= 0 {
		crawler.hybridVisitCap = 150
	}

	crawler.hybridCtx, crawler.hybridCancel = context.WithCancel(context.Background())

	if err := crawler.browserPool.Initialize(crawler.hybridCtx); err != nil {
		crawler.hybridActive.Store(false)
		crawler.hybridCancel()
		Logger.Errorf("hybrid mode disabled: %v", err)
		crawler.browserPool = nil
		crawler.stateGraph = nil
		crawler.hybridQueue = nil
		crawler.hybridVisited = nil
		crawler.hybridAPISet = nil
		crawler.hybridCancel = nil
		crawler.hybridCtx = nil
		return
	}

	crawler.hybridEnabled = true
	crawler.hybridActive.Store(true)

	for i := 0; i < workers; i++ {
		crawler.hybridWG.Add(1)
		go crawler.hybridWorker()
	}

	Logger.Infof("Hybrid state-aware crawling enabled (workers=%d, headless=%v)", workers, headless)
	crawler.enqueueHybrid(crawler.site.String())
}

func (crawler *Crawler) hybridWorker() {
	defer crawler.hybridWG.Done()
	if crawler.hybridQueue == nil || crawler.hybridCtx == nil {
		return
	}

	for {
		select {
		case <-crawler.hybridCtx.Done():
			return
		case url := <-crawler.hybridQueue:
			if !crawler.hybridActive.Load() || url == "" {
				continue
			}
			if crawler.browserPool == nil || crawler.stateGraph == nil {
				continue
			}
			result, err := crawler.browserPool.NavigateAndAnalyze(crawler.hybridCtx, url, crawler.stateGraph)
			if err != nil {
				Logger.Debugf("hybrid analyze failed for %s: %v", url, err)
				continue
			}
			crawler.handleHybridResult(result)
		}
	}
}

func (crawler *Crawler) enqueueHybrid(raw string) {
	if !crawler.hybridEnabled || !crawler.hybridActive.Load() || crawler.hybridQueue == nil || crawler.hybridCtx == nil {
		return
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if crawler.hybridVisited != nil && crawler.hybridVisited.Duplicate(raw) {
		return
	}

	select {
	case <-crawler.hybridCtx.Done():
		return
	case crawler.hybridQueue <- raw:
	default:
		Logger.Debugf("hybrid queue saturated, dropping %s", raw)
	}
}

func (crawler *Crawler) handleHybridResult(result *PageAnalysisResult) {
	if result == nil || crawler.stateGraph == nil {
		return
	}

	crawler.stateGraph.MarkAnalyzed(result.StateHash)

	if len(result.APICalls) > 0 {
		crawler.emitHybridAPICalls(result.URL, result.APICalls)
	}

	for _, tr := range result.Transitions {
		crawler.processHybridTransition(result.URL, tr)
	}
}

func (crawler *Crawler) emitHybridAPICalls(origin string, calls []string) {
	if crawler.hybridAPISet == nil {
		crawler.hybridAPISet = stringset.NewStringFilter()
	}

	for _, call := range calls {
		call = strings.TrimSpace(call)
		if call == "" || crawler.hybridAPISet.Duplicate(call) {
			continue
		}

		output := fmt.Sprintf("[hybrid][api] - %s", call)
		if crawler.JsonOutput {
			sout := SpiderOutput{
				Input:      crawler.Input,
				Source:     origin,
				OutputType: "hybrid-api",
				Output:     call,
			}
			if data, err := jsoniter.MarshalToString(sout); err == nil {
				output = data
			}
		}

		fmt.Println(output)
		if crawler.Output != nil {
			crawler.Output.WriteToFile(output)
		}
	}
}

func (crawler *Crawler) processHybridTransition(origin string, tr StateTransition) {
	action := strings.ToLower(strings.TrimSpace(tr.ActionType))
	if action == "" {
		return
	}

	switch action {
	case "navigate":
		target := ""
		if tr.Details != nil {
			target = tr.Details["targetUrl"]
		}
		crawler.scheduleHybridVisit(origin, target)
	case "form":
		target := ""
		if tr.Details != nil {
			target = tr.Details["targetUrl"]
			if target == "" {
				target = tr.Details["action"]
			}
		}
		crawler.scheduleHybridVisit(origin, target)
	}
}

func (crawler *Crawler) scheduleHybridVisit(origin, candidate string) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return
	}

	var base *url.URL
	if origin != "" {
		if parsed, err := url.Parse(origin); err == nil {
			base = parsed
		}
	}

	normalized, ok := NormalizeURL(base, candidate)
	if !ok {
		normalized, ok = NormalizeURL(crawler.site, candidate)
		if !ok {
			return
		}
	}

	if !crawler.isDuplicateURL(normalized) {
		_ = crawler.C.Visit(normalized)
	}

	crawler.enqueueHybrid(normalized)
}

func (crawler *Crawler) stopHybrid() {
	if !crawler.hybridEnabled {
		return
	}

	crawler.hybridActive.Store(false)
	if crawler.hybridCancel != nil {
		crawler.hybridCancel()
	}
}

func (crawler *Crawler) WaitHybrid() {
	if !crawler.hybridEnabled {
		return
	}

	crawler.stopHybrid()
	crawler.hybridWG.Wait()

	if crawler.browserPool != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := crawler.browserPool.Shutdown(shutdownCtx); err != nil {
			Logger.Debugf("hybrid browser shutdown: %v", err)
		}
	}

	crawler.browserPool = nil
	crawler.hybridQueue = nil
	crawler.hybridVisited = nil
	crawler.hybridAPISet = nil
	crawler.stateGraph = nil
	crawler.hybridEnabled = false
	crawler.hybridCancel = nil
	crawler.hybridCtx = nil
}
