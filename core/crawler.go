package core

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

	return &Crawler{
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
	}
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

	fmt.Println(rendered)

	if crawler.Output != nil {
		crawler.Output.WriteToFile(rendered)
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
		duplicateContent := false
		if crawler.registry != nil && response.Request != nil && response.Request.URL != nil {
			duplicateContent = crawler.registry.MarkResponse(response.Request.Method, response.Request.URL.String(), response.Body)
		}
		crawler.recordBackoff(response.StatusCode)
		respStr := DecodeChars(string(response.Body))

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
