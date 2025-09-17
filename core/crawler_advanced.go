package core

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gocolly/colly/v2"
	jsoniter "github.com/json-iterator/go"
)

const defaultReflectedPayload = "\"><u>1111</u>'\""

const reflectedParamName = "gospider_ref"

type reflectionEntry struct {
	baselineSet     bool
	mutatedSet      bool
	baselineHash    string
	mutatedHash     string
	baselineStatus  int
	mutatedStatus   int
	baselineLen     int
	mutatedLen      int
	mutatedContains bool
	url             string
	method          string
	origin          string
	param           string
	payload         string
	emitted         bool
}

type reflectionFinding struct {
	URL     string
	Method  string
	Origin  string
	Status  int
	Length  int
	Param   string
	Payload string
	Reasons []string
}

type reflectionMutation struct {
	Request JSRequest
	Param   string
}

func (crawler *Crawler) processGeneratedRequest(req JSRequest, origin string, parentDepth int) {
	normalized, ok := crawler.normalizeJSRequest(req, origin)
	if !ok {
		return
	}
	if !crawler.emitJSRequest(normalized, origin) {
		return
	}
	crawler.scheduleJSRequest(normalized, origin, parentDepth)
}

func (crawler *Crawler) normalizeJSRequest(req JSRequest, origin string) (JSRequest, bool) {
	normalized := req
	normalized.Method = strings.ToUpper(strings.TrimSpace(normalized.Method))
	if normalized.Method == "" {
		normalized.Method = http.MethodGet
	}

	source := strings.TrimSpace(normalized.Source)
	if source == "" {
		source = origin
	}
	normalized.Source = source

	raw := strings.TrimSpace(normalized.RawURL)
	base := crawler.site
	if origin != "" {
		if u, err := url.Parse(origin); err == nil {
			base = u
		}
	}
	if raw == "" {
		raw = origin
	}
	if raw == "" {
		return JSRequest{}, false
	}
	if base != nil {
		if u, err := url.Parse(raw); err == nil {
			normalized.RawURL = base.ResolveReference(u).String()
		} else {
			return JSRequest{}, false
		}
	} else {
		normalized.RawURL = raw
	}

	normalized.Body = strings.TrimSpace(normalized.Body)
	if len(normalized.Headers) > 0 {
		headers := make(map[string]string, len(normalized.Headers))
		for k, v := range normalized.Headers {
			headers[http.CanonicalHeaderKey(k)] = v
		}
		normalized.Headers = headers
	}
	if normalized.ContentType == "" && normalized.Headers != nil {
		if ct, ok := normalized.Headers["Content-Type"]; ok {
			normalized.ContentType = ct
		}
	}

	return normalized, true
}

func (crawler *Crawler) scheduleJSRequest(req JSRequest, origin string, parentDepth int) {
	key := buildRequestKey(req)
	crawler.queueRequest(req, origin, false, key, parentDepth, "")
	if crawler.reflected {
		mutations := crawler.buildReflectedRequests(req)
		for _, mutation := range mutations {
			crawler.queueRequest(mutation.Request, origin, true, key, parentDepth, mutation.Param)
		}
	}
}

func (crawler *Crawler) queueRequest(req JSRequest, origin string, reflected bool, baselineKey string, parentDepth int, paramName string) {
	if parentDepth < 0 {
		parentDepth = 0
	}
	nextDepth := parentDepth + 1
	if maxDepth := crawler.C.MaxDepth; maxDepth > 0 && nextDepth > maxDepth {
		return
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	headers := http.Header{}
	for k, v := range req.Headers {
		headers.Set(k, v)
	}
	if req.ContentType != "" && headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", req.ContentType)
	}

	var bodyReader io.Reader
	if !strings.EqualFold(method, http.MethodGet) && req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	ctx := colly.NewContext()
	ctx.Put("method", method)
	ctx.Put("__depth", strconv.Itoa(nextDepth))
	ctx.Put("origin", origin)
	if baselineKey == "" {
		baselineKey = buildRequestKey(req)
	}
	ctx.Put("request-key", baselineKey)
	if reflected {
		if paramName == "" {
			paramName = reflectedParamName
		}
		ctx.Put("reflected", "true")
		ctx.Put("payload", crawler.reflectedPayload)
		ctx.Put("param", paramName)
	}

	if baselineKey != "" {
		crawler.reflectedMutex.Lock()
		entry := crawler.ensureReflectionEntry(baselineKey)
		if reflected {
			if paramName == "" {
				paramName = reflectedParamName
			}
			entry.param = paramName
			entry.payload = crawler.reflectedPayload
		}
		crawler.reflectedMutex.Unlock()
	}

	if err := crawler.C.Request(method, req.RawURL, bodyReader, ctx, headers); err != nil {
		Logger.Debugf("failed to queue request %s %s: %v", method, req.RawURL, err)
	}
}

func (crawler *Crawler) buildReflectedRequests(req JSRequest) []reflectionMutation {
	mutations := make([]reflectionMutation, 0)
	payload := crawler.reflectedPayload

	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}

	if u, err := url.Parse(req.RawURL); err == nil {
		values := u.Query()
		if len(values) > 0 {
			for key := range values {
				if key == "" {
					continue
				}
				cloned := cloneValues(values)
				mutatedURL := *u
				cloned.Set(key, payload)
				mutatedURL.RawQuery = cloned.Encode()
				mutated := req
				mutated.RawURL = mutatedURL.String()
				mutations = append(mutations, reflectionMutation{Request: mutated, Param: key})
			}
		}
	}

	contentType := strings.ToLower(req.ContentType)
	if contentType == "" && req.Headers != nil {
		if ct, ok := req.Headers["Content-Type"]; ok {
			contentType = strings.ToLower(ct)
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(req.Body); err == nil && len(values) > 0 {
			for key := range values {
				if key == "" {
					continue
				}
				cloned := cloneValues(values)
				cloned.Set(key, payload)
				mutated := req
				mutated.Body = cloned.Encode()
				if mutated.ContentType == "" {
					mutated.ContentType = "application/x-www-form-urlencoded"
				}
				mutations = append(mutations, reflectionMutation{Request: mutated, Param: key})
			}
		}
	}

	if len(mutations) == 0 {
		mutated := req
		paramName := reflectedParamName

		switch method {
		case http.MethodGet, http.MethodHead:
			if u, err := url.Parse(mutated.RawURL); err == nil {
				values := u.Query()
				values.Set(paramName, payload)
				u.RawQuery = values.Encode()
				mutated.RawURL = u.String()
			} else {
				separator := "?"
				if strings.Contains(mutated.RawURL, "?") {
					separator = "&"
				}
				mutated.RawURL = mutated.RawURL + separator + paramName + "=" + url.QueryEscape(payload)
			}
		default:
			if strings.Contains(contentType, "application/x-www-form-urlencoded") || contentType == "" {
				values, err := url.ParseQuery(mutated.Body)
				if err != nil {
					values = url.Values{}
				}
				values.Set(paramName, payload)
				mutated.Body = values.Encode()
				if mutated.ContentType == "" {
					mutated.ContentType = "application/x-www-form-urlencoded"
				}
			} else if mutated.Body == "" {
				mutated.Body = payload
			} else {
				mutated.Body = mutated.Body + "&" + paramName + "=" + url.QueryEscape(payload)
			}
		}

		mutations = append(mutations, reflectionMutation{Request: mutated, Param: paramName})
	}

	return mutations
}

func (crawler *Crawler) handleBaselineReflection(response *colly.Response) {
	if !crawler.reflected || response.Ctx == nil {
		return
	}
	key := response.Ctx.Get("request-key")
	if key == "" {
		return
	}
	hash := hashBody(response.Body)

	crawler.reflectedMutex.Lock()
	entry := crawler.ensureReflectionEntry(key)
	entry.baselineSet = true
	entry.baselineHash = hash
	entry.baselineStatus = response.StatusCode
	entry.baselineLen = len(response.Body)
	if entry.method == "" {
		entry.method = response.Ctx.Get("method")
	}
	if entry.origin == "" {
		entry.origin = response.Ctx.Get("origin")
	}
	if entry.param == "" {
		entry.param = response.Ctx.Get("param")
	}
	if entry.payload == "" {
		entry.payload = response.Ctx.Get("payload")
	}
	finding := entry.evaluate()
	crawler.reflectedMutex.Unlock()

	if finding != nil {
		crawler.outputReflection(*finding)
	}
}

func (crawler *Crawler) handleReflectedResponse(response *colly.Response) {
	if response.Ctx == nil {
		return
	}
	key := response.Ctx.Get("request-key")
	if key == "" {
		return
	}

	body := response.Body
	contains := strings.Contains(string(body), crawler.reflectedPayload)
	hash := hashBody(body)

	crawler.reflectedMutex.Lock()
	entry := crawler.ensureReflectionEntry(key)
	entry.mutatedSet = true
	entry.mutatedHash = hash
	entry.mutatedStatus = response.StatusCode
	entry.mutatedLen = len(body)
	entry.mutatedContains = contains
	entry.url = response.Request.URL.String()
	if entry.method == "" {
		entry.method = response.Ctx.Get("method")
	}
	if entry.origin == "" {
		entry.origin = response.Ctx.Get("origin")
	}
	if param := response.Ctx.Get("param"); param != "" {
		entry.param = param
	}
	if payload := response.Ctx.Get("payload"); payload != "" {
		entry.payload = payload
	}
	finding := entry.evaluate()
	crawler.reflectedMutex.Unlock()

	if finding != nil {
		crawler.outputReflection(*finding)
	}
}

func (crawler *Crawler) ensureReflectionEntry(key string) *reflectionEntry {
	if crawler.reflectedStore == nil {
		crawler.reflectedStore = make(map[string]*reflectionEntry)
	}
	entry, ok := crawler.reflectedStore[key]
	if !ok {
		entry = &reflectionEntry{}
		crawler.reflectedStore[key] = entry
	}
	return entry
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, vals := range values {
		dup := make([]string, len(vals))
		copy(dup, vals)
		cloned[key] = dup
	}
	return cloned
}

func hashBody(body []byte) string {
	sum := sha1.Sum(body)
	return hex.EncodeToString(sum[:])
}

func (entry *reflectionEntry) evaluate() *reflectionFinding {
	if !entry.baselineSet || !entry.mutatedSet || entry.emitted {
		return nil
	}

	reasons := make([]string, 0, 2)
	if entry.mutatedContains {
		reasons = append(reasons, "payload-reflected")
	}
	if entry.baselineHash != entry.mutatedHash {
		reasons = append(reasons, "body-delta")
	}
	if len(reasons) == 0 {
		return nil
	}

	entry.emitted = true
	return &reflectionFinding{
		URL:     entry.url,
		Method:  entry.method,
		Origin:  entry.origin,
		Status:  entry.mutatedStatus,
		Length:  entry.mutatedLen,
		Param:   entry.param,
		Payload: entry.payload,
		Reasons: reasons,
	}
}

func (crawler *Crawler) outputReflection(f reflectionFinding) {
	method := strings.ToUpper(f.Method)
	param := f.Param
	if param == "" {
		param = reflectedParamName
	}
	payload := f.Payload
	if payload == "" {
		payload = crawler.reflectedPayload
	}
	reason := strings.Join(f.Reasons, ",")
	rendered := fmt.Sprintf("%s %s param:%s payload:%s (%s)", method, f.URL, param, payload, reason)
	output := rendered

	if crawler.JsonOutput {
		sout := SpiderOutput{
			Input:      crawler.Input,
			Source:     f.Origin,
			OutputType: "reflected",
			Output:     f.URL,
			StatusCode: f.Status,
			Length:     f.Length,
			Param:      param,
			Payload:    payload,
		}
		if data, err := jsoniter.MarshalToString(sout); err == nil {
			output = data
		}
	} else if crawler.Quiet {
		output = f.URL
	}

	if !crawler.Quiet || crawler.JsonOutput {
		fmt.Println(output)
	} else if crawler.Quiet {
		fmt.Println(output)
	}
	if crawler.Output != nil {
		crawler.Output.WriteToFile(output)
	}
	if crawler.reflectedWriter != nil {
		crawler.reflectedWriter.WriteToFile(rendered)
	}
}
