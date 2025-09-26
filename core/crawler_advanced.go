package core

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gocolly/colly/v2"
	jsoniter "github.com/json-iterator/go"
)

const defaultReflectedPayload = "__gospider_reflected__"

const reflectedParamName = "gospider_ref"

var templateMarkerRegex = regexp.MustCompile(`(?i)\[object [^\]]+\]([0-9]+)\[object [^\]]+\]`)

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
	mutatedMarkers  []string
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
	Payload string
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
	crawler.queueRequest(req, origin, false, key, parentDepth, "", "")

	budget := crawler.baselineFuzzCap
	aggressive := crawler.reflected
	if aggressive {
		budget = len(crawler.payloadVariants)
	}
	if budget == 0 {
		return
	}
	mutations := crawler.buildReflectedRequests(req, aggressive, budget)
	for _, mutation := range mutations {
		crawler.queueRequest(mutation.Request, origin, aggressive, key, parentDepth, mutation.Param, mutation.Payload)
	}
}

func (crawler *Crawler) queueRequest(req JSRequest, origin string, reflected bool, baselineKey string, parentDepth int, paramName string, payload string) {
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
	if crawler.isDuplicateRequest(method, req.RawURL, req.Body) {
		return
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
	if len(req.Events) > 0 {
		ctx.Put("events", strings.Join(req.Events, ","))
	}
	if reflected {
		if payload == "" {
			payload = crawler.reflectedPayload
		}
		if paramName == "" {
			paramName = reflectedParamName
		}
		ctx.Put("reflected", "true")
		ctx.Put("payload", payload)
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
			entry.payload = payload
		}
		crawler.reflectedMutex.Unlock()
	}

	if payload != "" {
		crawler.maybeThrottleMutations(reflected)
	}

	if err := crawler.C.Request(method, req.RawURL, bodyReader, ctx, headers); err != nil {
		Logger.Debugf("failed to queue request %s %s: %v", method, req.RawURL, err)
	}
}

func (crawler *Crawler) buildReflectedRequests(req JSRequest, aggressive bool, budget int) []reflectionMutation {
	payloads := crawler.pickPayloads(budget, aggressive)
	if len(payloads) == 0 {
		return nil
	}

	remaining := budget
	if remaining <= 0 || remaining > len(payloads) {
		remaining = len(payloads)
	}
	if remaining <= 0 {
		remaining = len(payloads)
	}
	index := 0
	nextPayload := func() (string, bool) {
		if remaining <= 0 {
			return "", false
		}
		payload := payloads[index%len(payloads)]
		index++
		remaining--
		return payload, true
	}

	mutations := make([]reflectionMutation, 0, len(payloads))
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}

	if u, err := url.Parse(req.RawURL); err == nil {
		values := u.Query()
		for key := range values {
			if strings.TrimSpace(key) == "" {
				continue
			}
			payload, ok := nextPayload()
			if !ok {
				break
			}
			cloned := cloneValues(values)
			mutatedURL := *u
			cloned.Set(key, payload)
			mutatedURL.RawQuery = cloned.Encode()
			mutated := req
			mutated.RawURL = mutatedURL.String()
			mutations = append(mutations, reflectionMutation{Request: mutated, Param: key, Payload: payload})
		}
	}

	contentType := strings.ToLower(req.ContentType)
	if contentType == "" && req.Headers != nil {
		if ct, ok := req.Headers["Content-Type"]; ok {
			contentType = strings.ToLower(ct)
		}
	}

	if remaining > 0 && strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(req.Body); err == nil && len(values) > 0 {
			for key := range values {
				if strings.TrimSpace(key) == "" {
					continue
				}
				payload, ok := nextPayload()
				if !ok {
					break
				}
				cloned := cloneValues(values)
				cloned.Set(key, payload)
				mutated := req
				mutated.Body = cloned.Encode()
				if mutated.ContentType == "" {
					mutated.ContentType = "application/x-www-form-urlencoded"
				}
				mutations = append(mutations, reflectionMutation{Request: mutated, Param: key, Payload: payload})
			}
		}
	}

	if remaining > 0 && (strings.Contains(contentType, "application/json") || looksLikeJSON(req.Body)) {
		jsonMutations := crawler.fuzzJSONBody(req, nextPayload)
		mutations = append(mutations, jsonMutations...)
	}

	if remaining > 0 && strings.Contains(contentType, "multipart/form-data") {
		multipartMutations := crawler.fuzzMultipartBody(req, contentType, nextPayload)
		mutations = append(mutations, multipartMutations...)
	}

	if len(mutations) == 0 {
		payload, ok := nextPayload()
		if ok {
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
			mutations = append(mutations, reflectionMutation{Request: mutated, Param: paramName, Payload: payload})
		}
	}

	return mutations
}

func (crawler *Crawler) pickPayloads(limit int, aggressive bool) []string {
	var variants []PayloadVariant
	if aggressive {
		variants = crawler.payloadVariants
	} else {
		variants = crawler.baselinePayloads
	}
	if len(variants) == 0 {
		if crawler.reflectedPayload != "" {
			return []string{crawler.reflectedPayload}
		}
		return nil
	}
	if limit <= 0 || limit > len(variants) {
		limit = len(variants)
	}
	indexes := crawler.sampleVariantIndexes(len(variants), limit)
	payloads := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		payloads = append(payloads, variants[idx].Render(crawler.reflectedPayload))
	}
	return payloads
}

func (crawler *Crawler) sampleVariantIndexes(size, count int) []int {
	if count >= size {
		count = size
	}
	if count <= 0 {
		return nil
	}
	crawler.payloadRNGMutex.Lock()
	rng := crawler.payloadRNG
	crawler.payloadRNGMutex.Unlock()
	if rng == nil {
		idxs := make([]int, count)
		for i := 0; i < count; i++ {
			idxs[i] = i
		}
		return idxs
	}
	perm := rng.Perm(size)
	return perm[:count]
}

func looksLikeJSON(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	first := trimmed[0]
	return first == '{' || first == '['
}

type jsonPathSegment struct {
	key     string
	index   int
	isIndex bool
}

func (crawler *Crawler) fuzzJSONBody(req JSRequest, next func() (string, bool)) []reflectionMutation {
	trimmed := strings.TrimSpace(req.Body)
	if trimmed == "" {
		return nil
	}
	var data interface{}
	if err := json.Unmarshal([]byte(req.Body), &data); err != nil {
		return nil
	}
	paths := make([][]jsonPathSegment, 0, 8)
	collectJSONPaths(data, nil, &paths)
	if len(paths) == 0 {
		return nil
	}
	mutations := make([]reflectionMutation, 0, len(paths))
	for _, path := range paths {
		payload, ok := next()
		if !ok {
			break
		}
		clone := cloneJSON(data)
		setJSONValue(clone, path, payload)
		buf, err := json.Marshal(clone)
		if err != nil {
			continue
		}
		mutated := req
		mutated.Body = string(buf)
		if mutated.ContentType == "" {
			mutated.ContentType = "application/json"
		}
		param := formatJSONPath(path)
		if param == "" {
			param = reflectedParamName
		}
		mutations = append(mutations, reflectionMutation{Request: mutated, Param: param, Payload: payload})
	}
	return mutations
}

func (crawler *Crawler) fuzzMultipartBody(req JSRequest, contentType string, next func() (string, bool)) []reflectionMutation {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.Contains(mediaType, "multipart/form-data") {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	payload, ok := next()
	if !ok {
		return nil
	}

	terminator := "--" + boundary + "--"
	body := strings.TrimSuffix(req.Body, terminator)
	if !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}

	builder := strings.Builder{}
	builder.WriteString(body)
	builder.WriteString("--")
	builder.WriteString(boundary)
	builder.WriteString("\\r\\nContent-Disposition: form-data; name=\"")
	builder.WriteString(reflectedParamName)
	builder.WriteString("\"\\r\\n\\r\\n")
	builder.WriteString(payload)
	builder.WriteString("\r\n--")
	builder.WriteString(boundary)
	builder.WriteString("--")

	mutated := req
	mutated.Body = builder.String()
	if mutated.ContentType == "" {
		mutated.ContentType = mediaType + "; boundary=" + boundary
	}

	return []reflectionMutation{{Request: mutated, Param: reflectedParamName, Payload: payload}}
}

func collectJSONPaths(node interface{}, prefix []jsonPathSegment, out *[][]jsonPathSegment) {
	switch val := node.(type) {
	case map[string]interface{}:
		for key, child := range val {
			collectJSONPaths(child, append(prefix, jsonPathSegment{key: key}), out)
		}
	case []interface{}:
		for idx, child := range val {
			collectJSONPaths(child, append(prefix, jsonPathSegment{index: idx, isIndex: true}), out)
		}
	default:
		pathCopy := make([]jsonPathSegment, len(prefix))
		copy(pathCopy, prefix)
		*out = append(*out, pathCopy)
	}
}

func cloneJSON(node interface{}) interface{} {
	switch val := node.(type) {
	case map[string]interface{}:
		dup := make(map[string]interface{}, len(val))
		for k, v := range val {
			dup[k] = cloneJSON(v)
		}
		return dup
	case []interface{}:
		dup := make([]interface{}, len(val))
		for i, v := range val {
			dup[i] = cloneJSON(v)
		}
		return dup
	default:
		return val
	}
}

func setJSONValue(root interface{}, path []jsonPathSegment, value string) {
	if len(path) == 0 {
		return
	}
	current := root
	for i := 0; i < len(path)-1; i++ {
		seg := path[i]
		if seg.isIndex {
			arr, ok := current.([]interface{})
			if !ok || seg.index < 0 || seg.index >= len(arr) {
				return
			}
			current = arr[seg.index]
		} else {
			obj, ok := current.(map[string]interface{})
			if !ok {
				return
			}
			current = obj[seg.key]
		}
	}
	last := path[len(path)-1]
	switch container := current.(type) {
	case map[string]interface{}:
		if !last.isIndex {
			container[last.key] = value
		}
	case []interface{}:
		if last.isIndex && last.index >= 0 && last.index < len(container) {
			container[last.index] = value
		}
	}
}

func formatJSONPath(path []jsonPathSegment) string {
	if len(path) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, seg := range path {
		if seg.isIndex {
			builder.WriteString("[")
			builder.WriteString(strconv.Itoa(seg.index))
			builder.WriteString("]")
		} else {
			if builder.Len() > 0 {
				builder.WriteString(".")
			}
			builder.WriteString(seg.key)
		}
	}
	return builder.String()
}

func findEncodedPayloads(body []byte, payload string, sentinel string) []string {
	reasons := make([]string, 0, 6)
	lowerBody := strings.ToLower(string(body))
	add := func(marker string) {
		reasons = appendUniqueMarker(reasons, marker)
	}
	if payload != "" {
		lowerPayload := strings.ToLower(payload)
		if strings.Contains(lowerBody, lowerPayload) {
			add("payload-reflected")
		}
		if htmlEncoded := strings.ToLower(html.EscapeString(payload)); htmlEncoded != lowerPayload && strings.Contains(lowerBody, htmlEncoded) {
			add("payload-html-encoded")
		}
		if urlEncoded := strings.ToLower(url.QueryEscape(payload)); urlEncoded != lowerPayload && strings.Contains(lowerBody, urlEncoded) {
			add("payload-url-encoded")
		}
	}
	if sentinel != "" {
		lowerSentinel := strings.ToLower(sentinel)
		if !strings.EqualFold(payload, sentinel) && strings.Contains(lowerBody, lowerSentinel) {
			add("payload-sentinel")
		}
		if htmlSentinel := strings.ToLower(html.EscapeString(sentinel)); htmlSentinel != lowerSentinel && strings.Contains(lowerBody, htmlSentinel) {
			add("payload-sentinel-html")
		}
		if urlSentinel := strings.ToLower(url.QueryEscape(sentinel)); urlSentinel != lowerSentinel && strings.Contains(lowerBody, urlSentinel) {
			add("payload-sentinel-url")
		}
	}
	return reasons
}

func appendUniqueMarker(list []string, marker string) []string {
	for _, existing := range list {
		if existing == marker {
			return list
		}
	}
	return append(list, marker)
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

	payload := response.Ctx.Get("payload")
	if payload == "" {
		payload = crawler.reflectedPayload
	}

	body := response.Body
	reasons := findEncodedPayloads(body, payload, crawler.reflectedPayload)
	contains := len(reasons) > 0
	if templateMarkerRegex.Match(body) {
		contains = true
		reasons = appendUniqueMarker(reasons, "template-marker")
	}

	hash := hashBody(body)

	crawler.reflectedMutex.Lock()
	entry := crawler.ensureReflectionEntry(key)
	entry.mutatedSet = true
	entry.mutatedHash = hash
	entry.mutatedStatus = response.StatusCode
	entry.mutatedLen = len(body)
	entry.mutatedContains = contains
	entry.mutatedMarkers = reasons
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
	if payload != "" {
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

	reasons := make([]string, 0, 3+len(entry.mutatedMarkers))
	if entry.mutatedContains && len(entry.mutatedMarkers) == 0 {
		reasons = appendUniqueMarker(reasons, "payload-reflected")
	}
	for _, marker := range entry.mutatedMarkers {
		reasons = appendUniqueMarker(reasons, marker)
	}
	if entry.baselineHash != entry.mutatedHash {
		reasons = appendUniqueMarker(reasons, "body-delta")
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
