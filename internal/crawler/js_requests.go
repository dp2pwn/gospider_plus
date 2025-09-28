package crawler

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type JSRequest struct {
	Method      string
	RawURL      string
	Body        string
	Headers     map[string]string
	ContentType string
	Source      string
	Events      []string
}

type jsOptions struct {
	method      string
	url         string
	body        string
	headers     map[string]string
	contentType string
}

type jsCall struct {
	name  string
	args  string
	start int
	end   int
}

func ExtractJSRequests(source string, base *url.URL) ([]JSRequest, error) {
	if base != nil {
		// placeholder for future base usage
	}

	var requests []JSRequest

	for _, call := range scanFunctionCallsName(source, "fetch") {
		args := splitArgs(call.args)
		if len(args) == 0 {
			continue
		}
		urlVal := decodeStringArgument(args[0])
		if urlVal == "" {
			continue
		}
		req := JSRequest{
			Method: "GET",
			RawURL: urlVal,
			Source: strings.TrimSpace(source[call.start:call.end]),
		}
		if len(args) > 1 && strings.HasPrefix(strings.TrimSpace(args[1]), "{") {
			opts := parseJSOptions(args[1])
			applyOptions(&req, opts)
		}
		requests = append(requests, req)
	}

	axiosVerbs := []string{"get", "post", "put", "delete", "patch", "head", "options"}
	for _, verb := range axiosVerbs {
		calls := scanFunctionCallsName(source, "axios."+verb)
		for _, call := range calls {
			args := splitArgs(call.args)
			if len(args) == 0 {
				continue
			}
			urlVal := decodeStringArgument(args[0])
			if urlVal == "" {
				continue
			}
			req := JSRequest{
				Method: strings.ToUpper(verb),
				RawURL: urlVal,
				Source: strings.TrimSpace(source[call.start:call.end]),
			}
			var configArg string
			if verb == "get" || verb == "delete" || verb == "head" || verb == "options" {
				if len(args) > 1 {
					configArg = args[1]
				}
			} else {
				if len(args) > 1 {
					req.Body = decodeBodyArgument(args[1])
				}
				if len(args) > 2 {
					configArg = args[2]
				}
			}
			if strings.TrimSpace(configArg) != "" {
				opts := parseJSOptions(configArg)
				applyOptions(&req, opts)
			}
			requests = append(requests, req)
		}
	}

	for _, call := range scanFunctionCallsName(source, "axios") {
		next := skipSpaces(source, call.start+len(call.name))
		if next < len(source) && source[next] == '.' {
			continue
		}
		args := splitArgs(call.args)
		if len(args) == 0 {
			continue
		}
		first := strings.TrimSpace(args[0])
		if !strings.HasPrefix(first, "{") {
			continue
		}
		opts := parseJSOptions(first)
		if opts.url == "" {
			continue
		}
		req := JSRequest{
			Method: "GET",
			RawURL: opts.url,
			Source: strings.TrimSpace(source[call.start:call.end]),
		}
		applyOptions(&req, opts)
		requests = append(requests, req)
	}

	for _, name := range []string{"$.ajax", "jQuery.ajax"} {
		for _, call := range scanFunctionCallsName(source, name) {
			args := splitArgs(call.args)
			if len(args) == 0 {
				continue
			}
			first := strings.TrimSpace(args[0])
			if !strings.HasPrefix(first, "{") {
				continue
			}
			opts := parseJSOptions(first)
			if opts.url == "" {
				continue
			}
			req := JSRequest{
				Method: "GET",
				RawURL: opts.url,
				Source: strings.TrimSpace(source[call.start:call.end]),
			}
			applyOptions(&req, opts)
			requests = append(requests, req)
		}
	}

	requests = append(requests, parseXHRRequests(source)...)

	return finalizeJSRequests(requests), nil
}

func applyOptions(req *JSRequest, opts jsOptions) {
	if opts.method != "" {
		req.Method = strings.ToUpper(opts.method)
	}
	if opts.body != "" {
		req.Body = opts.body
	}
	if opts.headers != nil {
		if req.Headers == nil {
			req.Headers = make(map[string]string, len(opts.headers))
		}
		for k, v := range opts.headers {
			req.Headers[k] = v
		}
	}
	if opts.contentType != "" {
		req.ContentType = opts.contentType
	}
	if opts.url != "" && req.RawURL == "" {
		req.RawURL = opts.url
	}
}

func parseJSOptions(block string) jsOptions {
	opts := jsOptions{}
	block = strings.TrimSpace(block)
	if block == "" {
		return opts
	}

	opts.method = strings.ToUpper(extractStringLiteral(block, "method"))
	if opts.method == "" {
		opts.method = strings.ToUpper(extractStringLiteral(block, "type"))
	}
	opts.url = extractStringLiteral(block, "url")

	if opts.body = extractStringLiteral(block, "body"); opts.body == "" {
		opts.body = extractStringLiteral(block, "data")
	}
	if opts.body == "" {
		if raw := extractObjectLiteral(block, "body"); raw != "" {
			opts.body = raw
		} else if raw := extractObjectLiteral(block, "data"); raw != "" {
			opts.body = raw
		}
	}

	opts.contentType = extractStringLiteral(block, "contentType")
	if opts.contentType == "" {
		opts.contentType = extractStringLiteral(block, "content-type")
	}

	if match := headersBlockRegex.FindStringSubmatch(block); len(match) >= 2 {
		headerText := match[1]
		pairs := headerPairRegex.FindAllStringSubmatch(headerText, -1)
		if len(pairs) > 0 {
			opts.headers = make(map[string]string, len(pairs))
			for _, pair := range pairs {
				if len(pair) < 5 {
					continue
				}
				key := DecodeJSString(pair[1] + pair[2] + pair[1])
				value := DecodeJSString(pair[3] + pair[4] + pair[3])
				opts.headers[key] = value
			}
		}
	}

	if opts.contentType == "" && opts.headers != nil {
		if ct, ok := opts.headers["Content-Type"]; ok {
			opts.contentType = ct
		} else if ct, ok := opts.headers["content-type"]; ok {
			opts.contentType = ct
		}
	}

	return opts
}

var (
	headersBlockRegex = regexp.MustCompile(`(?is)headers\s*:\s*\{([^{}]*)\}`)
	headerPairRegex   = regexp.MustCompile(`(['"\x60])([^'"\x60]+?)['"\x60]\s*:\s*(['"\x60])([^'"\x60]*?)['"\x60]`)
)

func extractStringLiteral(block, key string) string {
	if key == "" {
		return ""
	}

	pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(key) + `\s*:\s*`)
	indices := pattern.FindAllStringIndex(block, -1)
	for _, pair := range indices {
		pos := pair[1]
		if pos >= len(block) {
			continue
		}

		quote := block[pos]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}

		literal, ok := scanQuotedLiteral(block, pos)
		if !ok {
			continue
		}
		return DecodeJSString(literal)
	}

	return ""
}

func scanQuotedLiteral(source string, start int) (string, bool) {
	quote := source[start]
	i := start + 1
	for i < len(source) {
		ch := source[i]
		if ch == '\\' && i+1 < len(source) {
			i += 2
			continue
		}
		if ch == quote {
			return source[start : i+1], true
		}
		i++
	}

	return "", false
}

func extractObjectLiteral(block, key string) string {
	if key == "" {
		return ""
	}
	pattern := `(?is)` + regexp.QuoteMeta(key) + `\s*:\s*(\{[^{}]*\}|\[[^\[\]]*\])`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(block)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func decodeStringArgument(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return ""
	}
	first := raw[0]
	last := raw[len(raw)-1]
	if (first == '"' || first == '\'' || first == '`') && last == first {
		return DecodeJSString(raw)
	}
	return ""
}

func decodeBodyArgument(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if val := decodeStringArgument(raw); val != "" {
		return val
	}
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
		return raw
	}
	return ""
}

func parseXHRRequests(source string) []JSRequest {
	var requests []JSRequest
	re := regexp.MustCompile(`(?is)([A-Za-z0-9_\.$]+)\.open\s*\(\s*(['"\x60])([A-Za-z]+)['"\x60]\s*,\s*(['"\x60])([^'"\x60]+?)['"\x60]`)
	matches := re.FindAllStringSubmatchIndex(source, -1)
	for _, loc := range matches {
		variable := source[loc[2]:loc[3]]
		method := strings.ToUpper(source[loc[6]:loc[7]])
		urlFragment := source[loc[10]:loc[11]]
		quoteChar := source[loc[8]:loc[9]]
		literal := quoteChar + urlFragment + quoteChar
		rawURL := DecodeJSString(literal)
		if rawURL == "" {
			continue
		}
		snippet := strings.TrimSpace(source[loc[0]:loc[1]])
		req := JSRequest{
			Method: method,
			RawURL: rawURL,
			Source: snippet,
		}
		if body := findXHRSendBody(source[loc[1]:], variable); body != "" {
			req.Body = body
		}
		requests = append(requests, req)
	}
	return requests
}

func findXHRSendBody(section, variable string) string {
	name := variable + ".send"
	calls := scanFunctionCallsName(section, name)
	if len(calls) == 0 {
		return ""
	}
	args := splitArgs(calls[0].args)
	if len(args) == 0 {
		return ""
	}
	return decodeBodyArgument(args[0])
}

func finalizeJSRequests(reqs []JSRequest) []JSRequest {
	seen := make(map[string]struct{})
	out := make([]JSRequest, 0, len(reqs))
	for _, req := range reqs {
		req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
		if req.Method == "" {
			req.Method = "GET"
		}
		req.RawURL = strings.TrimSpace(req.RawURL)
		req.Body = strings.TrimSpace(req.Body)
		if len(req.Headers) == 0 {
			req.Headers = nil
		}
		if req.ContentType == "" && req.Headers != nil {
			if ct, ok := req.Headers["Content-Type"]; ok {
				req.ContentType = ct
			} else if ct, ok := req.Headers["content-type"]; ok {
				req.ContentType = ct
			}
		}

		key := buildRequestKey(req)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, req)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RawURL == out[j].RawURL {
			if out[i].Method == out[j].Method {
				return out[i].Body < out[j].Body
			}
			return out[i].Method < out[j].Method
		}
		return out[i].RawURL < out[j].RawURL
	})

	return out
}

func buildRequestKey(req JSRequest) string {
	var builder strings.Builder
	builder.WriteString(req.Method)
	builder.WriteByte(' ')
	builder.WriteString(req.RawURL)
	builder.WriteByte(' ')
	builder.WriteString(req.Body)

	if len(req.Headers) > 0 {
		keys := make([]string, 0, len(req.Headers))
		for k := range req.Headers {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)
		for _, k := range keys {
			builder.WriteByte(' ')
			builder.WriteString(k)
			builder.WriteByte('=')
			builder.WriteString(req.Headers[k])
		}
	}

	if req.ContentType != "" {
		builder.WriteString(" ct=")
		builder.WriteString(req.ContentType)
	}

	return builder.String()
}

func splitArgs(arguments string) []string {
	var args []string
	depth := 0
	start := 0
	inSingle, inDouble, inBacktick := false, false, false
	escaped := false

	for i := 0; i < len(arguments); i++ {
		ch := arguments[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				arg := strings.TrimSpace(arguments[start:i])
				if arg != "" {
					args = append(args, arg)
				}
				start = i + 1
			}
		}
	}

	if start < len(arguments) {
		arg := strings.TrimSpace(arguments[start:])
		if arg != "" {
			args = append(args, arg)
		}
	}

	return args
}

func scanFunctionCallsName(source, name string) []jsCall {
	lowerSource := strings.ToLower(source)
	lowerName := strings.ToLower(name)
	var calls []jsCall

	for idx := 0; idx < len(source); {
		pos := strings.Index(lowerSource[idx:], lowerName)
		if pos == -1 {
			break
		}
		start := idx + pos
		if start > 0 && isIdentChar(lowerSource[start-1]) {
			idx = start + len(lowerName)
			continue
		}
		afterName := skipSpaces(source, start+len(name))
		if afterName >= len(source) || source[afterName] != '(' {
			idx = start + len(lowerName)
			continue
		}
		args, nextIdx, ok := extractCallArguments(source, afterName)
		if !ok {
			idx = start + len(lowerName)
			continue
		}
		calls = append(calls, jsCall{
			name:  name,
			args:  args,
			start: start,
			end:   nextIdx,
		})
		idx = nextIdx
	}

	return calls
}

func extractCallArguments(source string, openIdx int) (string, int, bool) {
	depth := 0
	inSingle, inDouble, inBacktick := false, false, false
	escaped := false

	for i := openIdx; i < len(source); i++ {
		ch := source[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return source[openIdx+1 : i], i + 1, true
			}
		}
	}

	return "", openIdx, false
}

func skipSpaces(source string, idx int) int {
	for idx < len(source) {
		switch source[idx] {
		case ' ', '\t', '\r', '\n':
			idx++
		default:
			return idx
		}
	}
	return idx
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || b == '_'
}
