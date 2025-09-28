package netutil

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

var curlyBracketDecoder = strings.NewReplacer("%7B", "{", "%7b", "{", "%7D", "}", "%7d", "}")

func NormalizeDisplayURL(raw string) string {
	if raw == "" {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return curlyBracketDecoder.Replace(raw)
	}
	if parsed.RawQuery != "" {
		parsed.RawQuery = NormalizeQuery(parsed.RawQuery)
	}
	parsed.Path = curlyBracketDecoder.Replace(parsed.Path)
	result := parsed.String()
	return curlyBracketDecoder.Replace(result)
}

func NormalizeQuery(raw string) string {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder strings.Builder
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		vals = dedupeSortedStrings(vals)
		escapedKey := url.QueryEscape(k)
		if len(vals) == 0 {
			appendQueryComponent(&builder, escapedKey, "")
			continue
		}
		for _, v := range vals {
			appendQueryComponent(&builder, escapedKey, url.QueryEscape(v))
		}
	}

	return builder.String()
}

func NormalizePathComponent(p string) string {
	if p == "" {
		return "/"
	}
	clean := path.Clean(p)
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return NormalizeDisplayURL(clean)
}

func appendQueryComponent(builder *strings.Builder, key, value string) {
	if builder.Len() > 0 {
		builder.WriteByte('&')
	}
	builder.WriteString(key)
	if value != "" {
		builder.WriteByte('=')
		builder.WriteString(value)
	}
}

func dedupeSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	deduped := make([]string, 0, len(values))
	var last string
	for i, v := range values {
		if i > 0 && v == last {
			continue
		}
		deduped = append(deduped, v)
		last = v
	}
	return deduped
}
