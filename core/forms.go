package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// FormField represents a parsed HTML form field.
type FormField struct {
	Name  string
	Value string
}

// buildFormRequest constructs a JSRequest from form attributes and fields.
func buildFormRequest(action, method string, fields []FormField, base *url.URL) (JSRequest, bool) {
	resolved := strings.TrimSpace(action)
	if resolved == "" && base != nil {
		resolved = base.String()
	}

	if base != nil {
		if u, err := url.Parse(resolved); err == nil {
			resolved = base.ResolveReference(u).String()
		} else {
			return JSRequest{}, false
		}
	}

	if resolved == "" {
		return JSRequest{}, false
	}

	req := JSRequest{Method: strings.ToUpper(strings.TrimSpace(method)), RawURL: resolved}
	if req.Method == "" {
		req.Method = http.MethodGet
	}

	values := url.Values{}
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		values.Set(field.Name, field.Value)
	}

	if len(values) == 0 {
		return req, true
	}

	encoded := values.Encode()
	if strings.EqualFold(req.Method, http.MethodGet) {
		if strings.Contains(resolved, "?") {
			req.RawURL = resolved + "&" + encoded
		} else {
			req.RawURL = resolved + "?" + encoded
		}
	} else {
		req.Body = encoded
		req.ContentType = "application/x-www-form-urlencoded"
	}

	return req, true
}

// ExtractFormRequests converts a goquery selection (representing a form) into JSRequests.
func ExtractFormRequests(sel *goquery.Selection, base *url.URL) []JSRequest {
	if sel == nil {
		return nil
	}

	action, _ := sel.Attr("action")
	methodAttr := sel.AttrOr("method", http.MethodGet)

	fields := extractFormFields(sel)
	req, ok := buildFormRequest(action, methodAttr, fields, base)
	if !ok {
		return nil
	}

	requests := make([]JSRequest, 0, 6)
	requests = append(requests, req)

	if strings.EqualFold(req.Method, http.MethodGet) {
		headReq := req
		headReq.Method = http.MethodHead
		headReq.Body = ""
		headReq.ContentType = ""
		requests = append(requests, headReq)
	}

	if strings.EqualFold(req.Method, http.MethodPost) {
		if jsonBody := buildJSONFormBody(fields); jsonBody != "" {
			jsonReq := req
			jsonReq.Body = jsonBody
			jsonReq.ContentType = "application/json"
			requests = append(requests, jsonReq)
		}

		if multipartBody, boundary := buildMultipartFormBody(fields); multipartBody != "" {
			multipartReq := req
			multipartReq.Body = multipartBody
			multipartReq.ContentType = "multipart/form-data; boundary=" + boundary
			requests = append(requests, multipartReq)
		}

		if fuzzBody := buildFuzzFormBody(fields); fuzzBody != "" {
			fuzzReq := req
			fuzzReq.Body = fuzzBody
			requests = append(requests, fuzzReq)
		}

		emptyReq := req
		emptyReq.Body = ""
		emptyReq.ContentType = req.ContentType
		requests = append(requests, emptyReq)
	}

	return requests
}

func extractFormFields(sel *goquery.Selection) []FormField {
	var fields []FormField

	sel.Find("input").Each(func(_ int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if !exists {
			return
		}
		value := s.AttrOr("value", "")
		inputType := strings.ToLower(s.AttrOr("type", ""))
		switch inputType {
		case "checkbox", "radio":
			if _, ok := s.Attr("checked"); !ok {
				return
			}
			if value == "" {
				value = "on"
			}
		case "submit", "button", "image", "reset", "file":
			return
		}
		fields = append(fields, FormField{Name: name, Value: value})
	})

	sel.Find("textarea").Each(func(_ int, s *goquery.Selection) {
		if name, exists := s.Attr("name"); exists {
			fields = append(fields, FormField{Name: name, Value: strings.TrimSpace(s.Text())})
		}
	})

	sel.Find("select").Each(func(_ int, s *goquery.Selection) {
		name, exists := s.Attr("name")
		if !exists {
			return
		}
		value := ""
		s.Find("option").EachWithBreak(func(_ int, opt *goquery.Selection) bool {
			if _, selected := opt.Attr("selected"); selected {
				value = opt.AttrOr("value", strings.TrimSpace(opt.Text()))
				return false
			}
			if value == "" {
				value = opt.AttrOr("value", strings.TrimSpace(opt.Text()))
			}
			return true
		})
		fields = append(fields, FormField{Name: name, Value: value})
	})

	return fields
}

func buildJSONFormBody(fields []FormField) string {
	if len(fields) == 0 {
		return ""
	}
	payload := make(map[string]string, len(fields))
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		payload[field.Name] = field.Value
	}
	if len(payload) == 0 {
		return ""
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(buf)
}

func buildMultipartFormBody(fields []FormField) (string, string) {
	if len(fields) == 0 {
		return "", ""
	}
	boundary := fmt.Sprintf("gospider-%d", time.Now().UnixNano())
	var builder strings.Builder
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		builder.WriteString("--")
		builder.WriteString(boundary)
		builder.WriteString("\r\n")
		builder.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", field.Name, field.Value))
	}
	builder.WriteString("--")
	builder.WriteString(boundary)
	builder.WriteString("--")
	return builder.String(), boundary
}

func buildFuzzFormBody(fields []FormField) string {
	if len(fields) == 0 {
		return ""
	}
	values := url.Values{}
	for _, field := range fields {
		if field.Name == "" {
			continue
		}
		values.Set(field.Name, "FUZZ_"+field.Name)
	}
	if len(values) == 0 {
		return ""
	}
	return values.Encode()
}
