package core

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// FormField represents a parsed HTML form field.
type FormField struct {
	Name  string
	Value string
}

// buildFormRequest constructs a JSRequest from form attributes and fields.
func buildFormRequest(action string, method string, fields []FormField, base *url.URL) (JSRequest, bool) {
	resolved := action
	if resolved == "" && base != nil {
		resolved = base.String()
	}
	if base != nil {
		if u, err := url.Parse(resolved); err == nil {
			if base != nil {
				resolved = base.ResolveReference(u).String()
			} else {
				resolved = u.String()
			}
		} else {
			resolved = ""
		}
	}
	if resolved == "" {
		return JSRequest{}, false
	}

	req := JSRequest{Method: strings.ToUpper(method), RawURL: resolved}
	if req.Method == "" {
		req.Method = "GET"
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
	if req.Method == "GET" {
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
	methodAttr := sel.AttrOr("method", "GET")

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

	req, ok := buildFormRequest(action, methodAttr, fields, base)
	if !ok {
		return nil
	}
	return []JSRequest{req}
}
