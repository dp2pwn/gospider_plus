package stringset

import (
	"strings"
	"testing"
)

func TestStringFilterDuplicateCaseInsensitive(t *testing.T) {
	filter := NewStringFilter()
	first := "https://example.com/piUtils.js?ver=1"
	if filter.Duplicate(first) {
		t.Fatalf("first insert should not be duplicate")
	}
	if !filter.Duplicate(first) {
		t.Fatalf("identical string should be duplicate")
	}
	lower := strings.ToLower(first)
	if !filter.Duplicate(lower) {
		t.Fatalf("case-insensitive match should be duplicate")
	}
}
