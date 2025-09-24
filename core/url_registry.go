package core

import (
	"strings"
	"sync"

	"github.com/jaeles-project/gospider/stringset"
)

type URLRegistry struct {
	once   sync.Once
	filter *stringset.StringFilter
}

func NewURLRegistry() *URLRegistry {
	return &URLRegistry{}
}

func (r *URLRegistry) ensure() {
	r.once.Do(func() {
		r.filter = stringset.NewStringFilter()
	})
}

func (r *URLRegistry) Duplicate(raw string) bool {
	if raw == "" {
		return false
	}
	r.ensure()
	normalized := strings.TrimSpace(raw)
	return r.filter.Duplicate(normalized)
}

func (r *URLRegistry) Filter() *stringset.StringFilter {
	r.ensure()
	return r.filter
}
