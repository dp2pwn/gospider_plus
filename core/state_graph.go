package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

type DOMStateNode struct {
	StateHash  string
	PrimaryURL string
	URLs       map[string]struct{}
	Signature  uint64
	Digest     string
	FirstSeen  time.Time
	LastSeen   time.Time
	VisitCount int
	Analyzed   bool
}

type StateTransition struct {
	ActionType      string
	Details         map[string]string
	DestinationHash string
	Score           float64
	RecordedAt      time.Time
}

type ApplicationStateGraph struct {
	mu          sync.RWMutex
	nodes       map[string]*DOMStateNode
	transitions map[string]map[string]StateTransition
}

func NewApplicationStateGraph() *ApplicationStateGraph {
	return &ApplicationStateGraph{
		nodes:       make(map[string]*DOMStateNode),
		transitions: make(map[string]map[string]StateTransition),
	}
}

func (g *ApplicationStateGraph) NormalizeDOM(domContent string) string {
	return g.normalizeDOM(domContent)
}

func (g *ApplicationStateGraph) normalizeDOM(domContent string) string {
	if strings.TrimSpace(domContent) == "" {
		return ""
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(domContent))
	if err != nil {
		return normalizeWhitespace(domContent)
	}
	doc.Find("*").Each(func(_ int, selection *goquery.Selection) {
		node := selection.Get(0)
		if node == nil {
			return
		}
		tag := strings.ToLower(node.Data)
		switch tag {
		case "script", "style", "noscript", "template":
			_ = selection.SetHtml("")
		}
		dynamicIdentity := hasDynamicIdentity(node.Attr)
		cleaned := make([]html.Attribute, 0, len(node.Attr))
		for _, attr := range node.Attr {
			name := strings.ToLower(attr.Key)
			value := strings.TrimSpace(attr.Val)
			if shouldDropAttribute(name, value) {
				continue
			}
			if name == "value" && dynamicIdentity {
				value = ""
			} else if looksDynamicValue(value) {
				value = ""
			}
			cleaned = append(cleaned, html.Attribute{Namespace: attr.Namespace, Key: attr.Key, Val: value})
		}
		node.Attr = cleaned
	})
	htmlNode := doc.Find("html")
	var normalized string
	var errExtract error
	if htmlNode.Length() > 0 {
		normalized, errExtract = htmlNode.Html()
	}
	if errExtract != nil || normalized == "" {
		normalized, errExtract = doc.Html()
	}
	if errExtract != nil {
		return normalizeWhitespace(domContent)
	}
	return normalizeWhitespace(normalized)
}

func normalizeWhitespace(input string) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
	condensed := replacer.Replace(input)
	for strings.Contains(condensed, "  ") {
		condensed = strings.ReplaceAll(condensed, "  ", " ")
	}
	return strings.TrimSpace(condensed)
}

func shouldDropAttribute(name, value string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "data-") {
		if strings.Contains(name, "csrf") || strings.Contains(name, "token") {
			return true
		}
	}
	sensitiveKeys := []string{"csrf", "token", "nonce", "auth", "session", "timestamp"}
	for _, key := range sensitiveKeys {
		if strings.Contains(name, key) {
			return true
		}
	}
	if name == "class" && strings.Count(value, " ") > 12 {
		return true
	}
	return false
}

func hasDynamicIdentity(attrs []html.Attribute) bool {
	for _, attr := range attrs {
		name := strings.ToLower(attr.Key)
		value := strings.ToLower(strings.TrimSpace(attr.Val))
		if strings.Contains(name, "csrf") || strings.Contains(name, "token") || strings.Contains(name, "nonce") || strings.Contains(name, "session") || strings.Contains(name, "auth") {
			return true
		}
		if name == "id" || name == "name" || name == "class" {
			if strings.Contains(value, "csrf") || strings.Contains(value, "token") || strings.Contains(value, "nonce") || strings.Contains(value, "session") {
				return true
			}
		}
		if name == "type" && value == "hidden" {
			return true
		}
	}
	return false
}

func looksDynamicValue(value string) bool {
	if value == "" {
		return false
	}
	if len(value) >= 12 && strings.Count(value, "0")+strings.Count(value, "1")+strings.Count(value, "2")+
		strings.Count(value, "3")+strings.Count(value, "4")+strings.Count(value, "5")+
		strings.Count(value, "6")+strings.Count(value, "7")+strings.Count(value, "8")+
		strings.Count(value, "9") >= len(value)/2 {
		return true
	}
	if strings.Contains(value, "-") && strings.Count(value, "-") >= 3 {
		return true
	}
	if strings.Count(value, "=") >= 2 {
		return true
	}
	lower := strings.ToLower(value)
	dynamicHints := []string{"eyj", "csrf", "token", "timestamp", "expires", "refresh"}
	for _, hint := range dynamicHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func (g *ApplicationStateGraph) CalculateDOMFingerprint(domContent string) (string, uint64, string, error) {
	normalized := g.normalizeDOM(domContent)
	signature, err := ComputeDOMSignature([]byte(normalized))
	if err != nil {
		return "", 0, "", err
	}
	digest := sha256.Sum256([]byte(normalized))
	truncated := hex.EncodeToString(digest[:8])
	return fmt.Sprintf("%016x-%s", signature, truncated), signature, truncated, nil
}

func (g *ApplicationStateGraph) AddState(stateHash, url string, signature uint64, digest string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	node, exists := g.nodes[stateHash]
	if !exists {
		node = &DOMStateNode{
			StateHash:  stateHash,
			PrimaryURL: url,
			URLs:       make(map[string]struct{}),
			Signature:  signature,
			Digest:     digest,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			VisitCount: 1,
			Analyzed:   false,
		}
		if url != "" {
			node.URLs[url] = struct{}{}
		}
		g.nodes[stateHash] = node
		return true
	}
	node.LastSeen = time.Now()
	node.VisitCount++
	if url != "" {
		if node.PrimaryURL == "" {
			node.PrimaryURL = url
		}
		node.URLs[url] = struct{}{}
	}
	return false
}

func (g *ApplicationStateGraph) MarkAnalyzed(stateHash string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if node, ok := g.nodes[stateHash]; ok {
		node.Analyzed = true
	}
}

func (g *ApplicationStateGraph) NextUnanalyzed() *DOMStateNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var oldest *DOMStateNode
	for _, node := range g.nodes {
		if node.Analyzed {
			continue
		}
		if oldest == nil || node.FirstSeen.Before(oldest.FirstSeen) {
			oldest = node
		}
	}
	if oldest == nil {
		return nil
	}
	clone := *oldest
	return &clone
}

func (g *ApplicationStateGraph) RegisterTransitions(stateHash string, transitions []StateTransition) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	store, ok := g.transitions[stateHash]
	if !ok {
		store = make(map[string]StateTransition)
		g.transitions[stateHash] = store
	}
	added := 0
	for _, t := range transitions {
		key := transitionKey(t)
		if key == "" {
			continue
		}
		if _, exists := store[key]; exists {
			continue
		}
		if t.Details == nil {
			t.Details = make(map[string]string)
		}
		t.RecordedAt = time.Now()
		store[key] = t
		added++
	}
	return added
}

func (g *ApplicationStateGraph) UpdateTransitionDestination(stateHash, identity, destinationHash string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	store, ok := g.transitions[stateHash]
	if !ok {
		return
	}
	t, exists := store[identity]
	if !exists {
		return
	}
	t.DestinationHash = destinationHash
	store[identity] = t
}

func (g *ApplicationStateGraph) GetTransitions(stateHash string) []StateTransition {
	g.mu.RLock()
	defer g.mu.RUnlock()
	store, ok := g.transitions[stateHash]
	if !ok {
		return nil
	}
	result := make([]StateTransition, 0, len(store))
	for _, t := range store {
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].RecordedAt.Equal(result[j].RecordedAt) {
			return result[i].ActionType < result[j].ActionType
		}
		return result[i].RecordedAt.Before(result[j].RecordedAt)
	})
	return result
}

func (g *ApplicationStateGraph) TotalStates() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

func transitionKey(t StateTransition) string {
	if strings.TrimSpace(t.ActionType) == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(strings.ToLower(t.ActionType))
	if len(t.Details) > 0 {
		keys := make([]string, 0, len(t.Details))
		for k := range t.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			builder.WriteString("|")
			builder.WriteString(strings.ToLower(k))
			builder.WriteString("=")
			builder.WriteString(strings.TrimSpace(t.Details[k]))
		}
	}
	return builder.String()
}
