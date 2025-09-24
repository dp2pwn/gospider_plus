package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type crtRecord struct {
	Name string `json:"name_value"`
}

// FetchSubdomains aggregates subdomains from public sources for the given domain.
func FetchSubdomains(domain string) []string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil
	}

	seen := make(map[string]struct{})
	seen[domain] = struct{}{}

	if records, err := fetchCRTShSubdomains(domain); err != nil {
		Logger.Debugf("crt.sh lookup failed: %v", err)
	} else {
		for _, sub := range records {
			seen[sub] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for sub := range seen {
		out = append(out, sub)
	}
	sort.Strings(out)
	return out
}

func fetchCRTShSubdomains(domain string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	endpoint := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "gospider/plus")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var records []crtRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	set := make(map[string]struct{})
	for _, record := range records {
		if record.Name == "" {
			continue
		}
		for _, candidate := range strings.Split(record.Name, "\n") {
			sub := CleanSubdomain(candidate)
			if sub == "" {
				continue
			}
			if !strings.HasSuffix(sub, domain) {
				continue
			}
			set[sub] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for sub := range set {
		out = append(out, sub)
	}
	sort.Strings(out)
	return out, nil
}
