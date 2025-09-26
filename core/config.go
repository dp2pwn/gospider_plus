package core

import (
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type ExtractorIntensity string

const (
	IntensityStandard ExtractorIntensity = "standard"
	IntensityUltra    ExtractorIntensity = "ultra"
)

// CrawlerConfig captures CLI options that influence crawler behavior.
type CrawlerConfig struct {
	Registry                 *URLRegistry
	Intensity                ExtractorIntensity
	Quiet                    bool
	JSONOutput               bool
	MaxDepth                 int
	MaxConcurrency           int
	Delay                    time.Duration
	RandomDelay              time.Duration
	Length                   bool
	Raw                      bool
	Subs                     bool
	Reflected                bool
	Stealth                  bool
	Proxy                    string
	Timeout                  time.Duration
	NoRedirect               bool
	BurpFile                 string
	Cookie                   string
	Headers                  []string
	UserAgent                string
	OutputDir                string
	ReflectedOutput          string
	FilterLength             string
	Blacklist                string
	Whitelist                string
	WhitelistDomain          string
	DomDedup                 bool
	DomDedupThresh           int
	BaselineFuzzCap          int
	HybridCrawl              bool
	HybridWorkers            int
	HybridNavigationTimeout  time.Duration
	HybridStabilizationDelay time.Duration
	HybridHeadless           bool
	HybridInitScripts        []string
	HybridVisitLimit         int
}

func NewCrawlerConfig(cmd *cobra.Command) CrawlerConfig {
	getBool := func(name string) bool {
		v, _ := cmd.Flags().GetBool(name)
		return v
	}
	getInt := func(name string) int {
		v, _ := cmd.Flags().GetInt(name)
		return v
	}
	getString := func(name string) string {
		v, _ := cmd.Flags().GetString(name)
		return v
	}

	cfg := CrawlerConfig{
		Quiet:          getBool("quiet"),
		JSONOutput:     getBool("json"),
		MaxDepth:       getInt("depth"),
		MaxConcurrency: getInt("concurrent"),
		Delay:          time.Duration(getInt("delay")) * time.Second,
		RandomDelay:    time.Duration(getInt("random-delay")) * time.Second,
		Length:         getBool("length"),
		Raw:            getBool("raw"),
		Subs:           getBool("subs"),
		Reflected:      getBool("reflected"),
		Stealth:        getBool("stealth"),
		Proxy:          getString("proxy"),
		Timeout:        time.Duration(getInt("timeout")) * time.Second,
		NoRedirect:     getBool("no-redirect"),
		BurpFile:       getString("burp"),
		Cookie:         getString("cookie"),
		Headers: func() []string {
			v, _ := cmd.Flags().GetStringArray("header")
			return v
		}(),
		UserAgent:       strings.ToLower(getString("user-agent")),
		OutputDir:       getString("output"),
		ReflectedOutput: getString("reflected-output"),
		FilterLength:    getString("filter-length"),
		Blacklist:       getString("blacklist"),
		Whitelist:       getString("whitelist"),
		WhitelistDomain: getString("whitelist-domain"),
		DomDedup:        getBool("dom-dedup"),
		DomDedupThresh: func() int {
			if v := getInt("dom-dedup-threshold"); v > 0 {
				return v
			}
			return 6
		}(),
		BaselineFuzzCap: func() int {
			if v := getInt("baseline-fuzz-cap"); v > 0 {
				return v
			}
			return 2
		}(),
		Intensity: IntensityUltra,
	}

	cfg.HybridCrawl = getBool("hybrid")
	cfg.HybridWorkers = getInt("hybrid-workers")
	cfg.HybridNavigationTimeout = time.Duration(getInt("hybrid-nav-timeout")) * time.Second
	cfg.HybridStabilizationDelay = time.Duration(getInt("hybrid-stabilization")) * time.Millisecond
	cfg.HybridHeadless = getBool("hybrid-headless")
	cfg.HybridInitScripts = func() []string {
		v, _ := cmd.Flags().GetStringSlice("hybrid-init-script")
		return v
	}()
	cfg.HybridVisitLimit = getInt("hybrid-max-visits")

	if cfg.HybridNavigationTimeout <= 0 {
		cfg.HybridNavigationTimeout = 12 * time.Second
	}
	if cfg.HybridStabilizationDelay <= 0 {
		cfg.HybridStabilizationDelay = 600 * time.Millisecond
	}
	if cfg.HybridWorkers <= 0 {
		cfg.HybridWorkers = 2
	}

	if cfg.HybridVisitLimit < 0 {
		cfg.HybridVisitLimit = 0
	}
	if cfg.ReflectedOutput != "" {
		cfg.Reflected = true
	}

	return cfg
}
