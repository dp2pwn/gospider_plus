package config

import (
	"time"

	"github.com/jaeles-project/gospider/internal/registry"
)

type ExtractorIntensity string

const (
	IntensityStandard ExtractorIntensity = "standard"
	IntensityUltra    ExtractorIntensity = "ultra"
)

type CrawlerConfig struct {
	Registry                 *registry.URLRegistry
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

type RuntimeOptions struct {
	Threads                  int
	BaseOnly                 bool
	EnableLinkfinder         bool
	EnableSitemap            bool
	EnableRobots             bool
	EnableOtherSources       bool
	IncludeOtherSourceResult bool
	IncludeSubs              bool
}
