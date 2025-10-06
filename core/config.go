package core

import (
	"time"

	"github.com/spf13/cobra"
)

// CrawlerConfig holds the configuration for a single crawler.
type CrawlerConfig struct {
	Site                     string
	Sites                    string
	BurpFile                 string
	Cookie                   string
	UserAgent                string
	Headers                  []string
	Timeout                  time.Duration
	MaxDepth                 int
	MaxConcurrency           int
	Threads                  int
	Delay                    time.Duration
	RandomDelay              time.Duration
	OutputDir                string
	Quiet                    bool
	JSONOutput               bool
	Length                   bool
	Raw                      bool
	Subs                     bool
	OtherSource              bool
	IncludeSubs              bool
	IncludeOtherSourceResult bool
	NoRedirect               bool
	Proxy                    string
	Blacklist                string
	Whitelist                string
	WhitelistDomain          string
	LinkFinder               bool
	Reflected                bool
	Stealth                  bool
	ReflectedOutput          string
	FilterLength             string
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
	Intensity                string
	Registry                 *URLRegistry
	Sitemap                  bool
	Robots                   bool
}

// NewCrawlerConfig is a constructor for CrawlerConfig.
// It is used to get the config from the cobra command.
func NewCrawlerConfig(cmd *cobra.Command) CrawlerConfig {
	site, _ := cmd.Flags().GetString("site")
	sites, _ := cmd.Flags().GetString("sites")
	burpFile, _ := cmd.Flags().GetString("burp")
	cookie, _ := cmd.Flags().GetString("cookie")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	headers, _ := cmd.Flags().GetStringArray("header")
	timeout, _ := cmd.Flags().GetInt("timeout")
	depth, _ := cmd.Flags().GetInt("depth")
	concurrent, _ := cmd.Flags().GetInt("concurrent")
	threads, _ := cmd.Flags().GetInt("threads")
	delay, _ := cmd.Flags().GetInt("delay")
	randomDelay, _ := cmd.Flags().GetInt("random-delay")
	output, _ := cmd.Flags().GetString("output")
	quiet, _ := cmd.Flags().GetBool("quiet")
	json, _ := cmd.Flags().GetBool("json")
	length, _ := cmd.Flags().GetBool("length")
	raw, _ := cmd.Flags().GetBool("raw")
	subs, _ := cmd.Flags().GetBool("subs")
	otherSource, _ := cmd.Flags().GetBool("other-source")
	includeSubs, _ := cmd.Flags().GetBool("include-subs")
	includeOtherSourceResult, _ := cmd.Flags().GetBool("include-other-source-result")
	noRedirect, _ := cmd.Flags().GetBool("no-redirect")
	proxy, _ := cmd.Flags().GetString("proxy")
	blacklist, _ := cmd.Flags().GetString("blacklist")
	whitelist, _ := cmd.Flags().GetString("whitelist")
	whitelistDomain, _ := cmd.Flags().GetString("whitelist-domain")
	linkfinder, _ := cmd.Flags().GetBool("linkfinder")
	reflected, _ := cmd.Flags().GetBool("reflected")
	stealth, _ := cmd.Flags().GetBool("stealth")
	reflectedOutput, _ := cmd.Flags().GetString("reflected-output")
	filterLength, _ := cmd.Flags().GetString("filter-length")
	domDedup, _ := cmd.Flags().GetBool("dom-dedup")
	domDedupThresh, _ := cmd.Flags().GetInt("dom-dedup-threshold")
	baselineFuzzCap, _ := cmd.Flags().GetInt("baseline-fuzz-cap")
	hybrid, _ := cmd.Flags().GetBool("hybrid")
	hybridWorkers, _ := cmd.Flags().GetInt("hybrid-workers")
	hybridNavTimeout, _ := cmd.Flags().GetInt("hybrid-nav-timeout")
	hybridStabilization, _ := cmd.Flags().GetInt("hybrid-stabilization")
	hybridHeadless, _ := cmd.Flags().GetBool("hybrid-headless")
	hybridInitScripts, _ := cmd.Flags().GetStringSlice("hybrid-init-script")
	hybridMaxVisits, _ := cmd.Flags().GetInt("hybrid-max-visits")
	sitemap, _ := cmd.Flags().GetBool("sitemap")
	robots, _ := cmd.Flags().GetBool("robots")

	if reflectedOutput != "" {
		reflected = true
	}

	return CrawlerConfig{
		Site:                     site,
		Sites:                    sites,
		BurpFile:                 burpFile,
		Cookie:                   cookie,
		UserAgent:                userAgent,
		Headers:                  headers,
		Timeout:                  time.Duration(timeout) * time.Second,
		MaxDepth:                 depth,
		MaxConcurrency:           concurrent,
		Threads:                  threads,
		Delay:                    time.Duration(delay) * time.Second,
		RandomDelay:              time.Duration(randomDelay) * time.Second,
		OutputDir:                output,
		Quiet:                    quiet,
		JSONOutput:               json,
		Length:                   length,
		Raw:                      raw,
		Subs:                     subs,
		OtherSource:              otherSource,
		IncludeSubs:              includeSubs,
		IncludeOtherSourceResult: includeOtherSourceResult,
		NoRedirect:               noRedirect,
		Proxy:                    proxy,
		Blacklist:                blacklist,
		Whitelist:                whitelist,
		WhitelistDomain:          whitelistDomain,
		LinkFinder:               linkfinder,
		Reflected:                reflected,
		Stealth:                  stealth,
		ReflectedOutput:          reflectedOutput,
		FilterLength:             filterLength,
		DomDedup:                 domDedup,
		DomDedupThresh:           domDedupThresh,
		BaselineFuzzCap:          baselineFuzzCap,
		HybridCrawl:              hybrid,
		HybridWorkers:            hybridWorkers,
		HybridNavigationTimeout:  time.Duration(hybridNavTimeout) * time.Second,
		HybridStabilizationDelay: time.Duration(hybridStabilization) * time.Millisecond,
		HybridHeadless:           hybridHeadless,
		HybridInitScripts:        hybridInitScripts,
		HybridVisitLimit:         hybridMaxVisits,
		Sitemap:                  sitemap,
		Robots:                   robots,
	}
}