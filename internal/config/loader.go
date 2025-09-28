package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Loader struct {
	cmd *cobra.Command
}

func NewLoader(cmd *cobra.Command) Loader {
	return Loader{cmd: cmd}
}

func (l Loader) Load() (CrawlerConfig, RuntimeOptions, error) {
	flags := l.cmd.Flags()
	var cfg CrawlerConfig
	var runtime RuntimeOptions

	getBool := func(name string) (bool, error) {
		v, err := flags.GetBool(name)
		if err != nil {
			return false, fmt.Errorf("get bool %s: %w", name, err)
		}
		return v, nil
	}
	getInt := func(name string) (int, error) {
		v, err := flags.GetInt(name)
		if err != nil {
			return 0, fmt.Errorf("get int %s: %w", name, err)
		}
		return v, nil
	}
	getString := func(name string) (string, error) {
		v, err := flags.GetString(name)
		if err != nil {
			return "", fmt.Errorf("get string %s: %w", name, err)
		}
		return v, nil
	}

	var err error

	if cfg.Quiet, err = getBool("quiet"); err != nil {
		return cfg, runtime, err
	}
	if cfg.JSONOutput, err = getBool("json"); err != nil {
		return cfg, runtime, err
	}
	if cfg.MaxDepth, err = getInt("depth"); err != nil {
		return cfg, runtime, err
	}
	if cfg.MaxConcurrency, err = getInt("concurrent"); err != nil {
		return cfg, runtime, err
	}
	if v, err := getInt("delay"); err != nil {
		return cfg, runtime, err
	} else {
		cfg.Delay = time.Duration(v) * time.Second
	}
	if v, err := getInt("random-delay"); err != nil {
		return cfg, runtime, err
	} else {
		cfg.RandomDelay = time.Duration(v) * time.Second
	}
	if cfg.Length, err = getBool("length"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Raw, err = getBool("raw"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Subs, err = getBool("subs"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Reflected, err = getBool("reflected"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Stealth, err = getBool("stealth"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Proxy, err = getString("proxy"); err != nil {
		return cfg, runtime, err
	}
	if v, err := getInt("timeout"); err != nil {
		return cfg, runtime, err
	} else {
		cfg.Timeout = time.Duration(v) * time.Second
	}
	if cfg.NoRedirect, err = getBool("no-redirect"); err != nil {
		return cfg, runtime, err
	}
	if cfg.BurpFile, err = getString("burp"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Cookie, err = getString("cookie"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Headers, err = flags.GetStringArray("header"); err != nil {
		return cfg, runtime, fmt.Errorf("get headers: %w", err)
	}
	if cfg.UserAgent, err = getString("user-agent"); err != nil {
		return cfg, runtime, err
	}
	cfg.UserAgent = strings.ToLower(cfg.UserAgent)

	if cfg.OutputDir, err = getString("output"); err != nil {
		return cfg, runtime, err
	}
	if cfg.ReflectedOutput, err = getString("reflected-output"); err != nil {
		return cfg, runtime, err
	}
	if cfg.FilterLength, err = getString("filter-length"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Blacklist, err = getString("blacklist"); err != nil {
		return cfg, runtime, err
	}
	if cfg.Whitelist, err = getString("whitelist"); err != nil {
		return cfg, runtime, err
	}
	if cfg.WhitelistDomain, err = getString("whitelist-domain"); err != nil {
		return cfg, runtime, err
	}
	if cfg.DomDedup, err = getBool("dom-dedup"); err != nil {
		return cfg, runtime, err
	}
	if cfg.DomDedupThresh, err = getInt("dom-dedup-threshold"); err != nil {
		return cfg, runtime, err
	}
	if cfg.DomDedupThresh <= 0 {
		cfg.DomDedupThresh = 6
	}
	if cfg.BaselineFuzzCap, err = getInt("baseline-fuzz-cap"); err != nil {
		return cfg, runtime, err
	}
	if cfg.BaselineFuzzCap <= 0 {
		cfg.BaselineFuzzCap = 2
	}

	if cfg.HybridCrawl, err = getBool("hybrid"); err != nil {
		return cfg, runtime, err
	}
	if cfg.HybridWorkers, err = getInt("hybrid-workers"); err != nil {
		return cfg, runtime, err
	}
	if cfg.HybridNavigationTimeout, err = durationFromFlags(flags, "hybrid-nav-timeout", time.Second); err != nil {
		return cfg, runtime, err
	}
	if cfg.HybridNavigationTimeout <= 0 {
		cfg.HybridNavigationTimeout = 12 * time.Second
	}
	if cfg.HybridStabilizationDelay, err = durationFromFlags(flags, "hybrid-stabilization", time.Millisecond); err != nil {
		return cfg, runtime, err
	}
	if cfg.HybridStabilizationDelay <= 0 {
		cfg.HybridStabilizationDelay = 600 * time.Millisecond
	}
	if cfg.HybridHeadless, err = getBool("hybrid-headless"); err != nil {
		return cfg, runtime, err
	}
	if cfg.HybridInitScripts, err = flags.GetStringSlice("hybrid-init-script"); err != nil {
		return cfg, runtime, fmt.Errorf("get hybrid-init-script: %w", err)
	}
	if cfg.HybridVisitLimit, err = getInt("hybrid-max-visits"); err != nil {
		return cfg, runtime, err
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

	cfg.Intensity = IntensityUltra

	if runtime.Threads, err = getInt("threads"); err != nil {
		return cfg, runtime, err
	}
	if runtime.Threads <= 0 {
		runtime.Threads = 1
	}
	if runtime.BaseOnly, err = getBool("base"); err != nil {
		return cfg, runtime, err
	}
	if runtime.EnableLinkfinder, err = getBool("js"); err != nil {
		return cfg, runtime, err
	}
	if runtime.EnableSitemap, err = getBool("sitemap"); err != nil {
		return cfg, runtime, err
	}
	if runtime.EnableRobots, err = getBool("robots"); err != nil {
		return cfg, runtime, err
	}
	if runtime.EnableOtherSources, err = getBool("other-source"); err != nil {
		return cfg, runtime, err
	}
	if runtime.IncludeSubs, err = getBool("include-subs"); err != nil {
		return cfg, runtime, err
	}
	if runtime.IncludeOtherSourceResult, err = getBool("include-other-source"); err != nil {
		return cfg, runtime, err
	}

	if runtime.BaseOnly {
		runtime.EnableLinkfinder = false
		runtime.EnableRobots = false
		runtime.EnableOtherSources = false
		runtime.IncludeSubs = false
		runtime.IncludeOtherSourceResult = false
		runtime.EnableSitemap = false
	}

	return cfg, runtime, nil
}

func durationFromFlags(flags *pflag.FlagSet, name string, unit time.Duration) (time.Duration, error) {
	v, err := flags.GetInt(name)
	if err != nil {
		return 0, fmt.Errorf("get int %s: %w", name, err)
	}
	return time.Duration(v) * unit, nil
}
