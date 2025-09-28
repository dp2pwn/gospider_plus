package cmd

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/jaeles-project/gospider/core"
	"github.com/jaeles-project/gospider/internal/logging"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   core.CLIName,
		Short: "Fast web spider",
		Long:  fmt.Sprintf("Fast web spider written in Go - %s by %s", core.VERSION, core.AUTHOR),
		RunE:  runRoot,
	}
	registerGlobalFlags(cmd)
	cmd.SilenceUsage = true
	return cmd
}

func runRoot(cmd *cobra.Command, _ []string) error {
	if showVersion, err := cmd.Flags().GetBool("version"); err == nil && showVersion {
		fmt.Printf("Version: %s\n", core.VERSION)
		fmt.Println(renderExamples())
		return nil
	}

	debug, err := cmd.Flags().GetBool("debug")
	if err != nil {
		return err
	}
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	quiet, err := cmd.Flags().GetBool("quiet")
	if err != nil {
		return err
	}

	logging.Configure(core.Logger, logging.Options{Debug: debug, Verbose: verbose, Quiet: quiet})

	crawlerConfig, runtimeOpts, err := core.LoadConfig(cmd)
	if err != nil {
		return err
	}

	if outDir := strings.TrimSpace(crawlerConfig.OutputDir); outDir != "" {
		if err := os.MkdirAll(outDir, os.ModePerm); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	targets, err := gatherTargets(cmd)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		core.Logger.Info("No site in list. Please check your site input again")
		return nil
	}

	threads := runtimeOpts.Threads
	if threads <= 0 {
		threads = 1
	}

	var wg sync.WaitGroup
	inputChan := make(chan string, threads)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for raw := range inputChan {
				crawlSite(raw, crawlerConfig, runtimeOpts)
			}
		}()
	}

	for _, target := range targets {
		inputChan <- target
	}
	close(inputChan)

	wg.Wait()
	core.Logger.Info("Done.")
	return nil
}

func crawlSite(raw string, cfg core.CrawlerConfig, runtime core.RuntimeOptions) {
	site, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		logrus.Errorf("Failed to parse %s: %v", raw, err)
		return
	}

	var siteWg sync.WaitGroup
	crawler := core.NewCrawler(site, cfg)

	siteWg.Add(1)
	go func() {
		defer siteWg.Done()
		if err := crawler.DeepCrawlWithKatana(cfg); err != nil {
			core.Logger.Errorf("katana crawl failed for %s: %v", site, err)
		}
	}()

	siteWg.Add(1)
	go func() {
		defer siteWg.Done()
		crawler.Start(runtime.EnableLinkfinder)
	}()

	if runtime.EnableSitemap {
		siteWg.Add(1)
		go core.ParseSiteMap(site, crawler, crawler.C, &siteWg)
	}
	if runtime.EnableRobots {
		siteWg.Add(1)
		go core.ParseRobots(site, crawler, crawler.C, &siteWg)
	}
	if runtime.EnableOtherSources {
		siteWg.Add(1)
		go func() {
			defer siteWg.Done()
			emitOtherSources(site, crawler, runtime.IncludeSubs, runtime.IncludeOtherSourceResult)
		}()
	}

	siteWg.Wait()
	crawler.C.Wait()
	crawler.LinkFinderCollector.Wait()
	crawler.WaitHybrid()
}

func emitOtherSources(site *url.URL, crawler *core.Crawler, includeSubs, includeOtherSourceResult bool) {
	urls := core.OtherSources(site.Hostname(), includeSubs)
	for _, value := range urls {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		outputFormat := fmt.Sprintf("[other-sources] - %s", value)
		if includeOtherSourceResult {
			if crawler.JsonOutput {
				sout := core.SpiderOutput{
					Input:      crawler.Input,
					Source:     "other-sources",
					OutputType: "url",
					Output:     value,
				}
				if data, err := jsoniter.MarshalToString(sout); err == nil {
					outputFormat = data
				}
			} else if crawler.Quiet {
				outputFormat = value
			}
		}

		fmt.Println(outputFormat)
		if crawler.Output != nil {
			crawler.Output.WriteToFile(outputFormat)
		}

		_ = crawler.C.Visit(value)
	}
}

func gatherTargets(cmd *cobra.Command) ([]string, error) {
	var targets []string
	if site, err := cmd.Flags().GetString("site"); err == nil && strings.TrimSpace(site) != "" {
		targets = append(targets, strings.TrimSpace(site))
	} else if err != nil {
		return nil, err
	}

	if listPath, err := cmd.Flags().GetString("sites"); err == nil && strings.TrimSpace(listPath) != "" {
		targets = append(targets, core.ReadingLines(listPath)...)
	} else if err != nil {
		return nil, err
	}

	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			if value == "" {
				continue
			}
			targets = append(targets, value)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return targets, nil
}

func registerGlobalFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringP("site", "s", "", "Site to crawl")
	flags.StringP("sites", "S", "", "Site list to crawl")
	flags.StringP("proxy", "p", "", "Proxy (Ex: http://127.0.0.1:8080)")
	flags.StringP("output", "o", "", "Output folder")
	flags.StringP("user-agent", "u", "web", "User Agent to use\n\tweb: random web user-agent\n\tmobi: random mobile user-agent\n\tor you can set your special user-agent")
	flags.StringP("cookie", "", "", "Cookie to use (testA=a; testB=b)")
	flags.StringArrayP("header", "H", []string{}, "Header to use (Use multiple flag to set multiple header)")
	flags.StringP("burp", "", "", "Load headers and cookie from burp raw http request")
	flags.StringP("blacklist", "", "", "Blacklist URL Regex")
	flags.StringP("whitelist", "", "", "Whitelist URL Regex")
	flags.StringP("whitelist-domain", "", "", "Whitelist Domain")
	flags.StringP("filter-length", "L", "", "Turn on length filter")

	flags.BoolP("stealth", "", false, "Enable stealth mode with advanced WAF bypass techniques")
	flags.IntP("threads", "t", 1, "Number of threads (Run sites in parallel)")
	flags.IntP("concurrent", "c", 5, "The number of the maximum allowed concurrent requests of the matching domains")
	flags.IntP("depth", "d", 1, "MaxDepth limits the recursion depth of visited URLs. (Set it to 0 for infinite recursion)")
	flags.IntP("delay", "k", 0, "Delay is the duration to wait before creating a new request to the matching domains (second)")
	flags.IntP("random-delay", "K", 0, "RandomDelay is the extra randomized duration to wait added to Delay before creating a new request (second)")
	flags.IntP("timeout", "m", 10, "Request timeout (second)")

	flags.BoolP("base", "B", false, "Disable all and only use HTML content")
	flags.BoolP("js", "", true, "Enable linkfinder in javascript file")
	flags.BoolP("sitemap", "", false, "Try to crawl sitemap.xml")
	flags.BoolP("robots", "", true, "Try to crawl robots.txt")
	flags.BoolP("other-source", "a", false, "Find URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com)")
	flags.BoolP("include-subs", "w", false, "Include subdomains crawled from 3rd party. Default is main domain")
	flags.BoolP("include-other-source", "r", false, "Also include other-source's urls (still crawl and request)")
	flags.Bool("subs", false, "Include subdomains")

	flags.BoolP("debug", "", false, "Turn on debug mode")
	flags.BoolP("json", "", false, "Enable JSON output")
	flags.BoolP("verbose", "v", false, "Turn on verbose")
	flags.BoolP("quiet", "q", false, "Suppress all the output and only show URL")
	flags.BoolP("no-redirect", "", false, "Disable redirect")
	flags.BoolP("version", "", false, "Check version")
	flags.BoolP("length", "l", false, "Turn on length")
	flags.BoolP("raw", "R", false, "Enable raw output")
	flags.Bool("reflected", false, "Enable reflected payload detection")
	flags.String("reflected-output", "", "File path to store reflected findings")
	flags.Bool("dom-dedup", false, "Enable DOM structural deduplication")
	flags.Int("dom-dedup-threshold", 6, "Hamming threshold for DOM dedup")
	flags.Int("baseline-fuzz-cap", 2, "Maximum baseline fuzz mutations per parameter")
	flags.Bool("hybrid", false, "Enable state-aware hybrid crawling (requires Chromium)")
	flags.Int("hybrid-workers", 2, "Number of concurrent browser workers for hybrid crawling")
	flags.Int("hybrid-nav-timeout", 12, "Hybrid browser navigation timeout in seconds")
	flags.Int("hybrid-stabilization", 600, "Extra wait after load before analysis in milliseconds")
	flags.Bool("hybrid-headless", true, "Run hybrid browser workers in headless mode")
	flags.StringSlice("hybrid-init-script", []string{}, "Inject JavaScript files into hybrid browsers before navigation")
	flags.Int("hybrid-max-visits", 150, "Limit total pages explored by hybrid browser (0 = unlimited)")

	flags.SortFlags = false
}
