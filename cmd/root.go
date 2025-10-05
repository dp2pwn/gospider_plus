package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jaeles-project/gospider/core"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd returns the root command.
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   core.CLIName,
		Short: "Fast web spider written in Go",
		Long:  fmt.Sprintf("Fast web spider written in Go - %v by %v", core.VERSION, core.AUTHOR),
		RunE:  runRoot,
	}
	registerGlobalFlags(cmd)
	return cmd
}

// runRoot is the main function for the crawler.
func runRoot(cmd *cobra.Command, _ []string) error {
	version, _ := cmd.Flags().GetBool("version")
	if version {
		fmt.Printf("Version: %s\n", core.VERSION)
		Examples()
		return nil
	}

	isDebug, _ := cmd.Flags().GetBool("debug")
	if isDebug {
		core.Logger.SetLevel(logrus.DebugLevel)
	} else {
		core.Logger.SetLevel(logrus.InfoLevel)
	}

	verbose, _ := cmd.Flags().GetBool("verbose")
	if !verbose && !isDebug {
		core.Logger.SetOutput(ioutil.Discard)
	}

	outputFolder, _ := cmd.Flags().GetString("output")
	if outputFolder != "" {
		if _, err := os.Stat(outputFolder); os.IsNotExist(err) {
			_ = os.Mkdir(outputFolder, os.ModePerm)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	stats := core.NewCrawlStats()
	startTime := time.Now()
	quiet, _ := cmd.Flags().GetBool("quiet")

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case sig := <-sigChan:
				core.Logger.Warnf("Received signal %s, shutting down...", sig)
				cancel()
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !quiet {
					elapsed := time.Since(startTime).Round(time.Second)
					core.Logger.Infof("Stats [%s]: URLs: %d, Requests: %d, Errors: %d, RPS: %.2f",
						elapsed, stats.GetURLsFound(), stats.GetRequestsMade(), stats.GetErrors(), stats.GetRPS(elapsed))
				}
			}
		}
	}()

	var siteList []string
	siteInput, _ := cmd.Flags().GetString("site")
	if siteInput != "" {
		siteList = append(siteList, siteInput)
	}
	sitesListInput, _ := cmd.Flags().GetString("sites")
	if sitesListInput != "" {
		sitesFile := core.ReadingLines(sitesListInput)
		if len(sitesFile) > 0 {
			siteList = append(siteList, sitesFile...)
		}
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.TrimSpace(sc.Text())
			if err := sc.Err(); err == nil && target != "" {
				siteList = append(siteList, target)
			}
		}
	}

	if len(siteList) == 0 {
		core.Logger.Info("No site in list. Please check your site input again")
		return nil
	}

	threads, _ := cmd.Flags().GetInt("threads")
	sitemap, _ := cmd.Flags().GetBool("sitemap")
	robots, _ := cmd.Flags().GetBool("robots")
	otherSource, _ := cmd.Flags().GetBool("other-source")
	includeSubs, _ := cmd.Flags().GetBool("include-subs")
	includeOtherSourceResult, _ := cmd.Flags().GetBool("include-other-source")

	base, _ := cmd.Flags().GetBool("base")
	if base {
		cmd.Flags().Set("js", "false")
		cmd.Flags().Set("sitemap", "false")
		cmd.Flags().Set("robots", "false")
		cmd.Flags().Set("other-source", "false")
		cmd.Flags().Set("include-subs", "false")
		cmd.Flags().Set("include-other-source", "false")
	}

	crawlerConfig := core.NewCrawlerConfig(cmd)

	var wg sync.WaitGroup
	inputChan := make(chan string, threads)

	activeCrawlers := make(map[*core.Crawler]struct{})
	var crawlerMutex sync.Mutex

	go func() {
		<-ctx.Done()
		time.Sleep(500 * time.Millisecond)

		crawlerMutex.Lock()
		if len(activeCrawlers) > 0 {
			core.Logger.Warn("Forcing stop on active crawlers...")
		}
		for crawler := range activeCrawlers {
			crawler.Stop()
		}
		crawlerMutex.Unlock()
	}()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawSite := range inputChan {
				if ctx.Err() != nil {
					return
				}

				site, err := url.Parse(rawSite)
				if err != nil {
					logrus.Errorf("Failed to parse %s: %s", rawSite, err)
					stats.IncrementErrors()
					continue
				}

				var siteWg sync.WaitGroup

				crawler := core.NewCrawler(site, crawlerConfig)
				crawler.Stats = stats

				crawlerMutex.Lock()
				activeCrawlers[crawler] = struct{}{}
				crawlerMutex.Unlock()

				defer func() {
					crawlerMutex.Lock()
					delete(activeCrawlers, crawler)
					crawlerMutex.Unlock()
				}()

				siteWg.Add(1)
				go func() {
					defer siteWg.Done()
					if err := crawler.DeepCrawlWithKatana(crawlerConfig); err != nil {
						core.Logger.Errorf("katana crawl failed for %s: %v", site, err)
					}
				}()
				siteWg.Add(1)
				go func() {
					defer siteWg.Done()
					crawler.Start()
				}()

				if sitemap {
					siteWg.Add(1)
					go core.ParseSiteMap(site, crawler, crawler.C, &siteWg)
				}
				if robots {
					siteWg.Add(1)
					go core.ParseRobots(site, crawler, crawler.C, &siteWg)
				}

				if otherSource {
					siteWg.Add(1)
					go func() {
						defer siteWg.Done()
						urls := core.OtherSources(site.Hostname(), includeSubs)
						stats.AddURLsFound(len(urls))
						for _, u := range urls {
							if ctx.Err() != nil || crawler.IsStopped() {
								return
							}
							if includeOtherSourceResult {
								outputFormat := fmt.Sprintf("[other-sources] - %s", u)
								fmt.Println(outputFormat)
								if crawler.Output != nil {
									crawler.Output.WriteToFile(outputFormat)
								}
							}
							crawler.C.Visit(u)
						}
					}()
				}
				siteWg.Wait()
				crawler.C.Wait()
				crawler.LinkFinderCollector.Wait()
				crawler.WaitHybrid()
			}
		}()
	}

	go func() {
		defer close(inputChan)
		for _, site := range siteList {
			select {
			case <-ctx.Done():
				core.Logger.Warn("Stopping site input due to cancellation.")
				return
			case inputChan <- site:
			}
		}
	}()

	wg.Wait()
	cancel()

	elapsed := time.Since(startTime).Round(time.Second)
	if !quiet {
		core.Logger.Infof("Crawl finished in %s", elapsed)
		core.Logger.Infof("Final Stats: URLs Found: %d, Requests Made: %d, Errors: %d, Average RPS: %.2f",
			stats.GetURLsFound(), stats.GetRequestsMade(), stats.GetErrors(), stats.GetRPS(elapsed))
	}
	core.Logger.Info("Done.")
	return nil
}

func Examples() string {
	return `gospider -q -s "https://target.com/"
gospider -s "https://target.com/" -o output -c 10 -d 1
gospider -s "https://target.com/" -o output -c 10 -d 1 --other-source
echo 'http://target.com' | gospider -o output -c 10 -d 1 --other-source`
}

func registerGlobalFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("site", "s", "", "Site to crawl")
	cmd.Flags().StringP("sites", "S", "", "Site list to crawl")
	cmd.Flags().StringP("proxy", "p", "", "Proxy (Ex: http://127.0.0.1:8080)")
	cmd.Flags().StringP("output", "o", "", "Output folder")
	cmd.Flags().StringP("user-agent", "u", "web", "User Agent to use\n\tweb: random web user-agent\n\tmobi: random mobile user-agent\n\tor you can set your special user-agent")
	cmd.Flags().StringP("cookie", "", "", "Cookie to use (testA=a; testB=b)")
	cmd.Flags().StringArrayP("header", "H", []string{}, "Header to use (Use multiple flag to set multiple header)")
	cmd.Flags().StringP("burp", "", "", "Load headers and cookie from burp raw http request")
	cmd.Flags().StringP("blacklist", "", "", "Blacklist URL Regex")
	cmd.Flags().StringP("whitelist", "", "", "Whitelist URL Regex")
	cmd.Flags().StringP("whitelist-domain", "", "", "Whitelist Domain")
	cmd.Flags().StringP("filter-length", "L", "", "Turn on length filter")

	cmd.Flags().BoolP("stealth", "", false, "Enable stealth mode with advanced WAF bypass techniques")
	cmd.Flags().IntP("threads", "t", 1, "Number of threads (Run sites in parallel)")
	cmd.Flags().IntP("concurrent", "c", 5, "The number of the maximum allowed concurrent requests of the matching domains")
	cmd.Flags().IntP("depth", "d", 1, "MaxDepth limits the recursion depth of visited URLs. (Set it to 0 for infinite recursion)")
	cmd.Flags().IntP("delay", "k", 0, "Delay is the duration to wait before creating a new request to the matching domains (second)")
	cmd.Flags().IntP("random-delay", "K", 0, "RandomDelay is the extra randomized duration to wait added to Delay before creating a new request (second)")
	cmd.Flags().IntP("timeout", "m", 10, "Request timeout (second)")

	cmd.Flags().BoolP("base", "B", false, "Disable all and only use HTML content")
	cmd.Flags().BoolP("js", "", true, "Enable linkfinder in javascript file")
	cmd.Flags().BoolP("sitemap", "", false, "Try to crawl sitemap.xml")
	cmd.Flags().BoolP("robots", "", true, "Try to crawl robots.txt")
	cmd.Flags().BoolP("other-source", "a", false, "Find URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com)")
	cmd.Flags().BoolP("include-subs", "w", false, "Include subdomains crawled from 3rd party. Default is main domain")
	cmd.Flags().BoolP("include-other-source", "r", false, "Also include other-source's urls (still crawl and request)")
	cmd.Flags().Bool("subs", false, "Include subdomains")

	cmd.Flags().BoolP("debug", "", false, "Turn on debug mode")
	cmd.Flags().BoolP("json", "", false, "Enable JSON output")
	cmd.Flags().BoolP("verbose", "v", false, "Turn on verbose")
	cmd.Flags().BoolP("quiet", "q", false, "Suppress all the output and only show URL")
	cmd.Flags().BoolP("no-redirect", "", false, "Disable redirect")
	cmd.Flags().BoolP("version", "", false, "Check version")
	cmd.Flags().BoolP("length", "l", false, "Turn on length")
	cmd.Flags().BoolP("raw", "R", false, "Enable raw output")
	cmd.Flags().Bool("reflected", false, "Enable reflected payload detection")
	cmd.Flags().String("reflected-output", "", "File path to store reflected findings")
	cmd.Flags().Bool("dom-dedup", false, "Enable DOM structural deduplication")
	cmd.Flags().Int("dom-dedup-threshold", 6, "Hamming threshold for DOM dedup")
	cmd.Flags().Int("baseline-fuzz-cap", 2, "Maximum baseline fuzz mutations per parameter")
	cmd.Flags().Bool("hybrid", false, "Enable state-aware hybrid crawling (requires Chromium)")
	cmd.Flags().Int("hybrid-workers", 2, "Number of concurrent browser workers for hybrid crawling")
	cmd.Flags().Int("hybrid-nav-timeout", 12, "Hybrid browser navigation timeout in seconds")
	cmd.Flags().Int("hybrid-stabilization", 600, "Extra wait after load before analysis in milliseconds")
	cmd.Flags().Bool("hybrid-headless", true, "Run hybrid browser workers in headless mode")
	cmd.Flags().StringSlice("hybrid-init-script", []string{}, "Inject JavaScript files into hybrid browsers before navigation")
	cmd.Flags().Int("hybrid-max-visits", 150, "Limit total pages explored by hybrid browser (0 = unlimited)")

	cmd.Flags().SortFlags = false
}