package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

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
	engine := core.NewEngine(crawlerConfig)

	engine.Start()
	engine.Shutdown()

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
	cmd.Flags().String("intensity", "passive", "Crawl intensity (passive, medium, aggressive, ultra)")

	cmd.Flags().SortFlags = false
}