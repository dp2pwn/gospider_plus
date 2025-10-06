package core

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Engine manages the overall crawling process.
type Engine struct {
	ctx       context.Context
	cancel    context.CancelFunc
	cfg       CrawlerConfig
	stats     *CrawlStats
	startTime time.Time
}

// NewEngine creates a new crawling engine.
func NewEngine(cfg CrawlerConfig) *Engine {
	ctx, cancel := context.WithCancel(context.Background())

	// Ensure a single URL registry is shared across all crawlers.
	if cfg.Registry == nil {
		cfg.Registry = NewURLRegistry()
	}

	e := &Engine{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		stats:     NewCrawlStats(),
		startTime: time.Now(),
	}

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
		<-sigchan
		Logger.Infof("Interrupt signal received, shutting down...")
		e.cancel()
	}()

	return e
}

// resolveSites gathers the list of target sites from configuration and stdin.
func (e *Engine) resolveSites() []string {
	var siteList []string
	if e.cfg.Site != "" {
		siteList = append(siteList, e.cfg.Site)
	}

	if e.cfg.Sites != "" {
		// NOTE: ReadingLines is defined in core/utils.go, which is in the same package.
		sitesFile := ReadingLines(e.cfg.Sites)
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
		Logger.Info("No site in list. Please check your site input again")
		return nil
	}
	return siteList
}

// Start kicks off the crawling process and waits for it to complete.
func (e *Engine) Start() {
	sites := e.resolveSites()
	if sites == nil {
		return
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(sites))

	numThreads := e.cfg.Threads
	if numThreads <= 0 {
		numThreads = 1
	}

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for siteURL := range jobs {
				select {
				case <-e.ctx.Done():
					return
				default:
					u, err := url.Parse(siteURL)
					if err != nil {
						Logger.Errorf("Failed to parse site URL: %s", err)
						continue
					}
					crawler := NewCrawler(e.ctx, u, e.cfg, e.stats)
					crawler.Start()
				}
			}
		}()
	}

	for _, siteURL := range sites {
		jobs <- siteURL
	}
	close(jobs)

	wg.Wait()
}

// Shutdown prints final statistics.
func (e *Engine) Shutdown() {
	elapsed := time.Since(e.startTime)
	rps := e.stats.GetRPS(elapsed)

	Logger.Info("Crawling finished.")
	Logger.Infof("Time elapsed: %s", elapsed.Round(time.Millisecond))
	Logger.Infof("Requests made: %d", e.stats.GetRequestsMade())
	Logger.Infof("URLs found: %d", e.stats.GetURLsFound())
	Logger.Infof("Errors: %d", e.stats.GetErrors())
	Logger.Infof("RPS: %.2f", rps)
}

// Ctx returns the engine's context.
func (e *Engine) Ctx() context.Context {
	return e.ctx
}