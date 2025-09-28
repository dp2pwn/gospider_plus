package core

import (
	"sync/atomic"
	"time"
)

type CrawlStats struct {
	urlsFound     int64
	requestsMade  int64
	errors        int64
}

func NewCrawlStats() *CrawlStats {
	return &CrawlStats{}
}

func (s *CrawlStats) IncrementURLsFound() {
	atomic.AddInt64(&s.urlsFound, 1)
}

func (s *CrawlStats) AddURLsFound(count int) {
	if count > 0 {
		atomic.AddInt64(&s.urlsFound, int64(count))
	}
}

func (s *CrawlStats) IncrementRequestsMade() {
	atomic.AddInt64(&s.requestsMade, 1)
}

func (s *CrawlStats) IncrementErrors() {
	atomic.AddInt64(&s.errors, 1)
}

func (s *CrawlStats) GetURLsFound() int64 {
	return atomic.LoadInt64(&s.urlsFound)
}

func (s *CrawlStats) GetRequestsMade() int64 {
	return atomic.LoadInt64(&s.requestsMade)
}

func (s *CrawlStats) GetErrors() int64 {
	return atomic.LoadInt64(&s.errors)
}

func (s *CrawlStats) GetRPS(elapsed time.Duration) float64 {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return 0
	}
	requests := s.GetRequestsMade()
	return float64(requests) / seconds
}