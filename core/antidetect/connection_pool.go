package antidetect

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnectionPool manages HTTP connections in a browser-like manner
type ConnectionPool struct {
	transport    *http.Transport
	connections  map[string]*ConnectionInfo
	mutex        sync.RWMutex
	maxConns     int
	maxIdleTime  time.Duration
	cleanupTimer *time.Timer
}

// ConnectionInfo tracks information about a connection
type ConnectionInfo struct {
	Host        string
	Port        string
	Protocol    string
	CreatedAt   time.Time
	LastUsed    time.Time
	UseCount    int
	IsIdle      bool
	TLSVersion  uint16
	CipherSuite uint16
}

// NewConnectionPool creates a new browser-like connection pool
func NewConnectionPool(maxConns int, maxIdleTime time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		connections: make(map[string]*ConnectionInfo),
		maxConns:    maxConns,
		maxIdleTime: maxIdleTime,
	}

	// Setup transport with browser-like settings
	pool.transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		
		// Browser-like connection limits
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 6, // Chrome default
		MaxConnsPerHost:     6, // Chrome default
		IdleConnTimeout:     90 * time.Second,
		
		// TLS settings
		TLSHandshakeTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		
		// HTTP/2 settings
		ForceAttemptHTTP2: true,
		
		// Disable compression to avoid fingerprinting
		DisableCompression: false,
		
		// Response header timeout
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// Start cleanup routine
	pool.startCleanup()

	return pool
}

// GetTransport returns the configured transport
func (cp *ConnectionPool) GetTransport() *http.Transport {
	return cp.transport
}

// SetTLSConfig sets the TLS configuration for the transport
func (cp *ConnectionPool) SetTLSConfig(tlsConfig *tls.Config) {
	cp.transport.TLSClientConfig = tlsConfig
}

// TrackConnection tracks a new connection
func (cp *ConnectionPool) TrackConnection(host, port, protocol string) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	key := host + ":" + port
	now := time.Now()

	if conn, exists := cp.connections[key]; exists {
		conn.LastUsed = now
		conn.UseCount++
		conn.IsIdle = false
	} else {
		cp.connections[key] = &ConnectionInfo{
			Host:      host,
			Port:      port,
			Protocol:  protocol,
			CreatedAt: now,
			LastUsed:  now,
			UseCount:  1,
			IsIdle:    false,
		}
	}
}

// MarkConnectionIdle marks a connection as idle
func (cp *ConnectionPool) MarkConnectionIdle(host, port string) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	key := host + ":" + port
	if conn, exists := cp.connections[key]; exists {
		conn.IsIdle = true
		conn.LastUsed = time.Now()
	}
}

// GetConnectionStats returns statistics about connections
func (cp *ConnectionPool) GetConnectionStats() map[string]interface{} {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_connections"] = len(cp.connections)
	
	activeConns := 0
	idleConns := 0
	
	for _, conn := range cp.connections {
		if conn.IsIdle {
			idleConns++
		} else {
			activeConns++
		}
	}
	
	stats["active_connections"] = activeConns
	stats["idle_connections"] = idleConns
	stats["max_connections"] = cp.maxConns
	
	return stats
}

// CleanupIdleConnections removes idle connections that have exceeded the timeout
func (cp *ConnectionPool) CleanupIdleConnections() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	now := time.Now()
	for key, conn := range cp.connections {
		if conn.IsIdle && now.Sub(conn.LastUsed) > cp.maxIdleTime {
			delete(cp.connections, key)
		}
	}
}

// startCleanup starts the periodic cleanup routine
func (cp *ConnectionPool) startCleanup() {
	cp.cleanupTimer = time.AfterFunc(cp.maxIdleTime/2, func() {
		cp.CleanupIdleConnections()
		cp.startCleanup() // Reschedule
	})
}

// Stop stops the connection pool and cleanup routine
func (cp *ConnectionPool) Stop() {
	if cp.cleanupTimer != nil {
		cp.cleanupTimer.Stop()
	}
	
	// Close all idle connections
	cp.transport.CloseIdleConnections()
}

// BrowserConnectionBehavior simulates browser connection behavior
type BrowserConnectionBehavior struct {
	pool                *ConnectionPool
	maxConnectionsPerHost int
	connectionTimeout   time.Duration
	keepAliveTimeout    time.Duration
	http2Enabled        bool
}

// NewBrowserConnectionBehavior creates a new browser connection behavior simulator
func NewBrowserConnectionBehavior() *BrowserConnectionBehavior {
	return &BrowserConnectionBehavior{
		pool:                NewConnectionPool(100, 90*time.Second),
		maxConnectionsPerHost: 6, // Chrome default
		connectionTimeout:   30 * time.Second,
		keepAliveTimeout:    30 * time.Second,
		http2Enabled:        true,
	}
}

// ConfigureForBrowser configures connection behavior for a specific browser
func (bcb *BrowserConnectionBehavior) ConfigureForBrowser(browser string) {
	switch browser {
	case "chrome":
		bcb.maxConnectionsPerHost = 6
		bcb.connectionTimeout = 30 * time.Second
		bcb.keepAliveTimeout = 30 * time.Second
		bcb.http2Enabled = true
	case "firefox":
		bcb.maxConnectionsPerHost = 6
		bcb.connectionTimeout = 30 * time.Second
		bcb.keepAliveTimeout = 115 * time.Second
		bcb.http2Enabled = true
	case "safari":
		bcb.maxConnectionsPerHost = 6
		bcb.connectionTimeout = 30 * time.Second
		bcb.keepAliveTimeout = 30 * time.Second
		bcb.http2Enabled = true
	case "edge":
		bcb.maxConnectionsPerHost = 6
		bcb.connectionTimeout = 30 * time.Second
		bcb.keepAliveTimeout = 30 * time.Second
		bcb.http2Enabled = true
	}

	// Update transport settings
	transport := bcb.pool.GetTransport()
	transport.MaxConnsPerHost = bcb.maxConnectionsPerHost
	transport.MaxIdleConnsPerHost = bcb.maxConnectionsPerHost
	transport.ForceAttemptHTTP2 = bcb.http2Enabled
	
	// Update dialer settings
	transport.DialContext = (&net.Dialer{
		Timeout:   bcb.connectionTimeout,
		KeepAlive: bcb.keepAliveTimeout,
	}).DialContext
}

// GetTransport returns the configured transport
func (bcb *BrowserConnectionBehavior) GetTransport() *http.Transport {
	return bcb.pool.GetTransport()
}

// SimulateConnectionReuse simulates browser connection reuse patterns
func (bcb *BrowserConnectionBehavior) SimulateConnectionReuse(host string) {
	// Browsers typically reuse connections for the same host
	bcb.pool.TrackConnection(host, "443", "https")
	
	// Simulate some delay before marking as idle
	go func() {
		time.Sleep(time.Duration(1+len(host)%5) * time.Second)
		bcb.pool.MarkConnectionIdle(host, "443")
	}()
}

// ConnectionMultiplexer handles HTTP/2 connection multiplexing
type ConnectionMultiplexer struct {
	streams map[string]int
	mutex   sync.RWMutex
}

// NewConnectionMultiplexer creates a new connection multiplexer
func NewConnectionMultiplexer() *ConnectionMultiplexer {
	return &ConnectionMultiplexer{
		streams: make(map[string]int),
	}
}

// AllocateStream allocates a new stream for a host
func (cm *ConnectionMultiplexer) AllocateStream(host string) int {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	streamID := cm.streams[host]
	streamID += 2 // HTTP/2 client streams are odd numbers
	cm.streams[host] = streamID
	
	return streamID
}

// GetActiveStreams returns the number of active streams for a host
func (cm *ConnectionMultiplexer) GetActiveStreams(host string) int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return cm.streams[host] / 2
}

// ResetStreams resets stream counters for a host
func (cm *ConnectionMultiplexer) ResetStreams(host string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	delete(cm.streams, host)
}

// ConnectionLoadBalancer balances connections across multiple IPs
type ConnectionLoadBalancer struct {
	hostIPs map[string][]string
	current map[string]int
	mutex   sync.RWMutex
}

// NewConnectionLoadBalancer creates a new connection load balancer
func NewConnectionLoadBalancer() *ConnectionLoadBalancer {
	return &ConnectionLoadBalancer{
		hostIPs: make(map[string][]string),
		current: make(map[string]int),
	}
}

// AddHostIPs adds IP addresses for a host
func (clb *ConnectionLoadBalancer) AddHostIPs(host string, ips []string) {
	clb.mutex.Lock()
	defer clb.mutex.Unlock()

	clb.hostIPs[host] = ips
	clb.current[host] = 0
}

// GetNextIP returns the next IP for a host using round-robin
func (clb *ConnectionLoadBalancer) GetNextIP(host string) string {
	clb.mutex.Lock()
	defer clb.mutex.Unlock()

	ips, exists := clb.hostIPs[host]
	if !exists || len(ips) == 0 {
		return host // Return original host if no IPs configured
	}

	currentIdx := clb.current[host]
	ip := ips[currentIdx]
	
	clb.current[host] = (currentIdx + 1) % len(ips)
	
	return ip
}

// ConnectionMetrics tracks connection metrics
type ConnectionMetrics struct {
	TotalConnections    int64
	ActiveConnections   int64
	FailedConnections   int64
	ConnectionDuration  time.Duration
	BytesSent          int64
	BytesReceived      int64
	mutex              sync.RWMutex
}

// NewConnectionMetrics creates new connection metrics
func NewConnectionMetrics() *ConnectionMetrics {
	return &ConnectionMetrics{}
}

// RecordConnection records a new connection
func (cm *ConnectionMetrics) RecordConnection() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.TotalConnections++
	cm.ActiveConnections++
}

// RecordConnectionClosed records a closed connection
func (cm *ConnectionMetrics) RecordConnectionClosed(duration time.Duration) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.ActiveConnections--
	cm.ConnectionDuration += duration
}

// RecordFailedConnection records a failed connection
func (cm *ConnectionMetrics) RecordFailedConnection() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.FailedConnections++
}

// RecordBytes records bytes sent and received
func (cm *ConnectionMetrics) RecordBytes(sent, received int64) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.BytesSent += sent
	cm.BytesReceived += received
}

// GetMetrics returns current metrics
func (cm *ConnectionMetrics) GetMetrics() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return map[string]interface{}{
		"total_connections":    cm.TotalConnections,
		"active_connections":   cm.ActiveConnections,
		"failed_connections":   cm.FailedConnections,
		"avg_connection_duration": cm.ConnectionDuration.Milliseconds() / max(cm.TotalConnections, 1),
		"bytes_sent":          cm.BytesSent,
		"bytes_received":      cm.BytesReceived,
	}
}

// max returns the maximum of two int64 values
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
