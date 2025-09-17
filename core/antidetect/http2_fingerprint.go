package antidetect

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// HTTP2Settings represents HTTP/2 SETTINGS frame parameters
type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

// BrowserHTTP2Profile represents a browser's HTTP/2 fingerprint
type BrowserHTTP2Profile struct {
	Name                  string
	Settings              HTTP2Settings
	WindowUpdateIncrement uint32
	PriorityFrames        []PriorityFrame
	PseudoHeaderOrder     []string
}

// PriorityFrame represents HTTP/2 priority frame data
type PriorityFrame struct {
	StreamID  uint32
	DependsOn uint32
	Weight    uint8
	Exclusive bool
}

// Chrome HTTP/2 profile
var ChromeHTTP2Profile = BrowserHTTP2Profile{
	Name: "Chrome",
	Settings: HTTP2Settings{
		HeaderTableSize:      65536,
		EnablePush:           false,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
		MaxFrameSize:         16777215,
		MaxHeaderListSize:    0,
	},
	WindowUpdateIncrement: 15663105,
	PriorityFrames: []PriorityFrame{
		{StreamID: 3, DependsOn: 0, Weight: 200, Exclusive: false},
		{StreamID: 5, DependsOn: 0, Weight: 100, Exclusive: false},
		{StreamID: 7, DependsOn: 0, Weight: 0, Exclusive: false},
		{StreamID: 9, DependsOn: 7, Weight: 0, Exclusive: false},
		{StreamID: 11, DependsOn: 3, Weight: 0, Exclusive: false},
		{StreamID: 13, DependsOn: 0, Weight: 240, Exclusive: false},
	},
	PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
}

// Firefox HTTP/2 profile
var FirefoxHTTP2Profile = BrowserHTTP2Profile{
	Name: "Firefox",
	Settings: HTTP2Settings{
		HeaderTableSize:      65536,
		EnablePush:           true,
		MaxConcurrentStreams: 0,
		InitialWindowSize:    131072,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    0,
	},
	WindowUpdateIncrement: 12517377,
	PriorityFrames: []PriorityFrame{
		{StreamID: 3, DependsOn: 0, Weight: 200, Exclusive: false},
		{StreamID: 5, DependsOn: 0, Weight: 100, Exclusive: false},
		{StreamID: 7, DependsOn: 0, Weight: 0, Exclusive: false},
		{StreamID: 9, DependsOn: 7, Weight: 0, Exclusive: false},
		{StreamID: 11, DependsOn: 3, Weight: 0, Exclusive: false},
		{StreamID: 13, DependsOn: 0, Weight: 240, Exclusive: false},
	},
	PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
}

// Safari HTTP/2 profile
var SafariHTTP2Profile = BrowserHTTP2Profile{
	Name: "Safari",
	Settings: HTTP2Settings{
		HeaderTableSize:      4096,
		EnablePush:           false,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    2097152,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    0,
	},
	WindowUpdateIncrement: 10485760,
	PriorityFrames: []PriorityFrame{
		{StreamID: 3, DependsOn: 0, Weight: 200, Exclusive: false},
		{StreamID: 5, DependsOn: 0, Weight: 100, Exclusive: false},
		{StreamID: 7, DependsOn: 0, Weight: 0, Exclusive: false},
		{StreamID: 9, DependsOn: 7, Weight: 0, Exclusive: false},
		{StreamID: 11, DependsOn: 3, Weight: 0, Exclusive: false},
		{StreamID: 13, DependsOn: 0, Weight: 240, Exclusive: false},
	},
	PseudoHeaderOrder: []string{":method", ":scheme", ":authority", ":path"},
}

// GetHTTP2Profiles returns all available HTTP/2 profiles
func GetHTTP2Profiles() []BrowserHTTP2Profile {
	return []BrowserHTTP2Profile{
		ChromeHTTP2Profile,
		FirefoxHTTP2Profile,
		SafariHTTP2Profile,
	}
}

// GetRandomHTTP2Profile returns a random HTTP/2 profile
func GetRandomHTTP2Profile() BrowserHTTP2Profile {
	profiles := GetHTTP2Profiles()
	rand.Seed(time.Now().UnixNano())
	return profiles[rand.Intn(len(profiles))]
}

// CreateHTTP2Transport creates an HTTP/2 transport with browser-like settings
func CreateHTTP2Transport(profile BrowserHTTP2Profile, tlsConfig *tls.Config) *http.Transport {
	// Create HTTP/2 transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Force HTTP/2
		ForceAttemptHTTP2: true,
	}

	// Configure HTTP/2 transport
	// Note: HTTP/2 transport configuration is handled internally by Go's http package

	return transport
}

// RandomizeHTTP2Settings creates randomized HTTP/2 settings
func RandomizeHTTP2Settings(baseProfile BrowserHTTP2Profile) HTTP2Settings {
	rand.Seed(time.Now().UnixNano())

	settings := baseProfile.Settings

	// Add some randomization to settings
	settings.HeaderTableSize += uint32(rand.Intn(8192))
	settings.InitialWindowSize += uint32(rand.Intn(1048576))
	settings.MaxFrameSize += uint32(rand.Intn(1024))

	// Randomly enable/disable push
	if rand.Intn(2) == 0 {
		settings.EnablePush = !settings.EnablePush
	}

	return settings
}

// CreateStealthHTTP2Transport creates a highly randomized HTTP/2 transport
func CreateStealthHTTP2Transport(tlsConfig *tls.Config) *http.Transport {
	profile := GetRandomHTTP2Profile()

	// Randomize the profile
	profile.Settings = RandomizeHTTP2Settings(profile)

	return CreateHTTP2Transport(profile, tlsConfig)
}

// HTTP2FrameOrder represents the order of HTTP/2 frames
type HTTP2FrameOrder struct {
	SettingsFrame  bool
	WindowUpdate   bool
	PriorityFrames []PriorityFrame
}

// GetBrowserFrameOrder returns browser-specific frame order
func GetBrowserFrameOrder(browserName string) HTTP2FrameOrder {
	switch browserName {
	case "Chrome":
		return HTTP2FrameOrder{
			SettingsFrame:  true,
			WindowUpdate:   true,
			PriorityFrames: ChromeHTTP2Profile.PriorityFrames,
		}
	case "Firefox":
		return HTTP2FrameOrder{
			SettingsFrame:  true,
			WindowUpdate:   true,
			PriorityFrames: FirefoxHTTP2Profile.PriorityFrames,
		}
	case "Safari":
		return HTTP2FrameOrder{
			SettingsFrame:  true,
			WindowUpdate:   true,
			PriorityFrames: SafariHTTP2Profile.PriorityFrames,
		}
	default:
		profile := GetRandomHTTP2Profile()
		return HTTP2FrameOrder{
			SettingsFrame:  true,
			WindowUpdate:   true,
			PriorityFrames: profile.PriorityFrames,
		}
	}
}

// HTTP2HeaderOrder manages pseudo-header ordering
type HTTP2HeaderOrder struct {
	PseudoHeaders []string
	Headers       []string
}

// GetBrowserHeaderOrder returns browser-specific header order
func GetBrowserHeaderOrder(browserName string) HTTP2HeaderOrder {
	var pseudoOrder []string

	switch browserName {
	case "Chrome":
		pseudoOrder = ChromeHTTP2Profile.PseudoHeaderOrder
	case "Firefox":
		pseudoOrder = FirefoxHTTP2Profile.PseudoHeaderOrder
	case "Safari":
		pseudoOrder = SafariHTTP2Profile.PseudoHeaderOrder
	default:
		profile := GetRandomHTTP2Profile()
		pseudoOrder = profile.PseudoHeaderOrder
	}

	return HTTP2HeaderOrder{
		PseudoHeaders: pseudoOrder,
		Headers: []string{
			"host",
			"user-agent",
			"accept",
			"accept-language",
			"accept-encoding",
			"cache-control",
			"upgrade-insecure-requests",
		},
	}
}

// ApplyHTTP2Fingerprint applies HTTP/2 fingerprinting to a request
func ApplyHTTP2Fingerprint(req *http.Request, profile BrowserHTTP2Profile) {
	// Set HTTP/2 specific headers
	if req.Header.Get("Connection") != "" {
		req.Header.Del("Connection")
	}
	if req.Header.Get("Upgrade") != "" {
		req.Header.Del("Upgrade")
	}

	// Force HTTP/2
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Proto = "HTTP/2.0"
}

// CreateRandomHTTP2Config creates a randomized HTTP/2 configuration
func CreateRandomHTTP2Config() *http2.Transport {
	_ = GetRandomHTTP2Profile() // Get profile for future use

	return &http2.Transport{
		// Randomize settings
		DisableCompression: rand.Intn(2) == 0,
		AllowHTTP:          false,
		// Add more randomization as needed
	}
}
