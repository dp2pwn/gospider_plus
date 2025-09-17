package antidetect

import (
	"crypto/tls"
	"math/rand"
	"time"
)

// TLS cipher suites that mimic real browsers
var (
	// Chrome-like cipher suites
	ChromeCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	// Firefox-like cipher suites
	FirefoxCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	// Safari-like cipher suites
	SafariCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}

	// Supported curves that mimic real browsers
	BrowserCurves = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}

	// Supported signature algorithms
	BrowserSignatureSchemes = []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.PSSWithSHA256,
		tls.PKCS1WithSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.PSSWithSHA384,
		tls.PKCS1WithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA512,
	}
)

// BrowserProfile represents a browser's TLS fingerprint
type BrowserProfile struct {
	Name             string
	CipherSuites     []uint16
	Curves           []tls.CurveID
	SignatureSchemes []tls.SignatureScheme
	MinVersion       uint16
	MaxVersion       uint16
}

// GetBrowserProfiles returns predefined browser profiles
func GetBrowserProfiles() []BrowserProfile {
	return []BrowserProfile{
		{
			Name:             "Chrome",
			CipherSuites:     ChromeCipherSuites,
			Curves:           BrowserCurves,
			SignatureSchemes: BrowserSignatureSchemes,
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
		},
		{
			Name:             "Firefox",
			CipherSuites:     FirefoxCipherSuites,
			Curves:           BrowserCurves,
			SignatureSchemes: BrowserSignatureSchemes,
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
		},
		{
			Name:             "Safari",
			CipherSuites:     SafariCipherSuites,
			Curves:           BrowserCurves,
			SignatureSchemes: BrowserSignatureSchemes,
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
		},
	}
}

// GetRandomBrowserProfile returns a random browser profile
func GetRandomBrowserProfile() BrowserProfile {
	profiles := GetBrowserProfiles()
	rand.Seed(time.Now().UnixNano())
	return profiles[rand.Intn(len(profiles))]
}

// CreateTLSConfig creates a TLS config that mimics a real browser
func CreateTLSConfig(profile BrowserProfile) *tls.Config {
	return &tls.Config{
		CipherSuites:       profile.CipherSuites,
		CurvePreferences:   profile.Curves,
		MinVersion:         profile.MinVersion,
		MaxVersion:         profile.MaxVersion,
		InsecureSkipVerify: true,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		// Randomize session ticket key
		SessionTicketsDisabled: false,
	}
}

// CreateRandomTLSConfig creates a TLS config with a random browser profile
func CreateRandomTLSConfig() *tls.Config {
	profile := GetRandomBrowserProfile()
	return CreateTLSConfig(profile)
}

// ShuffleCipherSuites randomly shuffles cipher suites to avoid fingerprinting
func ShuffleCipherSuites(suites []uint16) []uint16 {
	rand.Seed(time.Now().UnixNano())
	shuffled := make([]uint16, len(suites))
	copy(shuffled, suites)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

// CreateStealthTLSConfig creates a highly randomized TLS config for maximum stealth
func CreateStealthTLSConfig() *tls.Config {
	profile := GetRandomBrowserProfile()

	// Shuffle cipher suites for additional randomization
	shuffledCiphers := ShuffleCipherSuites(profile.CipherSuites)

	// Take only a subset of cipher suites to mimic real browser behavior
	numCiphers := 8 + rand.Intn(8) // 8-15 cipher suites
	if numCiphers > len(shuffledCiphers) {
		numCiphers = len(shuffledCiphers)
	}

	return &tls.Config{
		CipherSuites:     shuffledCiphers[:numCiphers],
		CurvePreferences: profile.Curves,

		MinVersion:             profile.MinVersion,
		MaxVersion:             profile.MaxVersion,
		InsecureSkipVerify:     true,
		Renegotiation:          tls.RenegotiateOnceAsClient,
		SessionTicketsDisabled: rand.Intn(2) == 0, // Randomly enable/disable session tickets
	}
}
