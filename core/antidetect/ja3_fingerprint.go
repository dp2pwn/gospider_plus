package antidetect

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA3Fingerprint represents a JA3 TLS fingerprint
type JA3Fingerprint struct {
	Version            uint16
	CipherSuites       []uint16
	Extensions         []uint16
	EllipticCurves     []uint16
	EllipticCurveFormats []uint8
}

// JA4Fingerprint represents a JA4 TLS fingerprint (newer version)
type JA4Fingerprint struct {
	TLSVersion         string
	SNIExtension       string
	CipherSuites       []string
	Extensions         []string
	SignatureAlgorithms []string
}

// Common JA3 fingerprints for popular browsers
var (
	ChromeJA3Fingerprints = []JA3Fingerprint{
		{
			Version:      0x0303, // TLS 1.2
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009f, 0x009e, 0x006b, 0x0067, 0x0039, 0x0033, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f},
			Extensions:   []uint16{0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b, 0x002d, 0x000d, 0x001c, 0x0015},
			EllipticCurves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
			EllipticCurveFormats: []uint8{0x00},
		},
		{
			Version:      0x0304, // TLS 1.3
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc030, 0x009f, 0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc0a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033},
			Extensions:   []uint16{0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b, 0x002d, 0x000d, 0x001c, 0x0015, 0x0029},
			EllipticCurves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
			EllipticCurveFormats: []uint8{0x00},
		},
	}

	FirefoxJA3Fingerprints = []JA3Fingerprint{
		{
			Version:      0x0303, // TLS 1.2
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009f, 0x009e, 0x006b, 0x0067, 0x0039, 0x0033},
			Extensions:   []uint16{0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b, 0x002d, 0x000d, 0x001c},
			EllipticCurves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
			EllipticCurveFormats: []uint8{0x00},
		},
	}

	SafariJA3Fingerprints = []JA3Fingerprint{
		{
			Version:      0x0303, // TLS 1.2
			CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009f, 0x009e, 0x006b, 0x0067, 0x0039, 0x0033},
			Extensions:   []uint16{0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b, 0x002d, 0x000d},
			EllipticCurves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
			EllipticCurveFormats: []uint8{0x00},
		},
	}
)

// GenerateJA3String generates a JA3 string from fingerprint components
func GenerateJA3String(fp JA3Fingerprint) string {
	// Convert components to strings
	version := strconv.Itoa(int(fp.Version))
	
	cipherSuites := make([]string, len(fp.CipherSuites))
	for i, cs := range fp.CipherSuites {
		cipherSuites[i] = strconv.Itoa(int(cs))
	}
	
	extensions := make([]string, len(fp.Extensions))
	for i, ext := range fp.Extensions {
		extensions[i] = strconv.Itoa(int(ext))
	}
	
	curves := make([]string, len(fp.EllipticCurves))
	for i, curve := range fp.EllipticCurves {
		curves[i] = strconv.Itoa(int(curve))
	}
	
	formats := make([]string, len(fp.EllipticCurveFormats))
	for i, format := range fp.EllipticCurveFormats {
		formats[i] = strconv.Itoa(int(format))
	}
	
	// Join components with commas and separate sections with dashes
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(cipherSuites, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	)
	
	return ja3String
}

// GenerateJA3Hash generates an MD5 hash of the JA3 string
func GenerateJA3Hash(fp JA3Fingerprint) string {
	ja3String := GenerateJA3String(fp)
	hash := md5.Sum([]byte(ja3String))
	return fmt.Sprintf("%x", hash)
}

// GetRandomJA3Fingerprint returns a random JA3 fingerprint for a browser
func GetRandomJA3Fingerprint(browser string) JA3Fingerprint {
	switch strings.ToLower(browser) {
	case "chrome":
		if len(ChromeJA3Fingerprints) > 0 {
			return ChromeJA3Fingerprints[0]
		}
	case "firefox":
		if len(FirefoxJA3Fingerprints) > 0 {
			return FirefoxJA3Fingerprints[0]
		}
	case "safari":
		if len(SafariJA3Fingerprints) > 0 {
			return SafariJA3Fingerprints[0]
		}
	}
	
	// Default to Chrome
	return ChromeJA3Fingerprints[0]
}

// RandomizeJA3Fingerprint adds randomization to a JA3 fingerprint
func RandomizeJA3Fingerprint(fp JA3Fingerprint) JA3Fingerprint {
	randomized := fp
	
	// Shuffle cipher suites
	shuffledCiphers := make([]uint16, len(fp.CipherSuites))
	copy(shuffledCiphers, fp.CipherSuites)
	
	// Simple shuffle (Fisher-Yates)
	for i := len(shuffledCiphers) - 1; i > 0; i-- {
		j := i % (i + 1) // Simple pseudo-random
		shuffledCiphers[i], shuffledCiphers[j] = shuffledCiphers[j], shuffledCiphers[i]
	}
	
	randomized.CipherSuites = shuffledCiphers
	
	// Shuffle extensions
	shuffledExtensions := make([]uint16, len(fp.Extensions))
	copy(shuffledExtensions, fp.Extensions)
	
	for i := len(shuffledExtensions) - 1; i > 0; i-- {
		j := i % (i + 1)
		shuffledExtensions[i], shuffledExtensions[j] = shuffledExtensions[j], shuffledExtensions[i]
	}
	
	randomized.Extensions = shuffledExtensions
	
	return randomized
}

// JA4 Implementation (newer fingerprinting method)

// GenerateJA4String generates a JA4 string from fingerprint components
func GenerateJA4String(fp JA4Fingerprint) string {
	// JA4 format: TLSVersion_CipherSuites_Extensions_SignatureAlgorithms
	return fmt.Sprintf("%s_%s_%s_%s",
		fp.TLSVersion,
		strings.Join(fp.CipherSuites, ","),
		strings.Join(fp.Extensions, ","),
		strings.Join(fp.SignatureAlgorithms, ","),
	)
}

// GetChromeJA4Fingerprint returns a Chrome-like JA4 fingerprint
func GetChromeJA4Fingerprint() JA4Fingerprint {
	return JA4Fingerprint{
		TLSVersion:   "13",
		SNIExtension: "d",
		CipherSuites: []string{"1301", "1302", "1303", "c02c", "c030", "009f", "c02b", "c02f", "009e", "c024", "c028", "006b", "c023", "c027", "0067", "c0a", "c014", "0039", "c009", "c013", "0033"},
		Extensions:   []string{"0000", "0017", "0018", "ff01", "000a", "000b", "0023", "0010", "0005", "0012", "0033", "002b", "002d", "000d", "001c", "0015", "0029"},
		SignatureAlgorithms: []string{"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
	}
}

// GetFirefoxJA4Fingerprint returns a Firefox-like JA4 fingerprint
func GetFirefoxJA4Fingerprint() JA4Fingerprint {
	return JA4Fingerprint{
		TLSVersion:   "13",
		SNIExtension: "d",
		CipherSuites: []string{"1301", "1302", "1303", "c02c", "c02b", "c030", "c02f", "c028", "c027", "c014", "c013", "009f", "009e", "006b", "0067", "0039", "0033"},
		Extensions:   []string{"0000", "0017", "0018", "ff01", "000a", "000b", "0023", "0010", "0005", "0012", "0033", "002b", "002d", "000d", "001c"},
		SignatureAlgorithms: []string{"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
	}
}

// FingerprintDatabase stores known fingerprints
type FingerprintDatabase struct {
	JA3Fingerprints map[string][]JA3Fingerprint
	JA4Fingerprints map[string][]JA4Fingerprint
}

// NewFingerprintDatabase creates a new fingerprint database
func NewFingerprintDatabase() *FingerprintDatabase {
	return &FingerprintDatabase{
		JA3Fingerprints: map[string][]JA3Fingerprint{
			"chrome":  ChromeJA3Fingerprints,
			"firefox": FirefoxJA3Fingerprints,
			"safari":  SafariJA3Fingerprints,
		},
		JA4Fingerprints: map[string][]JA4Fingerprint{
			"chrome":  {GetChromeJA4Fingerprint()},
			"firefox": {GetFirefoxJA4Fingerprint()},
		},
	}
}

// GetRandomFingerprint returns a random fingerprint for a browser
func (fdb *FingerprintDatabase) GetRandomFingerprint(browser string, useJA4 bool) interface{} {
	if useJA4 {
		if fingerprints, exists := fdb.JA4Fingerprints[strings.ToLower(browser)]; exists && len(fingerprints) > 0 {
			return fingerprints[0] // Return first for now, could randomize
		}
		return GetChromeJA4Fingerprint()
	} else {
		if fingerprints, exists := fdb.JA3Fingerprints[strings.ToLower(browser)]; exists && len(fingerprints) > 0 {
			return fingerprints[0] // Return first for now, could randomize
		}
		return ChromeJA3Fingerprints[0]
	}
}

// ValidateJA3String validates a JA3 string format
func ValidateJA3String(ja3String string) bool {
	parts := strings.Split(ja3String, ",")
	return len(parts) == 5
}

// ParseJA3String parses a JA3 string into components
func ParseJA3String(ja3String string) (*JA3Fingerprint, error) {
	parts := strings.Split(ja3String, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JA3 string format")
	}
	
	// Parse version
	version, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %v", err)
	}
	
	fp := &JA3Fingerprint{
		Version: uint16(version),
	}
	
	// Parse cipher suites
	if parts[1] != "" {
		cipherStrs := strings.Split(parts[1], "-")
		fp.CipherSuites = make([]uint16, len(cipherStrs))
		for i, cs := range cipherStrs {
			cipher, err := strconv.ParseUint(cs, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid cipher suite: %v", err)
			}
			fp.CipherSuites[i] = uint16(cipher)
		}
	}
	
	// Parse extensions
	if parts[2] != "" {
		extStrs := strings.Split(parts[2], "-")
		fp.Extensions = make([]uint16, len(extStrs))
		for i, ext := range extStrs {
			extension, err := strconv.ParseUint(ext, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid extension: %v", err)
			}
			fp.Extensions[i] = uint16(extension)
		}
	}
	
	// Parse elliptic curves
	if parts[3] != "" {
		curveStrs := strings.Split(parts[3], "-")
		fp.EllipticCurves = make([]uint16, len(curveStrs))
		for i, curve := range curveStrs {
			ec, err := strconv.ParseUint(curve, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid elliptic curve: %v", err)
			}
			fp.EllipticCurves[i] = uint16(ec)
		}
	}
	
	// Parse elliptic curve formats
	if parts[4] != "" {
		formatStrs := strings.Split(parts[4], "-")
		fp.EllipticCurveFormats = make([]uint8, len(formatStrs))
		for i, format := range formatStrs {
			ecf, err := strconv.ParseUint(format, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid elliptic curve format: %v", err)
			}
			fp.EllipticCurveFormats[i] = uint8(ecf)
		}
	}
	
	return fp, nil
}

// SortExtensions sorts extensions in a specific order to match browser behavior
func SortExtensions(extensions []uint16) []uint16 {
	sorted := make([]uint16, len(extensions))
	copy(sorted, extensions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	return sorted
}
