package core

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jaeles-project/gospider/stringset"
)

type Output struct {
	mu     sync.Mutex
	f      *os.File
	filter *stringset.StringFilter
}

func NewOutput(folder, filename string) *Output {
	outFile := filepath.Join(folder, filename)
	return newOutput(outFile, func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	})
}

func (o *Output) WriteToFile(msg string) {
	if strings.TrimSpace(msg) == "" {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if o.filter != nil && o.filter.Duplicate(msg) {
		return
	}

	_, _ = o.f.WriteString(msg + "\n")
}

func (o *Output) Close() {
	if o.f != nil {
		_ = o.f.Close()
	}
}

func NewOutputPath(filePath string) *Output {
	abspath, err := filepath.Abs(filePath)
	if err != nil {
		Logger.Errorf("Failed to resolve reflected output path: %s", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(abspath), os.ModePerm); err != nil {
		Logger.Errorf("Failed to create reflected output directory: %s", err)
		os.Exit(1)
	}

	return newOutput(abspath, func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	})
}

func newOutput(outFile string, opener func(string) (*os.File, error)) *Output {
	f, err := opener(outFile)
	if err != nil {
		Logger.Errorf("Failed to open file to write Output: %s", err)
		os.Exit(1)
	}

	out := &Output{
		f:      f,
		filter: stringset.NewStringFilter(),
	}
	out.loadExisting(outFile)
	return out
}

func (o *Output) loadExisting(path string) {
	reader, err := os.Open(path)
	if err != nil {
		return
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			continue
		}
		if o.filter != nil {
			_ = o.filter.Duplicate(line)
		}
	}
}
