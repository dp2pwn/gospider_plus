package core

import (
	"os"
	"path/filepath"
	"sync"
)

type Output struct {
	mu sync.Mutex
	f  *os.File
}

func NewOutput(folder, filename string) *Output {
	outFile := filepath.Join(folder, filename)
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		Logger.Errorf("Failed to open file to write Output: %s", err)
		os.Exit(1)
	}
	return &Output{
		f: f,
	}
}

func (o *Output) WriteToFile(msg string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = o.f.WriteString(msg + "\n")
}

func (o *Output) Close() {
	o.f.Close()
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
	f, err := os.OpenFile(abspath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		Logger.Errorf("Failed to open reflected output file: %s", err)
		os.Exit(1)
	}
	return &Output{f: f}
}
